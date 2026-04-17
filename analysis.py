# analysis.py - Malware-focused threat analysis engine with Impact/Confidence Matrix
"""
DuCharme Triage Assistant - Malware Analysis Engine
Analyzes Windows and Sysmon events for threat indicators using Impact × Confidence matrix.

USES CSV FILES for malware/breach indicator definitions
"""

from collections import defaultdict
import csv
import os
import re
import sys
from datetime import datetime, timedelta

# Risk levels ordered by severity — shared across the module
RISK_PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

# Security event IDs that are high-signal on their own (no indicator string match needed)
HIGH_SIGNAL_SECURITY = {
    '1102',  # Security log cleared
    '4625',  # Failed login
    '4698',  # Scheduled task created
    '4720',  # Account created
    '4726',  # Account deleted
    '4728',  # Added to global group
    '4732',  # Added to privileged group
    '4740',  # Account locked out
    '4756',  # Added to universal group
    '4771',  # Kerberos pre-auth failed
    '4776',  # Credential validation failed
}

# Impact x Confidence risk matrix (both axes 1-indexed, 1-4)
# Rows = impact, Cols = confidence
_RISK_MATRIX = [
    #  conf: 1        2          3           4
    ["Low",    "Medium",   "Medium",   "Medium"],    # impact 1
    ["Medium", "Medium",   "High",     "High"],      # impact 2
    ["Medium", "High",     "Critical", "Critical"],  # impact 3
    ["High",   "Critical", "Critical", "Critical"],  # impact 4
]

# MITRE ATT&CK category display order for the assessment narrative
_MITRE_ORDER = [
    'Defense Evasion', 'Credential Access', 'Privilege Escalation',
    'Persistence', 'Execution', 'Lateral Movement',
    'Command and Control', 'Impact',
]

# Compiled once at module load — used in EID 3 private-IP suppression
_PRIVATE_172_RE = re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.')


# ------------------------------------------------------------------ #
# Module-level helpers
# ------------------------------------------------------------------ #

def _resolve_csv_path(csv_filename):
    """Return the first existing path for a CSV, checking the PyInstaller bundle dir first."""
    candidates = []
    if getattr(sys, 'frozen', False):
        candidates.append(os.path.join(sys._MEIPASS, csv_filename))
    candidates += [csv_filename, f'./{csv_filename}', f'../{csv_filename}']
    return next((p for p in candidates if os.path.exists(p)), None)


def _split_csv_field(raw):
    """Split a semicolon-separated CSV field into a stripped, non-empty list."""
    return [s.strip() for s in raw.split(';') if s.strip()]


def _deduped_list(items):
    """Return items in original order, deduplicating near-duplicates.
    Two items are considered duplicates if they share >= 70% of their
    significant words (stopwords excluded). The first occurrence wins."""
    import re
    _STOP = {'the','a','an','to','of','on','this','all','any','and','or',
             'in','for','from','with','is','are','that','be','by','as',
             'it','its','at','if','not','was','has','have','been'}

    def _words(s):
        tokens = re.sub(r'[^a-z0-9]', ' ', s.lower()).split()
        return set(t for t in tokens if t not in _STOP and len(t) > 2)

    seen_items = []
    out = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        w = _words(item)
        duplicate = False
        for prev_w in seen_items:
            if not w or not prev_w:
                continue
            overlap = len(w & prev_w) / min(len(w), len(prev_w))
            if overlap >= 0.90:
                duplicate = True
                break
        if not duplicate:
            seen_items.append(w)
            out.append(item)
    return out


# ------------------------------------------------------------------ #
# Analyzer
# ------------------------------------------------------------------ #

class MalwareAnalyzer:
    """
    Analyzes event logs for malware-related activity using Impact x Confidence matrix.
    All threat definitions are loaded from CSV; no indicators are hardcoded here.
    """

    def __init__(self,
                 malware_csv='malware_indicators.csv',
                 breach_csv='breach_indicators.csv',
                 defender_csv='defender_indicators.csv'):
        self.csv_paths = {
            'malware':  malware_csv,
            'breach':   breach_csv,
            'defender': defender_csv,
        }
        self.malware_events = defaultdict(list)
        self._load_all_indicators()

    # --- Loading ---

    def _load_all_indicators(self):
        print("Loading threat indicators...")
        for indicator_type, path in self.csv_paths.items():
            self._load_indicators_from_csv(path, indicator_type)
        print(f"Loaded {len(self.malware_events)} total threat indicators")

    def _load_indicators_from_csv(self, csv_filename, indicator_type):
        csv_path = _resolve_csv_path(csv_filename)
        if csv_path is None:
            print(f"Skipping {indicator_type} indicators - file not found: {csv_filename}")
            return

        default_event_type = {'defender': 'Defender', 'breach': 'Security'}.get(indicator_type, '')

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                loaded = 0
                for row in csv.DictReader(f):
                    event_id   = row['EventID'].strip()
                    event_type = row.get('EventType', '').strip() or default_event_type
                    score_key  = 'Score' if 'Score' in row else 'CVSSScore'
                    composite  = f"{event_type}:{event_id}" if event_type else event_id

                    self.malware_events[composite].append({
                        'event_type':        event_type,
                        'event_id':          event_id,
                        'description':       row['Description'].strip(),
                        'threat':            row['Threat'].strip(),
                        'score':             float(row[score_key].strip()),
                        'impact':            int(row['Impact'].strip()),
                        'base_confidence':   int(row['BaseConfidence'].strip()),
                        'category':          row['Category'].strip(),
                        'indicators':        _split_csv_field(row.get('Indicators', '')),
                        'type':              indicator_type,
                        'finding':           row.get('Finding', '').strip(),
                        'immediate_actions': _split_csv_field(row.get('ImmediateAction', '')),
                        'followups':         _split_csv_field(row.get('FollowUp', '')),
                    })
                    loaded += 1
            print(f"  - Loaded {loaded} {indicator_type} indicators")
        except Exception as e:
            print(f"Error loading {indicator_type} CSV ({csv_path}): {e}")

    # --- Matching ---

    def _event_matches_indicators(self, event, indicators, event_type, event_id):
        """
        Return True if this event counts as a threat match.

        Each event type checks only the fields that are meaningful for that
        detection — never the full event blob — so benign processes that happen
        to share field values with indicator strings don't produce false positives.

        The indicator strings in the CSVs are the sole source of truth.
        An event only fires if its relevant field actually contains one of them.

        - Defender:              always match (the Defender alert is itself the signal).
        - High-signal Security:  match on Event ID alone (no string needed).
        - Sysmon (no indicators): match on Event ID alone.
        - System EID 7045:       ImagePath checked against indicators.
        - Sysmon EID 7:          ImageLoaded (DLL path) checked against indicators.
        - Sysmon EID 11:         TargetFilename checked against indicators.
        - Sysmon EID 13:         TargetObject (registry key) checked against indicators.
        - Sysmon EID 1:          Image basename OR CommandLine checked — so a process
                                 is only flagged if its own name/args match, not because
                                 a parent/child field happens to contain the string.
        - Sysmon EID 8/10:       SourceImage basename checked — the target is the victim,
                                 not the threat; matching TargetImage alone caused every
                                 dwm.exe→csrss.exe pair to fire as critical.
        - All others:            indicator string must appear somewhere in the event
                                 data fields (targeted, not full blob).
        """
        if event_type == "Defender":
            return True
        if event_type == "Security" and event_id in HIGH_SIGNAL_SECURITY:
            return True
        if event_type == "Sysmon" and not indicators:
            # EID 2 (timestomping) has no indicators — fires on every timestamp change.
            # Filter out known-noisy applications that legitimately modify timestamps
            # constantly (Electron/Discord cache, browsers, package managers).
            if event_id == "2":
                data = event.get('data', {})
                image = str(data.get('Image') or '').lower().rsplit('\\', 1)[-1]
                fp    = str(data.get('TargetFilename') or '').lower()
                _NOISY_PROCS = {
                    # Browsers and Electron apps — constant cache timestamp updates
                    'discord.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
                    'brave.exe', 'code.exe', 'slack.exe', 'teams.exe',
                    'claude.exe',
                    'onedrive.exe', 'dropbox.exe', 'steamwebhelper.exe',
                    'steam.exe', 'epicgameslauncher.exe', 'gameoverlayrenderer.exe',
                    # Windows Installer — sets timestamps on extracted MSI content
                    'msiexec.exe',
                    # Dell update service — extracts inventory binaries to Temp
                    'invcolpc.exe',
                    # Python/WinGet installers — bundle files with embedded timestamps
                    'python-3.11.9-amd64.exe', 'python-3.12.exe', 'python-3.13.exe',
                }
                _NOISY_PATHS = ('\\appdata\\roaming\\discord\\', '\\appdata\\local\\discord\\',
                                '\\appdata\\local\\google\\chrome\\', '\\appdata\\local\\microsoft\\edge\\',
                                '\\appdata\\roaming\\claude\\')
                # Explorer icon cache files are rebuilt by the shell constantly — never timestomping
                _NOISY_TARGETS = ('\\explorer\\iconcache', '\\explorer\\thumbcache')
                # Installer self-extractors in GUID temp dirs (AWCC _is*.exe, VS BuildTools, etc.)
                # These restore original file timestamps from the bundle — not evidence hiding.
                _NOISY_IMAGE_PATTERNS = ('\\temp\\{', 'vs_buildtools', 'winget\\',
                                         'pip-build-env-', 'pip-install-')
                image_full = str(data.get('Image') or '').lower()
                if image in _NOISY_PROCS or any(p in fp for p in _NOISY_PATHS):
                    return False
                if any(t in fp for t in _NOISY_TARGETS):
                    return False
                if any(p in image_full for p in _NOISY_IMAGE_PATTERNS):
                    return False
            return True

        data = event.get('data', {})

        # ---- System EID 7045: Service Installed -----------------------------
        if event_type == "System" and event_id == "7045":
            path = str(data.get('ImagePath') or '').lower()
            return any(ind.lower() in path for ind in indicators)

        # ---- Sysmon EID 7: DLL Loaded ---------------------------------------
        # Indicators are one of two kinds:
        #   Directory-style (ending in \): match DLLs whose path contains the dir.
        #     '\Desktop\' catches DLLs anywhere under Desktop (including subdirs like
        #     \Desktop\info.rar\jli.dll) — do NOT require the dir to be the immediate
        #     parent, only that it appears in the path.
        #     Directory indicators only fire for UNSIGNED DLLs — a signed DLL from
        #     a user directory (e.g. Sysinternals on Desktop) is not malicious.
        #   Signature-style ('Signed: false', 'SignatureStatus: Unavailable'):
        #     check the actual Signed / SignatureStatus fields from the event data,
        #     not the ImageLoaded path string (those strings never appear in the path).
        if event_type == "Sysmon" and event_id == "7":
            dll_path    = str(data.get('ImageLoaded') or '').lower()
            signed      = str(data.get('Signed') or '').lower()
            sig_status  = str(data.get('SignatureStatus') or '').lower()
            is_unsigned = (signed == 'false' or sig_status in ('unavailable', 'nosignature', 'unsigned'))
            for ind in indicators:
                ind_l = ind.lower()
                # Signature-based indicators — match against the actual event fields
                if ind_l.startswith('signed:'):
                    expected_val = ind_l.split(':', 1)[1].strip()
                    if signed == expected_val:
                        return True
                    continue
                if ind_l.startswith('signaturestatus:'):
                    expected_val = ind_l.split(':', 1)[1].strip()
                    if sig_status == expected_val:
                        return True
                    continue
                # Directory-style: DLL path must contain the directory fragment,
                # end with .dll, AND be unsigned — signed DLLs in user dirs are
                # legitimate (e.g. Sysinternals tools on the Desktop).
                if ind_l.endswith('\\'):
                    if ind_l in dll_path and dll_path.endswith('.dll') and is_unsigned:
                        return True
                else:
                    if ind_l in dll_path:
                        return True
            return False

        # ---- Sysmon EID 11: File Created ------------------------------------
        # Two rows in the CSV:
        #   "Malware Dropper Detected" — directory indicators (ending in \);
        #     only flag executable/script extensions, not .tmp/.pdf/.log etc.
        #     Also exclude PyInstaller self-extraction (_MEI* temp dirs) and
        #     known-good processes writing to Temp.
        #   "Mimikatz Credential Harvester" — filename indicators (mimilsa.log etc.);
        #     exclude matches where the indicator appears only in the directory/path
        #     component rather than the actual filename (e.g. a downloaded .evtx
        #     sample whose path contains "mimikatz").
        if event_type == "Sysmon" and event_id == "11":
            fp      = str(data.get('TargetFilename', '')).lower()
            # Use rsplit on backslash — os.path.basename uses the OS separator
            # and returns the full path unchanged on Linux where sep is '/'.
            image   = str(data.get('Image') or '').lower().rsplit('\\', 1)[-1]
            fname   = fp.rsplit('\\', 1)[-1]
            _EXEC_EXTS = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.cmd', '.hta', '.js', '.jar'}
            # Exclude PyInstaller self-extraction: _MEI* subdirs in Temp are normal
            _PYINSTALLER_PATTERN = '\\temp\\_mei'
            # Processes that legitimately write executables/DLLs to Temp or ProgramData
            _SAFE_TEMP_PROCS = {
                'msiexec.exe', 'setup.exe', 'installer.exe', 'update.exe',
                'powershell.exe', 'pwsh.exe',
                # Windows Defender engine unpacking signature updates to ProgramData
                'msmpeng.exe',
                # AWCC (Alienware Command Center) installer self-extractor
                'awccinstallationmanager.exe',
                # Dell update service extracting inventory tools to Windows\Temp
                'invcolpc.exe',
            }
            # Trusted image root prefixes — signed vendor tools in Program Files or
            # Windows dirs writing to Temp as part of normal operation are not droppers.
            _TRUSTED_IMAGE_ROOTS = (
                'c:\\program files\\', 'c:\\program files (x86)\\',
                'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
                'c:\\windows\\',
                # Microsoft-signed packages unpacked by VS installer / WinGet
                'c:\\programdata\\microsoft\\',
                # Vendor game/peripheral software updaters in ProgramData
                'c:\\programdata\\steelseries\\', 'c:\\programdata\\razer\\',
                'c:\\programdata\\logitech\\',
                # VC++ / SDK redistributable Package Cache (signed MS installers)
                'c:\\programdata\\package cache\\',
            )
            # WinGet and user-run installer patterns: an installer binary in Downloads
            # or a WinGet staging area writing to its own Temp subfolder is legitimate.
            _INSTALLER_INDICATORS = ('winget\\', 'vs_buildtools', 'vs_setup_bootstrapper',
                                     'python-', '_bootstrapper')
            # Rust/pip build environments: maturin/cargo compile into Temp — not a dropper.
            _BUILD_ENV_INDICATORS = ('pip-build-env-', 'pip-install-', '\\target\\release\\',
                                     'maturin.exe', 'cargo-')
            for ind in indicators:
                ind_l = ind.lower()
                if ind_l.endswith('\\'):
                    # Directory-style: require executable ext, exclude PyInstaller and
                    # known-safe processes that legitimately write to Temp/ProgramData.
                    if ind_l in fp and any(fp.endswith(ext) for ext in _EXEC_EXTS):
                        if _PYINSTALLER_PATTERN in fp:
                            continue
                        if image in _SAFE_TEMP_PROCS:
                            continue
                        # Image is in a trusted root (Program Files, Windows, etc.)
                        image_full = str(data.get('Image') or '').lower()
                        if any(image_full.startswith(r) for r in _TRUSTED_IMAGE_ROOTS):
                            continue
                        # Image is a user-run installer (vs_BuildTools, WinGet downloads, etc.)
                        if any(p in image_full for p in _INSTALLER_INDICATORS):
                            continue
                        # Rust/pip/maturin build: compiler writing compiled artifacts to Temp
                        if any(p in image_full for p in _BUILD_ENV_INDICATORS):
                            continue
                        if any(p in fp for p in _BUILD_ENV_INDICATORS):
                            continue
                        return True
                else:
                    # Keyword-style (mimikatz, mimilsa.log etc.): match against the
                    # filename only, not the full path — prevents a downloaded sample
                    # log named "CA_Mimikatz_...evtx" from triggering.
                    # Also skip Zone.Identifier ADS streams and non-credential extensions.
                    _CRED_EXTS = {'.log', '.dmp', ''}   # mimikatz output has no/log/dmp ext
                    stem, _, ext = fname.rpartition('.')
                    file_ext = ('.' + ext) if ext else ''
                    if ':zone.identifier' in fname:
                        continue
                    if file_ext and file_ext not in _CRED_EXTS and file_ext not in ('.evtx',):
                        pass  # fall through to check — mimilsa.log needs .log allowed
                    if ind_l in fname:
                        # Don't fire on sample/research log files — they have
                        # structured names with GUIDs and are written by browsers.
                        image_full = str(data.get('Image') or '').lower()
                        _BROWSER_PROCS = {'brave.exe', 'chrome.exe', 'msedge.exe',
                                          'firefox.exe', 'iexplore.exe'}
                        if image in _BROWSER_PROCS:
                            continue
                        return True
            return False

        # ---- Sysmon EID 13: Registry Value Set ------------------------------
        if event_type == "Sysmon" and event_id == "13":
            reg_key = str(data.get('TargetObject', '')).lower()
            if not any(ind.lower() in reg_key for ind in indicators):
                return False

            # ---- Sub-check: service ImagePath written to a non-standard location ----
            # The CSV row uses sentinel 'CurrentControlSet\services\' to reach here.
            # ANY key under \services\ matching the sentinel is handled entirely here —
            # it must NEVER fall through to the Run-key logic below.
            # Falling through causes false positives on:
            #   - Bluetooth device keys  (BTHPORT\Parameters\Devices\...)
            #   - WMI perf counter keys  (WmiApRpl\Performance\PerfIniFile etc.)
            #   - Any other \services\ subkey that contains the sentinel string.
            _SERVICE_SENTINEL = 'currentcontrolset\\services\\'
            if _SERVICE_SENTINEL in reg_key:
                # Only fire on \ImagePath — suppress everything else under \services\
                if not reg_key.endswith('\\imagepath'):
                    return False
                details = str(data.get('Details') or '').lower().strip('"').strip()
                # Trusted service binary roots — any path starting here is legitimate.
                # c:\\programdata\\ covers OEM/vendor services registered by
                # wpbbin.exe (Windows Platform Binary Table) and hardware vendor
                # update services (Gigabyte, Dell, HP, etc.).
                _TRUSTED_SVC_ROOTS = (
                    'c:\\windows\\system32\\',
                    'c:\\windows\\syswow64\\',
                    'c:\\windows\\',
                    'c:\\program files\\',
                    'c:\\program files (x86)\\',
                    'c:\\programdata\\',
                    # Driver paths using \SystemRoot or \??\ device namespace
                    '\\systemroot\\',
                    '\\??\\',
                    # Environment-variable forms Windows and OEM installers use:
                    # %SystemRoot%\system32\svchost.exe -k ...
                    # %ProgramFiles%\Vendor\service.exe
                    # These are always legitimate — no malware registers via env vars.
                    '%systemroot%\\',
                    '%windir%\\',
                    '%programfiles%\\',
                    '%programfiles(x86)%\\',
                    '%commonprogramfiles%\\',
                    '%commonprogramfiles(x86)%\\',
                )
                if not details:
                    return False
                # Suspicious subdirs under Windows\ that are NOT safe even though
                # c:\windows\ is in the trusted roots.  Check these first so that
                # a payload in Windows\Temp isn't accidentally allowed.
                _SUSPICIOUS_WIN_SUBDIRS = (
                    'c:\\windows\\temp\\',
                    'c:\\windows\\tasks\\',
                )
                if any(details.startswith(s) for s in _SUSPICIOUS_WIN_SUBDIRS):
                    return True
                if any(details.startswith(r) for r in _TRUSTED_SVC_ROOTS):
                    return False
                # Trusted writers: processes that are part of Windows or OEM firmware
                # and can only register legitimate services. wpbbin.exe is the UEFI
                # Platform Binary Table executor placed by firmware — not attacker-
                # controllable without physical access. services.exe is the SCM.
                _image_dd = str(data.get('Image') or '').lower()
                _TRUSTED_SVC_WRITERS = {
                    # wpbbin.exe is the UEFI Platform Binary Table executor,
                    # placed by firmware — it cannot be replaced by an attacker
                    # without physical hardware access. Any service it registers
                    # (e.g. GigabyteUpdateService, Dell OEM services) is OEM-legitimate.
                    'c:\\windows\\system32\\wpbbin.exe',
                }
                if _image_dd in _TRUSTED_SVC_WRITERS:
                    return False
                # Per-user service instances: Windows appends a hex session-ID suffix
                # (_XXXXXX, e.g. OneSyncSvc_104139, NPSMSvc_104139) when it creates
                # per-session copies of built-in services. Their ImagePath is always
                # a legitimate svchost.exe command — suppress them entirely.
                _svc_name = reg_key.split('\\services\\', 1)[-1].split('\\')[0]
                if re.search(r'_[0-9a-f]{4,8}$', _svc_name, re.IGNORECASE):
                    return False
                # Everything else (Desktop, AppData, Public, temp, unknown paths) fires
                return True
            # Run-key match found. Now require that the writing process comes from
            # a suspicious location — legitimate signed installers in Program Files
            # or Windows dirs writing RunOnce during install are not persistence malware.
            image = str(data.get('Image') or '').lower()
            # rsplit on single backslash — the double-backslash form splits on
            # the literal two-char sequence '\\' which never appears in a
            # normalised Windows path stored in memory.
            image_basename = image.rsplit('\\', 1)[-1]
            _SUSPICIOUS_PATHS = (
                '\\temp\\', '\\appdata\\local\\temp\\', '\\users\\public\\',
                '\\programdata\\', '\\windows\\temp\\',
            )
            _TRUSTED_ROOTS = (
                '\\program files\\', '\\program files (x86)\\',
                '\\windows\\system32\\', '\\windows\\syswow64\\',
                'c:\\windows\\', 'c:\\program files',
                # Electron/desktop apps registering their own Run key via auto-updater
                '\\appdata\\local\\anthropicclaude\\',
                '\\appdata\\local\\programs\\',
                # Vendor installer executables in WindowsApps (Store apps)
                'c:\\program files\\windowsapps\\',
            )
            # RunOnce keys written by signed installer bundles are never persistence
            # malware — they register a cleanup/finalize step post-reboot with a GUID
            # key name (e.g. RunOnce\{91ee571b-...}). Suppress these.
            _RUNONCE_GUID = r'runonce\\\{[0-9a-f\-]{36}\}'
            if 'runonce' in reg_key and re.search(_RUNONCE_GUID, reg_key, re.IGNORECASE):
                return False
            # reg.exe is an attacker-controlled tool — never suppress it regardless
            # of its location (system32). Same policy as EID 12.
            if image_basename == 'reg.exe':
                return True
            # If the image is in a known-trusted root, only flag it if the
            # executable name itself is inherently suspicious (e.g. not a
            # well-known vendor binary).
            _SUSPICIOUS_NAMES = {
                'nc.exe', 'ncat.exe', 'netcat.exe', 'payload.exe', 'rat.exe',
                'backdoor.exe', 'meterpreter.exe', 'beacon.exe',
            }
            if image_basename in _SUSPICIOUS_NAMES:
                return True
            # Vendor software writing its own named Run key — suppress if the
            # key name matches the process path (self-registration pattern).
            # Must come before the suspicious-path blanket so that a legitimate
            # installer in ProgramData registering its own app doesn't fire.
            _run_key_name = reg_key.rsplit('\\', 1)[-1].lower()
            if _run_key_name and _run_key_name in image:
                return False
            if any(p in image for p in _SUSPICIOUS_PATHS):
                return True
            if any(image.startswith(r) for r in _TRUSTED_ROOTS):
                return False
            # Unknown/AppData path — flag it
            return True

        # ---- Sysmon EID 12: Registry Key Created/Deleted --------------------
        # Suppresses legitimate Group Policy / Windows Update writers touching
        # policies\system and UAC keys — but keeps reg.exe (attacker tool) flagged.
        if event_type == "Sysmon" and event_id == "12":
            reg_key = str(data.get('TargetObject', '')).lower()
            if not any(ind.lower() in reg_key for ind in indicators):
                return False
            image = str(data.get('Image') or '').lower()
            # These system processes legitimately write UAC/policy keys via GP/WU.
            # reg.exe is intentionally NOT suppressed — attackers use it directly.
            _TRUSTED_WRITERS_12 = {
                'c:\\windows\\system32\\svchost.exe',
                'c:\\windows\\system32\\lsass.exe',
                'c:\\windows\\system32\\services.exe',
                'c:\\windows\\system32\\wbem\\wmiprvse.exe',
            }
            if image in _TRUSTED_WRITERS_12:
                return False
            return True

        # ---- Sysmon EID 1: Process Created ----------------------------------
        # Use whole-word matching so short indicators like 'nc.exe' don't
        # substring-match legitimate binaries like 'tzsync.exe' or 'AudioSync.exe'.
        #
        # Additional FP suppression:
        #   - Pentest/admin tools (psexec, procdump, nc.exe) launched from a trusted
        #     security or admin path (Sysinternals, Program Files) by a system process
        #     are presumed authorized. They must come from a suspicious path OR have
        #     a suspicious parent to fire.
        #   - Known package-manager / dev-tool invocations of cmd.exe and powershell.exe
        #     are not flagged unless cmdline contains a genuinely suspicious pattern.
        if event_type == "Sysmon" and event_id == "1":
            image_full   = str(data.get('Image') or '').lower()
            image        = image_full.rsplit('\\', 1)[-1]
            cmdline      = str(data.get('CommandLine') or '').lower()
            parent_full  = str(data.get('ParentImage') or '').lower()
            parent       = parent_full.rsplit('\\', 1)[-1]

            def _whole_word(ind, text):
                pattern = r'(?<![a-zA-Z0-9_\-])' + re.escape(ind.lower()) + r'(?![a-zA-Z0-9_\-])'
                return bool(re.search(pattern, text))

            # --- Suspicious parent-chain heuristics (fires even without a CSV name match) ---
            # These catch attacks where the payload process name is not in the indicator
            # list (e.g. jjs.exe, a renamed binary, or a random MSI-extracted .tmp file).
            _SUSPICIOUS_SPAWNERS = {
                'jjs.exe', 'wmic.exe', 'mshta.exe', 'cscript.exe', 'wscript.exe',
                'regsvr32.exe', 'rundll32.exe', 'msiexec.exe', 'installutil.exe',
                'schtasks.exe', 'at.exe', 'odbcconf.exe', 'pcalua.exe', 'forfiles.exe',
            }
            _RECON_SHELLS = {
                'cmd.exe', 'powershell.exe', 'whoami.exe', 'net.exe',
                'ipconfig.exe', 'systeminfo.exe', 'tasklist.exe',
                'nltest.exe', 'arp.exe', 'route.exe', 'netstat.exe',
            }
            _DISCOVERY_CMDS = (
                'whoami', 'systeminfo', 'ipconfig', 'net user', 'net group',
                'nltest', 'arp ', 'route print', 'tasklist', 'netstat', '/c ', '/k ',
            )
            _INSTALLER_ROOTS = (
                'c:\\program files\\', 'c:\\program files (x86)\\',
                'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
            )

            # Heuristic A: Known LOLBIN / scripting engine spawning a recon shell.
            if parent in _SUSPICIOUS_SPAWNERS and image in _RECON_SHELLS:
                # Only fire when the spawner itself is not from a safe installer root.
                # Vendors like Adobe/Office legitimately launch cmd.exe during installation.
                if not any(parent_full.startswith(r) for r in _INSTALLER_ROOTS):
                    return True
                # Even from a trusted root, flag if the command is discovery-oriented
                if any(d in cmdline for d in _DISCOVERY_CMDS):
                    return True

            # Heuristic B: MSI-extracted temporary binary spawning a shell.
            # msiexec extracts a random-named .tmp file to a GUID temp dir and runs it;
            # that .tmp then spawns cmd.exe / whoami.exe — the classic MSI meterpreter
            # delivery chain.  The .tmp binary name never appears in the CSV.
            if (parent in {'msiexec.exe'} or image_full.endswith('.tmp')) and image in _RECON_SHELLS:
                # A .tmp file spawning any shell is always suspicious
                if parent_full.endswith('.tmp') or image_full.endswith('.tmp'):
                    return True
                # msiexec directly spawning discovery shells (not installers running
                # their own sub-installers) is suspicious
                if parent in {'msiexec.exe'} and image in {'cmd.exe', 'whoami.exe',
                                                            'powershell.exe', 'net.exe'}:
                    if any(d in cmdline for d in _DISCOVERY_CMDS):
                        return True

            # Does the indicator match at all?
            if not any(_whole_word(ind, image) or _whole_word(ind, cmdline) for ind in indicators):
                return False

            # --- Suppress authorized/expected launches ---

            # 1. Sysinternals and vendor security tools in known-safe locations:
            #    procdump, psexec, etc. installed to Program Files or Sysinternals
            #    paths are authorized admin tools, not post-exploitation.
            _ADMIN_TOOL_ROOTS = (
                'c:\\program files\\sysinternals',
                'c:\\tools\\', 'c:\\sysinternals\\',
                'c:\\programdata\\chocolatey\\',
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
            )
            _DUAL_USE_TOOLS = {
                'procdump.exe', 'procdump64.exe', 'psexec.exe', 'psexec64.exe',
                'psloggedon.exe', 'pskill.exe', 'handle.exe',
            }
            if image in _DUAL_USE_TOOLS and any(image_full.startswith(r) for r in _ADMIN_TOOL_ROOTS):
                # Launched from a trusted admin root — only flag if parent is suspicious
                _SUSPICIOUS_PARENTS = {
                    'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
                    'mshta.exe', 'rundll32.exe', 'regsvr32.exe',
                }
                if parent not in _SUSPICIOUS_PARENTS:
                    return False

            # 2. nc.exe / ncat.exe are also part of Nmap on Windows — suppress if
            #    launched from the Nmap install dir or MSYS2/Git-bash paths.
            _NETCAT_NAMES = {'nc.exe', 'ncat.exe', 'netcat.exe'}
            if image in _NETCAT_NAMES:
                _NMAP_ROOTS = (
                    'c:\\program files (x86)\\nmap\\',
                    'c:\\program files\\nmap\\',
                    'c:\\msys64\\', 'c:\\msys32\\',
                    'c:\\tools\\nmap\\',
                )
                if any(image_full.startswith(r) for r in _NMAP_ROOTS):
                    return False

            # 3. powershell.exe / cmd.exe spawned by package managers, IDEs, or
            #    build systems are not C2 shells. Only flag when cmdline contains
            #    a genuinely suspicious pattern (encoded payload, download cradle,
            #    bypass flag, or explicit C2 port) rather than a bare process name match.
            _SHELL_INDICATORS = {'powershell', 'powershell.exe', 'cmd.exe'}
            _SAFE_SHELL_PARENTS = {
                'explorer.exe', 'code.exe', 'devenv.exe', 'msbuild.exe',
                'git.exe', 'python.exe', 'pythonw.exe', 'node.exe',
                'npm.cmd', 'cargo.exe', 'gradle', 'make.exe',
                'rider64.exe', 'idea64.exe', 'pycharm64.exe',
                'windowsterminal.exe', 'wt.exe',
            }
            _SUSPICIOUS_CMDLINE_PATTERNS = (
                '-enc ', '-encodedcommand', 'downloadstring', 'invoke-expression',
                'iex ', 'bypass', 'hidden', '-nop ', '-noprofile',
                'webclient', 'net.webclient', 'bitsadmin', 'certutil',
                ':4444', ':1337', ':8443', ':9001',
            )
            if any(_whole_word(ind, image) for ind in indicators if ind.lower() in _SHELL_INDICATORS):
                if parent in _SAFE_SHELL_PARENTS:
                    if not any(p in cmdline for p in _SUSPICIOUS_CMDLINE_PATTERNS):
                        return False

            return True

        # ---- Sysmon EID 8: CreateRemoteThread --------------------------------
        # Indicators name the target (victim) processes — lsass, svchost, csrss etc.
        if event_type == "Sysmon" and event_id == "8":
            target = str(data.get('TargetImage') or '').lower().rsplit('\\\\', 1)[-1]
            if not any(ind.lower() in target for ind in indicators):
                return False
            # Suppress known-benign CreateRemoteThread patterns:
            # 1. CtrlRoutine — Windows console control handler attachment.
            #    Fired when any process attaches/creates a console via kernel32.
            #    Source often shows as <unknown process> because it exited before
            #    Sysmon could resolve the PID.
            start_fn = str(data.get('StartFunction') or '').lower()
            if 'ctrlroutine' in start_fn:
                return False
            # 2. Kernel-mode start address (0xFFFFF8... range on x64) — indicates
            #    a kernel callback, not user-mode injection. DWM legitimately calls
            #    into csrss.exe via kernel for session/window management at logon.
            start_addr = str(data.get('StartAddress') or '')
            if start_addr.upper().startswith('0XFFFFF'):
                return False
            return True

        # ---- Sysmon EID 10: ProcessAccess -----------------------------------
        # Two separate CSV rows with different semantics:
        #   Credential Access row: indicator is in TARGET (victim = lsass.exe)
        #   Lateral Movement row:  indicator is in SOURCE (the attacker process)
        # Previously both checked target OR source, causing cross-row false positives
        # (e.g. powershell→svchost matching the lsass credential row).
        # We distinguish by whether any indicator is a known credential-theft target.
        if event_type == "Sysmon" and event_id == "10":
            target = str(data.get('TargetImage') or '').lower().rsplit('\\', 1)[-1]
            source = str(data.get('SourceImage') or '').lower().rsplit('\\', 1)[-1]
            _CRED_TARGETS = {'lsass.exe', 'lsaiso.exe', 'sam', 'ntds.dit'}
            is_cred_row = any(ind.lower() in _CRED_TARGETS for ind in indicators)
            if is_cred_row:
                # Only match if target is the credential store AND access rights are elevated
                if not any(ind.lower() in target for ind in indicators):
                    return False
                # Suppress low-rights access — legitimate tools (Task Manager, AV) open
                # lsass with limited rights. Only flag full/near-full access.
                granted = str(data.get('GrantedAccess') or '').lower()
                _HIGH_ACCESS = {'0x001fffff', '0x1fffff', '0x1010', '0x1410', '0x143a', '0x40'}
                if granted and not any(a in granted for a in _HIGH_ACCESS):
                    return False
                return True
            else:
                # Lateral movement row: the attacker process name is in SOURCE
                return any(ind.lower() in source for ind in indicators)

        # ---- Sysmon EID 3: Network Connection --------------------------------
        if event_type == "Sysmon" and event_id == "3":
            image_full = str(data.get('Image') or '').lower()
            image      = image_full.rsplit('\\', 1)[-1]
            dest_port  = str(data.get('DestinationPort') or '')
            dest_ip    = str(data.get('DestinationIp') or '').lower()
            cmdline    = str(data.get('CommandLine') or '').lower()

            # Suppress inbound connections — Sysmon logs both directions when
            # NetworkConnect fires on accepted sockets. Attackers initiate outbound;
            # a server process receiving a connection is not C2.
            initiated = str(data.get('Initiated') or '').lower()
            if initiated == 'false':
                return False

            # Suppress connections to private/loopback ranges — these are always
            # internal and cannot be C2 callbacks to an external attacker server.
            # Covers 127.x, 10.x, 172.16-31.x, 192.168.x, and ::1 (IPv6 loopback).
            _PRIVATE_PREFIXES = ('127.', '10.', '192.168.', '::1', '0:0:0:0:0:0:0:1')
            if any(dest_ip.startswith(p) for p in _PRIVATE_PREFIXES):
                return False
            if _PRIVATE_172_RE.match(dest_ip):
                return False

            # Indicators like 'rundll32' and 'powershell' are process-name strings
            # that match the image basename. When the binary is from a trusted Windows
            # location (System32/SysWOW64) making an HTTPS connection, that alone is
            # normal — e.g. rundll32 calling CryptNet/WU callbacks on port 443.
            # Only flag these process-name indicators when:
            #   a) the image is NOT from a trusted root, OR
            #   b) the indicator appears in the CommandLine (meaning it was invoked
            #      with a suspicious argument), OR
            #   c) the destination port is an explicitly suspicious one.
            _TRUSTED_WIN_ROOTS = (
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\',
            )
            _PROC_NAME_INDICATORS = {
                'rundll32', 'rundll32.exe',
                'powershell', 'powershell.exe',
                'cmd.exe', 'wscript', 'cscript', 'mshta', 'regsvr32',
            }
            _SUSPICIOUS_PORTS = {
                '4444', '1337', '9001', '9050', '31337',
            }
            # Common legitimate high-numbered ports that are NOT suspicious on their own.
            # Port-based indicators in the CSV (:8080, :8443) are still flagged because
            # process-name tools using them over cleartext/non-browser channels is suspect.
            _BENIGN_PORTS = {
                '80', '443', '53', '123', '389', '636', '88', '445', '139',
                '25', '587', '993', '995', '143', '110',
            }
            port_is_suspicious = dest_port in _SUSPICIOUS_PORTS

            for ind in indicators:
                ind_l = ind.lower()
                # Port-based indicator — always flag (already scoped to non-private IPs above)
                if ind_l.startswith(':'):
                    if ind_l[1:] == dest_port:
                        return True
                    continue
                # IP-based indicator
                if ind_l in dest_ip:
                    return True
                # Process-name indicator
                if ind_l in _PROC_NAME_INDICATORS:
                    if ind_l in image:
                        # Benign port from trusted root → suppress unless cmdline is suspicious
                        if dest_port in _BENIGN_PORTS and any(image_full.startswith(r) for r in _TRUSTED_WIN_ROOTS):
                            _SUSPICIOUS_CMDLINE = (
                                '-enc', '-encodedcommand', 'downloadstring', 'iex ',
                                'invoke-expression', 'bypass', 'webclient', 'hidden',
                            )
                            if any(p in cmdline for p in _SUSPICIOUS_CMDLINE):
                                return True
                            continue
                        # From trusted root on a non-suspicious port → only flag if cmdline matches
                        if (any(image_full.startswith(r) for r in _TRUSTED_WIN_ROOTS)
                                and not port_is_suspicious):
                            if ind_l in cmdline:
                                return True
                            continue
                        return True
                    # Indicator appears in cmdline (e.g. "-enc ... powershell") → always flag
                    if ind_l in cmdline:
                        return True
            return False

        # ---- Sysmon EID 18: Named Pipe Connected ----------------------------
        if event_type == "Sysmon" and event_id == "18":
            pipe = str(data.get('PipeName') or '').lower()
            return any(ind.lower() in pipe for ind in indicators)

        # ---- Sysmon EID 22: DNS Query ---------------------------------------
        if event_type == "Sysmon" and event_id == "22":
            query = str(data.get('QueryName') or '').lower()
            image = str(data.get('Image') or '').lower().rsplit('\\', 1)[-1]
            # raw.githubusercontent.com is a real C2 hosting indicator, but browsers
            # fetch extension manifests/content-filter lists from it constantly.
            # Only flag it when the querying process is NOT a known trusted browser.
            _TRUSTED_BROWSERS = {
                'brave.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
                'iexplore.exe', 'opera.exe', 'vivaldi.exe',
            }
            _BROWSER_ONLY_INDICATORS = {'raw.githubusercontent.com'}
            for ind in indicators:
                ind_l = ind.lower()
                if ind_l not in query:
                    continue
                if ind_l in _BROWSER_ONLY_INDICATORS and image in _TRUSTED_BROWSERS:
                    continue
                return True
            return False

        # ---- Sysmon EID 23: File Delete -------------------------------------
        # Without indicators the CSV row matched EVERY file deletion (wiper noise).
        # When indicators are empty, scope to security-relevant paths only and
        # suppress known-noisy deleters (browsers, package managers, AV engines).
        if event_type == "Sysmon" and event_id == "23":
            fp    = str(data.get('TargetFilename') or '').lower()
            image = str(data.get('Image') or '').lower().rsplit('\\', 1)[-1]
            if indicators:
                return any(ind.lower() in fp for ind in indicators)
            # No indicators defined — only flag deletions in high-value paths
            _SENSITIVE_PATHS = (
                '\\windows\\system32\\', '\\windows\\syswow64\\',
                '\\windows\\system32\\winevt\\', '\\programdata\\microsoft\\windows defender\\',
                '\\windows\\prefetch\\',
            )
            if not any(p in fp for p in _SENSITIVE_PATHS):
                return False
            # Suppress known-safe processes that routinely delete from system paths
            _SAFE_DELETERS = {
                'msmpeng.exe', 'msiexec.exe', 'trustedinstaller.exe',
                'tiworker.exe', 'wuauclt.exe', 'cleanmgr.exe',
                'chrome.exe', 'msedge.exe', 'brave.exe', 'firefox.exe',
            }
            if image in _SAFE_DELETERS:
                return False
            return True

        # ---- Security EID 5145: Network Share Object Access -----------------
        # BloodHound, PowerView, and net.exe enumerate AD by accessing named
        # pipes (samr, lsarpc, srvsvc) and shares (IPC$, SYSVOL, NETLOGON)
        # over SMB. The relevant data lives in ShareName and RelativeTargetName
        # — neither of which is in the generic TARGETED_FIELDS set below.
        if event_type == "Security" and event_id == "5145":
            share  = str(data.get('ShareName')          or '').lower()
            target = str(data.get('RelativeTargetName') or '').lower()
            return any(ind.lower() in share or ind.lower() in target
                       for ind in indicators)

        # ---- Security EID 4662: Directory Service Object Access -------------
        # DCSync and BloodHound LDAP enumeration trigger 4662 events against
        # domain objects. ObjectName and ObjectType carry the meaningful data.
        if event_type == "Security" and event_id == "4662":
            obj_name = str(data.get('ObjectName') or '').lower()
            obj_type = str(data.get('ObjectType') or '').lower()
            if not indicators:
                return True  # Any 4662 in breach CSV is high-signal on its own
            return any(ind.lower() in obj_name or ind.lower() in obj_type
                       for ind in indicators)

        # ---- All other events -----------------------------------------------
        # Search only a targeted allowlist of fields — not the full blob.
        TARGETED_FIELDS = {
            'Image', 'CommandLine', 'TargetFilename', 'TargetObject',
            'ImageLoaded', 'PipeName', 'QueryName', 'DestinationIp',
            'DestinationPort', 'ImagePath', 'ServiceName',
            'ThreatName', 'Path', 'ObjectName',
        }
        searchable = " ".join(
            str(v).lower() for k, v in data.items()
            if v and k in TARGETED_FIELDS
        )
        return any(ind.lower() in searchable for ind in indicators)

    # --- Scoring ---

    def _calculate_dynamic_confidence(self, event_id, base_confidence, impact, count, timeline_data=None):
        """
        Boost confidence from base_confidence based on event frequency and clustering.
        Returns (confidence, boost_reasons).

        Boost cap: indicators with base_confidence <= 2 AND impact <= 2 can only
        be boosted by +1 total regardless of count — prevents high-volume benign
        events (e.g. 200x EID 5007 Defender config changes) from reaching Critical.
        """
        confidence    = base_confidence
        boost_reasons = []
        max_boost     = 1 if (base_confidence <= 2 and impact <= 2) else 2

        if count >= 50 and max_boost >= 2:
            confidence += 2
            boost_reasons.append("high event frequency")
        elif count >= 5:
            new_conf = confidence + 1
            if new_conf <= base_confidence + max_boost:
                confidence = new_conf
                boost_reasons.append("high event frequency")

        if timeline_data:
            grouped = timeline_data.get('grouped_events', {})
            max_in_window = max(
                (sum(1 for e in window if e.get('event_id') == event_id)
                 for window in grouped.values()),
                default=0
            )
            if max_in_window >= 20 and confidence < 4:
                new_conf = confidence + 1
                if new_conf <= base_confidence + max_boost:
                    confidence = new_conf
                    boost_reasons.append("event clustering")

        return min(4, confidence), boost_reasons

    @staticmethod
    def _risk_from_matrix(impact, confidence):
        """Map impact and confidence (both 1-4) to a risk level string."""
        try:
            return _RISK_MATRIX[impact - 1][confidence - 1]
        except IndexError:
            return "Unknown"

    # --- Correlation ---

    @staticmethod
    def _apply_correlations(malware_indicators):
        """
        Cross-indicator correlation pass.  After all indicators have been scored
        individually, look for co-occurrence patterns that raise confidence on
        participating indicators and add a synthetic correlated_boost reason.

        Rules (all additive, capped at 4):
          1. EID 8 (CreateRemoteThread) + EID 10 (ProcessAccess) together →
             confirmed in-memory attack chain; both get +1 confidence.
          2. EID 10 lsass access + EID 11 mimikatz file → credential dump chain;
             both get +1 confidence.
          3. EID 1 (hacking tool) + EID 3 (C2 connection) → tool launched then
             phoned home; both get +1 confidence.
          4. EID 12/13 security control disabled + EID 7045 malicious service →
             defence evasion then persistence; both get +1 confidence.
          5. EID 1102 (log cleared) paired with ANY other indicator → deliberate
             cover-up; EID 1102 indicator gets +1 confidence.
          6. EID 4625 (failed logins) + EID 4740 (lockout) within same session →
             confirmed brute-force; both get +1 confidence.
        """
        fired_eids = {ind['event_id'] for ind in malware_indicators}

        # Build a lookup: event_id → list of indicator dicts (there may be >1 row per EID)
        by_eid = defaultdict(list)
        for ind in malware_indicators:
            by_eid[ind['event_id']].append(ind)

        def _boost(ind, reason):
            new_conf = min(4, ind['actual_confidence'] + 1)
            if new_conf > ind['actual_confidence']:
                ind['actual_confidence'] = new_conf
                if reason not in ind['boost_reasons']:
                    ind['boost_reasons'].append(reason)
                ind['matrix_risk'] = MalwareAnalyzer._risk_from_matrix(
                    ind['impact'], ind['actual_confidence']
                )

        # Rule 1: injection + memory access = in-memory attack chain
        if '8' in fired_eids and '10' in fired_eids:
            for ind in by_eid['8'] + by_eid['10']:
                _boost(ind, 'correlation: EID 8 (thread injection) + EID 10 (process access) = in-memory attack chain')

        # Rule 2: lsass memory access + mimikatz file = confirmed credential dump
        eid10_cred = [i for i in by_eid['10'] if i.get('category') == 'Credential Access']
        eid11_mimi = [i for i in by_eid['11'] if 'Mimikatz' in i.get('threat', '')
                      or 'Credential' in i.get('threat', '')]
        if eid10_cred and eid11_mimi:
            for ind in eid10_cred + eid11_mimi:
                _boost(ind, 'correlation: EID 10 (lsass access) + EID 11 (file create) = credential dumping')

        # Rule 3: hacking tool launched + C2 network connection
        eid1_tool = [i for i in by_eid['1'] if i.get('category') == 'Execution']
        eid3_c2   = [i for i in by_eid['3']]
        if eid1_tool and eid3_c2:
            for ind in eid1_tool + eid3_c2:
                _boost(ind, 'correlation: EID 1 (hacking tool launched) + EID 3 (network connection) = C2 callback')

        # Rule 4: security control disabled + malicious service installed
        evasion_eids = {'12', '13', '5001', '5004', '1102'}
        if fired_eids & evasion_eids and '7045' in fired_eids:
            for eid in fired_eids & evasion_eids:
                for ind in by_eid[eid]:
                    _boost(ind, 'correlation: security control disabled + EID 7045 (malicious service) = defense evasion → persistence')
            for ind in by_eid['7045']:
                _boost(ind, 'correlation: security control disabled + EID 7045 (malicious service) = defense evasion → persistence')


        # Rule 6: failed logins + lockout = confirmed brute-force
        if '4625' in fired_eids and '4740' in fired_eids:
            for ind in by_eid['4625'] + by_eid['4740']:
                _boost(ind, 'correlation: EID 4625 (failed login) + EID 4740 (account lockout) = brute force')

        # Rule 7: MSI-delivery chain — EID 2 (msiexec timestomping) + EID 1
        # (heuristic shell spawn) indicates an MSI package was used to deliver
        # a payload.  The combination is more suspicious than either alone because
        # msiexec timestomping paired with a post-extraction shell is the hallmark
        # of a meterpreter-over-MSI attack.
        eid2_msi = [i for i in by_eid.get('2', [])
                    if i.get('category') == 'Defense Evasion']
        eid1_heuristic = [i for i in by_eid.get('1', [])
                          if i.get('category') == 'Execution']
        if eid2_msi and eid1_heuristic:
            for ind in eid2_msi + eid1_heuristic:
                _boost(ind, 'correlation: EID 2 (timestomping) + EID 1 (process create) = MSI payload delivery')



        return malware_indicators

    # --- Analysis ---

    def analyze_for_malware(self, results, timeline_data=None):
        """
        Analyze parsed event results for malware indicators.

        Args:
            results: dict from parser.analyze_events()
            timeline_data: optional timeline dict for confidence boosting

        Returns dict with:
            malware_indicators, risk_level, highest_impact, highest_confidence,
            highest_cvss_score, events_by_category, total_malware_events,
            total_event_occurrences
        """
        all_events = [
            event
            for key in ('sysmon_events', 'security_events', 'system_events',
                        'defender_events', 'windows_events')
            for event in results.get(key, [])
        ]

        matched_events = defaultdict(list)
        for event in all_events:
            event_type = event.get('type', 'Unknown')
            event_id   = event.get('event_id')
            key        = f"{event_type}:{event_id}"
            if key in self.malware_events:
                for info in self.malware_events[key]:
                    sub_key = f"{key}:{info['threat']}"
                    if self._event_matches_indicators(event, info['indicators'], event_type, event_id):
                        matched_events[sub_key].append((event, info))

        # EID 4625 (Failed Login / Brute Force): a single failed login is noise —
        # mistyped passwords happen constantly. Only score it when there are enough
        # failures to constitute a real spray or brute-force attempt.
        _COUNT_THRESHOLDS = {
            '4625': 5,   # need ≥5 failures before brute-force fires
            '4776': 5,   # NTLM credential validation failures — same rationale
            '4771': 3,   # Kerberos pre-auth failures — slightly lower bar
        }
        for sub_key in list(matched_events.keys()):
            pairs   = matched_events[sub_key]
            eid     = pairs[0][1]['event_id'] if pairs else None
            minimum = _COUNT_THRESHOLDS.get(eid)
            if minimum and len(pairs) < minimum:
                del matched_events[sub_key]

        malware_indicators = []
        events_by_category = defaultdict(list)

        for key, matching_pairs in matched_events.items():
            matching_events = [pair[0] for pair in matching_pairs]
            info      = matching_pairs[0][1]
            count     = len(matching_events)
            impact    = info['impact']
            base_conf = info['base_confidence']

            actual_conf, boost_reasons = self._calculate_dynamic_confidence(
                info['event_id'], base_conf, impact, count, timeline_data
            )
            matrix_risk = self._risk_from_matrix(impact, actual_conf)

            indicator = {
                'event_id':           info['event_id'],
                'event_type':         info['event_type'],
                'description':        info['description'],
                'threat':             info['threat'],
                'count':              count,
                'cvss_score':         info['score'],
                'impact':             impact,
                'base_confidence':    base_conf,
                'actual_confidence':  actual_conf,
                'boost_reasons':      boost_reasons,
                'matrix_risk':        matrix_risk,
                'category':           info['category'],
                'indicators_to_check': info['indicators'],
                'finding':            info['finding'],
                'immediate_actions':  info['immediate_actions'],
                'followups':          info['followups'],
                'matched_events':     matching_events,
            }
            malware_indicators.append(indicator)
            events_by_category[info['category']].append(indicator)

        # Correlation pass — must run after all indicators are scored so
        # co-occurrence checks can see the full fired-EID set.
        malware_indicators = self._apply_correlations(malware_indicators)

        # Re-sort after correlation may have updated matrix_risk values.
        malware_indicators.sort(
            key=lambda x: (RISK_PRIORITY.get(x['matrix_risk'], 0), x['impact']),
            reverse=True
        )

        # Rebuild events_by_category after correlation so downstream code
        # (assessment, report) sees the final boosted matrix_risk per category.
        events_by_category = defaultdict(list)
        for ind in malware_indicators:
            events_by_category[ind['category']].append(ind)

        highest_risk = max(
            (ind['matrix_risk'] for ind in malware_indicators),
            key=lambda r: RISK_PRIORITY.get(r, 0),
            default="Low"
        )

        return {
            'malware_indicators':      malware_indicators,
            'highest_cvss_score':      max((i['cvss_score'] for i in malware_indicators), default=0),
            'highest_impact':          max((i['impact'] for i in malware_indicators), default=0),
            'highest_confidence':      max((i['actual_confidence'] for i in malware_indicators), default=0),
            'risk_level':              highest_risk,
            'events_by_category':      dict(events_by_category),
            'total_malware_events':    len(malware_indicators),
            'total_event_occurrences': sum(i['count'] for i in malware_indicators),
        }


# ------------------------------------------------------------------ #
# Assessment generation (CSV-driven, no hardcoded findings/actions)
# ------------------------------------------------------------------ #

def generate_assessment(malware_analysis):
    """
    Build a formal assessment from the Finding / ImmediateAction / FollowUp
    fields stored on each fired indicator (loaded from CSV at startup).

    Returns dict with 'narrative', 'immediate_actions', 'followups'.
    """
    risk_level   = malware_analysis.get('risk_level', 'Unknown')
    categories   = set(malware_analysis.get('events_by_category', {}).keys())
    indicators   = malware_analysis.get('malware_indicators', [])
    total_hits   = malware_analysis.get('total_event_occurrences', 0)
    total_types  = malware_analysis.get('total_malware_events', len(indicators))

    # Paragraph 1: risk summary + active MITRE categories
    opener = {
        'Critical': f"Analysis identified {total_types} threat type(s) across {total_hits} event occurrence(s) at Critical risk. Immediate containment is required.",
        'High':     f"Analysis identified {total_types} threat type(s) across {total_hits} event occurrence(s) at High risk. Prompt investigation is recommended.",
        'Medium':   f"Analysis identified {total_types} threat type(s) across {total_hits} event occurrence(s) at Medium risk. Review is recommended.",
        'Low':      f"Analysis identified {total_types} threat type(s) across {total_hits} event occurrence(s) at Low risk. No immediate action required.",
    }.get(risk_level, f"Analysis identified {total_types} threat type(s) across {total_hits} event occurrence(s). Review is recommended.")

    # Note if any indicators were caught by parent-chain heuristics rather than
    # named-tool CSV matches (e.g. jjs.exe → cmd.exe, msiexec → .tmp → whoami).
    heuristic_boosts = [
        ind for ind in indicators
        if any('MSI delivery chain' in r or 'heuristic spawner' in r
               for r in ind.get('boost_reasons', []))
    ]
    if heuristic_boosts:
        opener += (" Note: one or more detections were triggered by behavioural"
                   " parent-chain heuristics (e.g. installer or scripting engine"
                   " spawning a discovery shell) rather than named-tool indicators."
                   " Manual review of the process tree is recommended.")

    active_cats = [c for c in _MITRE_ORDER if c in categories]
    active_cats += [c for c in categories if c not in _MITRE_ORDER]
    if active_cats:
        opener += f" Active threat categories: {', '.join(active_cats)}."

    # Paragraph 2: per-indicator findings (from CSV Finding field)
    # Special case: when both 4720 (account created) and 4726 (account deleted) fire,
    # 4726's Finding already covers both ("created then deleted"). Suppress 4720's
    # standalone finding to avoid describing the same event twice.
    fired_ids = {ind['event_id'] for ind in indicators}
    suppress_finding_for = set()
    if '4720' in fired_ids and '4726' in fired_ids:
        suppress_finding_for.add('4720')

    findings = _deduped_list(
        ind.get('finding', '')
        for ind in indicators
        if ind['event_id'] not in suppress_finding_for
    )
    paragraphs = [opener] + findings  # each finding rendered as its own paragraph

    # Immediate actions and follow-ups: pull from the single highest-severity
    # indicator per MITRE category to prevent overlapping action lists.
    def _top_per_category(inds):
        best = {}
        for ind in inds:
            cat   = ind.get('category', 'Unknown')
            score = ind.get('impact', 0) * ind.get('base_confidence', 0)
            if cat not in best or score > best[cat][0]:
                best[cat] = (score, ind)
        return [v for _, v in best.values()]

    top_indicators = _top_per_category(indicators)

    prepend = []
    if risk_level in ('Critical', 'High'):
        prepend.append("Isolate the affected host from the network immediately.")
        if 'Defense Evasion' in categories:
            prepend.append("Acquire a memory image before rebooting. Volatile artifacts will be lost on restart.")

    csv_immediate = _deduped_list(
        action
        for ind in top_indicators
        for action in ind.get('immediate_actions', [])
    )
    immediate = _deduped_list(prepend + csv_immediate) or [
        "Review flagged events in the Deep Dive section and confirm whether activity was authorized."
    ]

    csv_followups = _deduped_list(
        fu
        for ind in top_indicators
        for fu in ind.get('followups', [])
    )
    close = ["Document findings and timeline for incident recordkeeping."]
    if risk_level in ('Critical', 'High'):
        close.append("Escalate to senior IT security staff.")
    followups = _deduped_list(csv_followups + close)

    return {
        'narrative':         paragraphs,
        'immediate_actions': immediate,
        'followups':         followups,
    }


# ------------------------------------------------------------------ #
# Convenience wrapper
# ------------------------------------------------------------------ #

def analyze_malware(results, timeline_data=None,
                    malware_csv='malware_indicators.csv',
                    breach_csv='breach_indicators.csv',
                    defender_csv='defender_indicators.csv'):
    """Create a MalwareAnalyzer and run analysis in one call."""
    return MalwareAnalyzer(
        malware_csv=malware_csv,
        breach_csv=breach_csv,
        defender_csv=defender_csv,
    ).analyze_for_malware(results, timeline_data)


# ------------------------------------------------------------------ #
# Timeline extraction
# ------------------------------------------------------------------ #

def extract_timeline(events, window_minutes=5):
    """
    Build a timeline from parsed event_entry dicts (output of parse_evtx).

    Returns dict with 'chronological_events' (sorted) and
    'grouped_events' (keyed by time-window start datetime).
    """
    timeline = []

    for event in events:
        try:
            system_time = event["basic_info"].get("time_created")
            eid         = event.get("event_id", "Unknown")

            if not system_time:
                continue

            timestamp = datetime.fromisoformat(system_time.replace("Z", "+00:00"))
            # Normalise the stored string so report timestamps are always
            # human-readable (YYYY-MM-DD HH:MM:SS.ffffff) regardless of
            # whether the Rust evtx parser emitted ISO-8601 T/Z suffixes.
            clean_time = system_time.replace("T", " ").rstrip("Z").split("+")[0].strip()
            event["basic_info"]["time_created"] = clean_time
            timeline.append({
                "timestamp": timestamp,
                "event_id":  eid,
                "event":     event,
            })
        except Exception:
            continue

    timeline.sort(key=lambda x: x["timestamp"])

    grouped = defaultdict(list)
    for event in timeline:
        ts           = event["timestamp"].replace(second=0, microsecond=0)
        window_start = ts - timedelta(minutes=ts.minute % window_minutes)
        grouped[window_start].append(event)

    return {
        "chronological_events": timeline,
        "grouped_events":       dict(grouped),
    }


if __name__ == "__main__":
    print("=== Malware Analysis Engine with Impact x Confidence Matrix ===")
    print("Usage: from analysis import analyze_malware, extract_timeline")
    print("\n1. Parse your log file using parser.py")
    print("2. Extract timeline: extract_timeline(events)")
    print("3. Analyze:          analyze_malware(results, timeline_data)")
