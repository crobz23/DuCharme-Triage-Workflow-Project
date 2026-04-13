# DuCharme Triage Assistant

**Version 0.7** | Trine University Senior Capstone Project

A Windows event log analyzer that helps incident responders quickly identify malware and security breaches through a triage workflow. Built for DuCharme, McMillen & Associates, Inc.

---

## Table of Contents

- [Release Notes](#release-notes)
- [What This Tool Does](#what-this-tool-does)
- [How It Works](#how-it-works)
- [Getting Started](#getting-started)
- [How to Use](#how-to-use)
- [Understanding the Results](#understanding-the-results)
- [Threat Detection](#threat-detection)
- [Troubleshooting](#troubleshooting)
- [For Developers](#for-developers)
- [Quick Reference Card](#quick-reference-card)
- [Credits](#credits)

---

## Release Notes

### Version 0.7 (Current)

**parser.py:**
- Rewritten to use the Rust-based `evtx` library, replacing the previous Python-based parser. Parsing is now 3-5x faster on the same hardware
- The parser now extracts structured evidence fields from each event at parse time: process chains, parent processes, command lines, IP addresses, user accounts, logon types, registry keys, and more. This data feeds the new Deep Dive Evidence section in the GUI and PDF report directly

**analysis.py:**
- A third indicator file, `defender_indicators.csv`, is now loaded alongside the existing malware and breach CSVs. Windows Defender events were already parsed in previous versions but were not scored; they are now fully analyzed for threats
- The three CSV files now include `Finding`, `ImmediateAction`, and `FollowUp` columns. A new `generate_assessment()` function builds the report narrative, immediate action steps, and follow-up recommendations entirely from these columns with nothing hardcoded in the engine
- Cross-indicator correlation logic added: after all indicators are scored individually, the engine checks for co-occurring Event ID combinations that together indicate a more serious attack chain. Eight correlation rules are applied, including injection confirmation (EID 8 + EID 10), credential dumping (EID 10 + EID 11), log clearing paired with any other indicator (EID 1102), and confirmed brute force (EID 4625 + EID 4740). Indicators involved in a confirmed correlation receive a confidence boost
- A boost cap has been added: low-signal indicators (base confidence <= 2 and impact <= 2) can only receive a maximum of +1 confidence boost regardless of event volume, preventing noisy but benign high-frequency events from reaching Critical
- Minimum occurrence thresholds added for high-frequency Security events: EID 4625 (failed logins) requires at least 5 occurrences, EID 4776 requires at least 5, and EID 4771 requires at least 3 before they are scored at all
- False positive suppression substantially improved across Sysmon EIDs 1, 3, 7, 8, 10, 11, 12, 13, 22, and 23. EID 1 (process creation) now uses whole-word matching and parent-chain heuristics to catch LOLBIN abuse and MSI-delivered payloads even when the binary name is not listed in the CSV

**report.py:**
- Three new sections added to the PDF report: Executive Summary (Section 1), Deep Dive Evidence (Section 7), and Assessment & Actions (Section 8). The report is now eight sections total
- The Executive Summary displays the overall risk level, active MITRE threat categories, and a plain-English narrative generated from the CSV Finding fields
- The Deep Dive Evidence section shows the specific event evidence (timestamps, processes, IPs, registry keys, etc.) for each flagged threat, so analysts can verify findings without returning to the raw logs
- The Assessment & Actions section lists immediate containment steps and follow-up recommendations pulled directly from the CSV, tailored to the threats detected in that specific analysis

**gui.py:**
- The malware summary panel now renders structured evidence for each flagged event inline, using the evidence fields extracted by the parser. Sysmon events are labeled with their specific EID description for clarity

**defender_indicators.csv (new file):**
- Covers Defender-specific Event IDs including 1116 (malware detected), 1118 (remediation failed), 1121 (behavior blocked), 1123 (ransomware protection triggered), 5001 and 5004 (Tamper Protection disabled or tampered with), and others

---

## What This Tool Does

When something suspicious happens on a computer, the system creates event logs. These logs contain thousands of entries that are nearly impossible to read manually.

This tool analyzes those logs for you and tells you:
- Is there malware on the system?
- Is someone trying to break in?
- What happened, when did it happen, and how serious is it?
- Ranks the threats based on severity using an Impact x Confidence matrix
- What you should do next

Instead of spending hours digging through logs, you get a clean PDF report with threat scores and recommendations. Any IT Help Desk Analyst can isolate a machine from the network, plug a USB with the tool in, and run it to analyze threats.

---

## How It Works

### Data Flow Diagram

```
┌──────────────────────────────────────────────────┐
│         INPUT: .evtx Log File(s)                 │
│   Security  /  System  /  Sysmon  /  Defender    │
└─────────────────────┬────────────────────────────┘
                      │
                      ▼
         ┌────────────────────────┐
         │   parser.py            │
         │                        │
         │  Reads & classifies    │
         │  events by channel     │
         │                        │
         │  Extracts per-event:   │
         │    processes, IPs,     │
         │    users, registry,    │
         │    timestamps          │
         └───────────┬────────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
┌──────────────────┐  ┌─────────────────────────────────────┐
│  Timeline        │  │  Threat Detection                   │
│  (analysis.py)   │  │  (analysis.py)                      │
│                  │  │                                     │
│                  │  │  Loads indicator CSVs:              │
│  Sorts events    │  │    malware_indicators.csv           │
│  by time         │  │    breach_indicators.csv            │
│                  │  │    defender_indicators.csv          │
│  Detects burst   │  │                                     │
│  clusters in     │  │  Matches events by EventType:EventID│
│  5-min windows   │  │  Checks IOC strings in event fields │
│                  │  │  Scores Impact x Confidence         │
└────────┬─────────┘  │  Boosts by frequency, clustering,  │
         │            │    and correlation rules            │
         └───────────>│  Generates assessment from CSV text │
   (cluster counts    └─────────────────┬───────────────────┘
    fed into scoring)                   │
                                        │
                         ┌─────────────┴─────────────┐
                         │                           │
                         ▼                           ▼
            ┌────────────────────┐     ┌─────────────────────────┐
            │  gui.py            │     │  report.py              │
            │                    │     │                         │
            │  Displays results: │     │  User fills in incident │
            │    Risk levels     │     │  context in the GUI;    │
            │    Top 5 threats   │     │  results are passed to  │
            │    Truncated       │     │  report.py              │
            │    evidence        │     │                         │
            │                    │     │  Generates PDF:         │
            │  Filters:          │     │   1. Executive Summary  │
            │    by Event ID     │     │   2. File Info          │
            │    by Time range   │     │   3. Asset & Scope      │
            └────────────────────┘     │   4. Incident Context   │
                                       │   5. Timeline           │
                                       │   6. Threat Indicators  │
                                       │   7. Deep Dive Evidence │
                                       │   8. Assessment &       │
                                       │      Actions            │
                                       └───────────┬─────────────┘
                                                   │
                                                   ▼
                                       ┌───────────────────────┐
                                       │  OUTPUT: PDF Report   │
                                       │  triage_report_*.pdf  │
                                       └───────────────────────┘
```

---

## Getting Started

### What You Need

- A Windows computer
- Windows event log files (.evtx format)

### Installation

1. Go to [our GitHub repository](https://github.com/crobz23/DuCharme-Triage-Workflow-Project)
2. Click the "Releases" button on the right panel and select "DuCharme_Triage_Assistant_V7.exe"
3. Save the file to your computer and run the .exe

---

## How to Use

### Basic Workflow

**Step 1: Start the application**

Double-click `DuCharme_Triage_Assistant_V7.exe` to launch the tool. A window will open with the DuCharme Triage Assistant interface.

**Step 2: Load your log file(s)**

You have three options:

- **Browse File** — select one or more .evtx files directly
- **Browse Directory** — select a folder to load all .evtx files inside it; files are accepted regardless of name, so custom exports work fine
- **Default Windows Logs** — automatically loads the four supported log types directly from `C:\Windows\System32\winevt\Logs` (Security, System, Sysmon, and Windows Defender only)

Common log locations:
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Security events)
- `C:\Windows\System32\winevt\Logs\System.evtx` (System events)
- `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` (Sysmon, if installed)
- `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx` (Windows Defender)

**Step 3: Analyze**

Click the "Analyze" button. The tool will parse all selected log files and show you:
- How many total events were found across all files, broken down by channel
- Event ID breakdown; Sysmon Event IDs are annotated with `(Sysmon)` to distinguish them from Windows System IDs that share the same number
- Threat analysis with Impact x Confidence matrix risk levels
- Which threats had their confidence score boosted due to frequency, clustering, or a confirmed attack chain correlation
- Inline evidence for each flagged threat: process names, command lines, IPs, registry keys, and more, so you can verify findings without opening the raw logs

**Step 4: Filter (optional)**

Two filtering options are available and can be used together in any order:

- **Filter by Event ID** — select specific Event IDs to focus on
- **Time Filtering** — narrow results to a specific time window using quick presets (Last 24 Hours, Last 7 Days, Last 30 Days) or a custom date and time range

Both filters stack; applying one does not reset the other. Use the "Clear Filters" button to reset both at once.

**Step 5: Generate Report**

Click "Generate Report (PDF)" to create a professional report. A dialog will open asking you to fill in incident context (who reported it, what they observed, etc.), with a 500-character limit per field. After submitting, you will be prompted to choose where to save the PDF.

The report includes:
- Executive summary with overall risk level and a plain-English narrative of what was found
- File information
- Asset and scope details (what computers, users, IPs were involved)
- Incident context
- Timeline of events
- Threat indicators with Impact, Confidence, matrix risk level, and Event ID descriptions
- Risk levels color-coded by severity
- Deep dive evidence — the specific raw details behind each flagged threat (see subsections below)
- Assessment and actions — immediate containment steps and follow-up recommendations tailored to what was found

Each subsection of the Deep Dive Evidence section only appears in the report if there is matching threat evidence for it. Subsections with no relevant events are skipped entirely.

| Subsection | What It Shows |
|---|---|
| Suspicious Activity | Process launches and script executions flagged as malicious (Sysmon EID 1, Security EID 4688, PowerShell EID 4104, file drops and timestomping) |
| Persistence Changes — Account Activity | New user accounts created, scheduled tasks added, and suspicious registry run keys written |
| Persistence Changes — Service Installations | New services installed on the system (System EID 7045) |
| Credential Theft & Memory Access | LSASS memory access and Mimikatz output files (Sysmon EID 10, EID 11 — Credential Access category) |
| Logon & Directory Activity | Login events, failed logins, DCSync attempts, and group membership changes (Security EID 4624, 4625, 4648, 4662, 4728) |
| Network Observations | Outbound network connections and DNS queries made by flagged processes (Sysmon EID 3, EID 22) |
| Enumeration & Discovery | Network share and named pipe access consistent with AD enumeration tools like BloodHound or PowerView (Security EID 5145) |
| Malware / AV / OS Protections | Windows Defender detections, blocked behaviors, and Tamper Protection events |

---

## Understanding the Results

### Risk Levels

The tool assigns an overall risk level based on what it finds:

- **Low**: Normal activity, nothing alarming. Maybe keep an eye on it.
- **Medium**: Something unusual is happening. Worth investigating.
- **High**: Probable attack or compromise in progress. Act soon.
- **Critical**: Active or confirmed breach. Immediate response required.

### Threat Categories (MITRE ATT&CK)

- **Execution**: Something tried to run malicious code
- **Persistence**: Something tried to survive a reboot
- **Privilege Escalation**: Something tried to gain admin rights
- **Defense Evasion**: Something tried to hide itself or clear logs
- **Credential Access**: Something tried to steal passwords
- **Lateral Movement**: Something tried to spread to other systems
- **Impact**: Destructive actions (file deletion, ransomware)

---

## Threat Detection

### How Risk is Calculated

Each detected threat is scored using two values and then run through a risk matrix:

**Impact** (What would this mean if true?)

| Impact Level | Description | Example Log Patterns |
|---|---|---|
| 1 – Low | Routine activity or misconfiguration | Single failed login |
| 2 – Moderate | Suspicious but limited scope | Multiple failed logins from one host |
| 3 – High | Privilege escalation or lateral movement indicators | Account added to admin group |
| 4 – Critical | Domain-wide compromise or ransomware indicators | DC account manipulation + mass encryption |

---

**Confidence** (How strong is the evidence?)

| Confidence Level | Description | Example Scenario |
|---|---|---|
| 1 – Weak | Single isolated event | One 4625 |
| 2 – Correlated | Multiple related logs | 4625 + 4624 success |
| 3 – Behavioral Pattern | Clear attack chain | 4688 + 4624 + 4672 |
| 4 – Confirmed Malicious | Known IOC or tool match | Mimikatz string, C2 beacon |

---

Confidence is boosted automatically when:
- The same Event ID appears 5 or more times -> +1
- The same Event ID appears 50 or more times -> +2
- 20 or more events of the same type occur in a single 5-minute window -> +1 (active attack clustering)
- Two or more Event IDs together confirm a known attack chain -> +1 on each participating indicator (see Correlation Rules below)

Confidence is capped at 4. The reasons for any boost are stored alongside the indicator so the help desk can see exactly why a score was elevated.

To prevent noisy but benign high-frequency events from inflating scores, low-signal indicators (base confidence <= 2 and impact <= 2) can receive a maximum boost of +1 regardless of volume. Additionally, some high-frequency Security events require a minimum number of occurrences before they are scored at all. For example, failed login events (EID 4625) must occur at least 5 times before the tool considers them a brute force indicator.

### Correlation Rules

After all indicators are scored individually, the tool checks whether certain Event ID combinations appeared together in the same session. When they do, the involved indicators each receive an additional confidence boost, because the combination is more suspicious than either event alone. The eight correlation rules are:

| Rule | Event IDs | What It Means |
|---|---|---|
| In-memory attack chain | EID 8 + EID 10 | Code injection followed by memory access, confirming a running payload |
| Credential dump chain | EID 10 + EID 11 | LSASS memory access followed by a Mimikatz output file |
| Tool launch + C2 callback | EID 1 + EID 3 | Hacking tool executed, then made an outbound network connection |
| Defense evasion + persistence | EID 12/13 or 1102 + EID 7045 | Security controls disabled, then a malicious service installed |
| Cover-up detected | EID 1102 + any other | Security log cleared alongside other suspicious activity |
| Confirmed brute force | EID 4625 + EID 4740 | Failed logins followed by an account lockout |
| MSI delivery chain | EID 2 + EID 1 | Installer timestomping followed by a suspicious process spawn |
| Heuristic spawner + C2 | EID 1 (heuristic) + EID 3 | A scripting engine or temp binary spawned a shell, then called out |

### Risk Matrix

**Impact**
1 = Low
2 = Medium
3 = High
4 = Critical

**Confidence**
1 = Low (possible)
2 = Medium (likely)
3 = High (probable)
4 = Confirmed

Once Impact and Confidence are both determined, the matrix below resolves them to a final risk level:

| | Confidence 1 | Confidence 2 | Confidence 3 | Confidence 4 |
|---|---|---|---|---|
| **Impact 4** | High | Critical | Critical | Critical |
| **Impact 3** | Medium | High | Critical | Critical |
| **Impact 2** | Medium | Medium | High | High |
| **Impact 1** | Low | Medium | Medium | Medium |

The overall risk level shown in the application is always the highest matrix result found across all detected threats.

### The CSV Files

The tool uses three CSV files to define what it looks for:

**malware_indicators.csv** — Detects malware and hacking tools
- Suspicious programs (mimikatz, psexec, cobaltstrike, etc.)
- Encoded PowerShell commands
- Code injection and process hollowing
- Malicious services, scheduled tasks, and drivers
- Alternate data stream usage and timestomping

**breach_indicators.csv** — Detects break-in attempts
- Failed login attempts (brute force)
- Account lockouts and Kerberos attacks
- Privilege escalation (user added to admin groups)
- Unauthorized account creation and modification
- Security log clearing

**defender_indicators.csv** — Detects Windows Defender alerts
- Malware detected or remediation failed
- Suspicious behavior blocked by behavior monitoring
- Ransomware protection triggered (Controlled Folder Access)
- Tamper Protection disabled or tamper attempt detected
- Real-time protection disabled

**CSV Format:**

| Column Name | What It Means | Example Value |
|-------------|---------------|---------------|
| EventType | The log channel the event comes from | Sysmon |
| EventID | The event's identification number | 4625 |
| Description | Brief explanation | "Failed Login Attempt" |
| Threat | What kind of attack this indicates | "Brute Force Attack" |
| Score | CVSS severity reference (0-10 scale) | 7.0 |
| Impact | How damaging if confirmed (1-4 scale) | 2 |
| BaseConfidence | Starting confidence this is malicious (1-4 scale) | 1 |
| Category | MITRE ATT&CK attack category | "Credential Access" |
| Indicators | Specific strings to search for in event data that are Indicators of Compromise | "mimikatz.exe; psexec.exe" |
| Finding | Plain-English description of what this threat means if confirmed | "A known credential harvester was executed..." |
| ImmediateAction | Containment steps to take right now | "Isolate the host; reset all credentials" |
| FollowUp | Longer-term remediation and hardening steps | "Enable Credential Guard..." |

**Column Sources:**

The columns are a mix between industry standards and our own creation. Triage-wise, threats are ranked by matrix risk level first, then by Impact as a tiebreaker.

Standardized:
- EventID (Microsoft)
- Category (MITRE ATT&CK)
- CVSS Score methodology (FIRST.org industry standard calculator)

Our creation:
- EventType
- Description
- Threat
- Indicators
- Finding
- ImmediateAction
- FollowUp
- Impact values
- BaseConfidence values
- Specific score assignments

---

## Troubleshooting

### "No events found" error

**Problem**: The log file couldn't be parsed.

**Solution**:
- Make sure you're loading an actual .evtx file (not a .txt or .csv)
- The file might be corrupted; try a different log file
- You might need administrator privileges to access certain log files

### "Permission Denied" when using Default Windows Logs

**Problem**: The tool cannot read logs directly from `C:\Windows\System32\winevt\Logs` without elevated privileges.

**Solution**:
- Close the tool, right-click the executable, and select "Run as administrator"
- Alternatively, export the logs from Event Viewer (right-click a log, select "Save All Events As...", save as .evtx) and load the exported files using Browse File instead

### Tool is slow or freezing

**Problem**: Large log files (100MB+) can take a while to process.

**Solution**: This is normal for logs with hundreds of events. Give it a minute or two. Multiple files are now processed in parallel, so loading a full directory is faster than in previous versions. Use the Default Windows Logs button or Browse Directory to limit the load to the four supported log types when scanning a system folder.

### "Generate Report" button is grayed out

**Problem**: You need to analyze a log file first before generating a report.

**Solution**: Click "Analyze" first, then the report button will become available.

### PDF won't generate

**Problem**: The PDF generation library may have encountered an error.

**Solution**: Try re-downloading the latest .exe from the GitHub releases page.

### Tool crashes immediately on launch

**Problem**: A required Visual C++ runtime component may be missing on the target machine.

**Solution**: Install the Visual C++ Redistributable from Microsoft: https://aka.ms/vs/17/release/vc_redist.x64.exe

### Antivirus flags the .exe as suspicious

**Problem**: Some antivirus tools flag PyInstaller-packaged executables as potentially unwanted.

**Solution**: The tool is safe to run. Whitelist the executable in your antivirus software if needed.

---

## For Developers

### Project Structure

```
DuCharme-Triage-Workflow-Project/
├── main.py                      # Application entry point
├── gui.py                       # User interface
├── parser.py                    # Event log parsing
├── analysis.py                  # Threat detection engine
├── report.py                    # PDF generation
├── malware_indicators.csv       # Malware detection rules
├── breach_indicators.csv        # Breach detection rules
├── defender_indicators.csv      # Windows Defender detection rules
└── requirements.txt             # Python dependencies
```

---

## Quick Reference Card

**Most Common Event IDs:**

| Event ID | What It Means | Why It Matters |
|----------|---------------|----------------|
| 4625 | Failed login attempt | Could be brute force attack |
| 4624 | Successful login | Normal, but watch for odd times/locations |
| 4688 | Program started | Look for suspicious executables |
| 1102 | Logs cleared | Someone covering their tracks |
| 7045 | Service installed | Malware often installs services |
| 4698 | Scheduled task created | Common persistence mechanism |
| 4732 | User added to admin group | Privilege escalation |
| 1 (Sysmon) | Process created | Hacking tool launched (e.g. mimikatz.exe) |
| 10 (Sysmon) | Process memory access | Credential theft (LSASS) |
| 1116 (Defender) | Malware detected | Windows Defender found a known threat |
| 1123 (Defender) | Ransomware protection triggered | Controlled Folder Access blocked a write |

---

## Credits

**Development Team**
- Collin Robinson — Project Manager, analysis engine, integrator, tester
- Matthew Domsich — Timeline analysis, parsing, researcher
- Nathan Bradshaw — Report generation, GUI Designer, posterboard design

**Sponsor**
- Eric Gaby

**Special Thanks**
- Dr. David Corcoran (Advisor)
- Dr. William Topp (Advisor)
- Senior Capstone Classmates

---

Version 0.7 | Last updated: Apr. 2026
