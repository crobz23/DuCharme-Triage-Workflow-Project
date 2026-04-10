# parser.py - Windows, Sysmon, System.evtx, and Windows Defender support
# Uses the Rust-based 'evtx' library for binary parsing (3-5x faster than python-evtx).
# Install: pip install evtx --no-binary evtx
import evtx as evtx_lib
import json
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import sys

# ==================== Constants ====================

_CREDENTIAL_EIDS = {
    "4624", "4625", "4648", "4662",
    "4728", "4729", "4732", "4733", "4740", "4771", "4776", "4720",
}

_GROUP_ADD_EIDS    = {"4732", "4728", "4720"}
_GROUP_REMOVE_EIDS = {"4729", "4733"}

_LOGON_TYPE_MAP = {
    "2":  "Interactive (local login)",
    "3":  "Network (remote share/service)",
    "4":  "Batch (scheduled task)",
    "5":  "Service account login",
    "7":  "Unlock (workstation unlock)",
    "8":  "Network plaintext",
    "9":  "New credentials (runas)",
    "10": "RemoteInteractive (RDP)",
    "11": "Cached credentials (offline login)",
}

_SYSMON_PROVIDER  = "Sysmon"
_SYSMON_CHANNEL   = "Microsoft-Windows-Sysmon"
_DEFENDER_KEYWORD = "Defender"

# ==================== Helpers ====================

def _resolve_member(data):
    member = data.get("MemberName")
    if not member or member.strip() == "-":
        member = data.get("MemberSid") or data.get("TargetUserName")
    if member and "CN=" in member:
        member = member.split(",")[0].replace("CN=", "").strip()
    return member if (member and not member.startswith("S-1-")) else "(name not logged)"


def _parse_reg_val(raw):
    if not raw:
        return None
    leaf = raw.rsplit("\\", 1)[-1]
    if " = " in leaf:
        key_name, val = (s.strip() for s in leaf.split(" = ", 1))
        is_disable_key = key_name.lower().startswith("disable")
        if val == "0x1":
            val = "0x1 (disabled)" if is_disable_key else "0x1 (enabled)"
        elif val == "0x0":
            val = "0x0 (enabled)" if is_disable_key else "0x0 (disabled)"
        return f"{key_name}: {val}"
    return leaf.strip()


def _str(val):
    """Safe string conversion — returns None for None/empty."""
    if val is None:
        return None
    s = str(val).strip()
    return s if s else None


# ==================== OS Version Mapping ====================

def map_build_to_windows_version(build_string):
    """Map Windows build numbers (e.g. '10.0.19045') to human-readable versions."""
    if not build_string:
        return None
    try:
        parts = build_string.split(".")
        if len(parts) < 2:
            return f"Windows (Build {build_string})"
        major = parts[0]
        minor = parts[1]
        build = parts[2] if len(parts) > 2 else "0"
        if major == "10" and minor == "0":
            return f"Windows 11 (Build {build})" if int(build) >= 22000 else f"Windows 10 (Build {build})"
        if major == "6" and minor == "3":
            return f"Windows 8.1 / Server 2012 R2 (Build {build})"
        if major == "6" and minor == "2":
            return f"Windows 8 / Server 2012 (Build {build})"
        if major == "6" and minor == "1":
            return f"Windows 7 / Server 2008 R2 (Build {build})"
        if major == "6" and minor == "0":
            return f"Windows Vista / Server 2008 (Build {build})"
        if major == "5" and minor == "2":
            return f"Windows Server 2003 (Build {build})"
        if major == "5" and minor == "1":
            return f"Windows XP (Build {build})"
        return f"Windows {major}.{minor} (Build {build})"
    except Exception:
        return f"Windows (Build {build_string})"


# ==================== User Classification ====================

def _is_system_account(username):
    if not username or username in ("-", "", "None"):
        return True
    if "@" in username:
        return True
    system_accounts = {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
        "NT AUTHORITY\\SYSTEM", "DWM-1", "DWM-2", "DWM-3", "DWM-4",
        "UMFD-0", "UMFD-1", "UMFD-2", "UMFD-3",
        "Guest", "DefaultAccount", "WDAGUtilityAccount",
    }
    windows_groups = {
        "Users", "Administrators", "Backup Operators", "Power Users",
        "Remote Desktop Users", "Guests", "Network Configuration Operators",
        "Performance Monitor Users", "Performance Log Users",
        "Distributed COM Users", "IIS_IUSRS", "Cryptographic Operators",
        "Event Log Readers", "Remote Management Users",
        "System Managed Accounts Group",
    }
    if username in system_accounts or username in windows_groups:
        return True
    ul = username.lower()
    for pat in ("system", "service", "dwm-", "umfd-", "font driver host",
                "window manager", "$", "test", "dummy", "doesnotexist", "example"):
        if pat in ul:
            return True
    return False


def _is_privileged_account(username):
    if not username:
        return False
    ul = username.lower()
    for pat in ("admin", "administrator", "root", "backup operator",
                "domain admin", "enterprise admin", "schema admin"):
        if pat in ul:
            return True
    return False


# ==================== Asset / Scope Extraction ====================

def _extract_asset_scope(basic_info, data):
    """
    Build asset + scope dicts from basic_info and event data fields.
    Mirrors the logic from the old XML-based parser.
    """
    asset = {}
    scope = {}

    computer = basic_info.get("computer")
    if computer:
        asset["hostname"] = computer

    for field in ("IpAddress", "SourceIp", "DestinationIp", "SourceAddress", "DestAddress"):
        val = data.get(field)
        if val and val not in ("-", "0.0.0.0", "127.0.0.1", "::1"):
            asset.setdefault("ip_addresses", []).append(val)

    # Categorise users
    privileged, regular = [], []
    for field in ("TargetUserName", "SubjectUserName", "User", "AccountName", "UserName"):
        username = data.get(field)
        if username and not _is_system_account(username):
            if _is_privileged_account(username):
                privileged.append(username)
            else:
                regular.append(username)
    if privileged:
        scope["privileged_users"] = privileged
    if regular:
        scope["regular_users"] = regular

    # Domains (skip junk values)
    _skip_domains = {"-", "", "NT AUTHORITY", "Window Manager",
                     "Font Driver Host", "Builtin", "MicrosoftAccount"}
    for field in ("TargetDomainName", "SubjectDomainName", "Domain"):
        domain = data.get(field)
        if domain and domain not in _skip_domains and domain != computer:
            scope.setdefault("domains", []).append(domain)

    for field in ("LogonType", "ProcessName", "Image", "CommandLine",
                  "TargetServerName", "WorkstationName"):
        if data.get(field):
            scope[field] = data[field]

    return {"asset": asset, "scope": scope}


# ==================== Classification ====================

def _classify_event(system):
    channel       = _str(system.get("Channel")) or ""
    provider      = system.get("Provider") or {}
    provider_name = _str(provider.get("Name") if isinstance(provider, dict) else provider) or ""

    if _SYSMON_PROVIDER in provider_name or channel.startswith(_SYSMON_CHANNEL):
        return "Sysmon", channel
    if _DEFENDER_KEYWORD in provider_name or _DEFENDER_KEYWORD in channel:
        return "Defender", channel
    if channel == "System":
        return "System", channel
    if channel == "Security":
        return "Security", channel
    if channel == "Application":
        return "Application", channel
    return "Windows", channel


# ==================== Record conversion ====================

def _record_to_entry(record_dict):
    """
    Convert one record dict from the Rust evtx parser into an event_entry
    dict that matches the format the rest of the app expects.

    The Rust library returns JSON-decoded dicts structured as:
        {
          "Event": {
            "System": { "EventID": ..., "Channel": ..., "TimeCreated": {...}, ... },
            "EventData": { "Data": [ {"@Name": k, "#text": v}, ... ] }
          }
        }
    """
    try:
        event_root = record_dict.get("Event", {})
        system     = event_root.get("System", {})

        # --- EventID ---
        raw_eid = system.get("EventID")
        if isinstance(raw_eid, dict):
            raw_eid = raw_eid.get("#text") or raw_eid.get("_")
        eid = _str(raw_eid)
        if not eid:
            return None

        event_type, channel = _classify_event(system)

        # --- TimeCreated ---
        tc = system.get("TimeCreated") or {}
        if isinstance(tc, dict):
            time_created = _str(tc.get("SystemTime") or tc.get("#attributes", {}).get("SystemTime"))
        else:
            time_created = _str(tc)

        # --- Provider name ---
        provider = system.get("Provider") or {}
        if isinstance(provider, dict):
            provider_name = _str(provider.get("Name") or provider.get("#attributes", {}).get("Name"))
        else:
            provider_name = _str(provider)

        basic_info = {
            "provider":     provider_name,
            "channel":      channel,
            "computer":     _str(system.get("Computer")) or "",
            "time_created": time_created,
            "record_id":    _str(system.get("EventRecordID")) or "",
            "level":        _str(system.get("Level")) or "",
        }

        # --- EventData / UserData ---
        data = {}
        raw_data = event_root.get("EventData") or event_root.get("UserData") or {}

        if isinstance(raw_data, dict):
            inner = raw_data.get("Data") or raw_data
            if isinstance(inner, list):
                for item in inner:
                    if isinstance(item, dict):
                        name = item.get("@Name") or item.get("Name")
                        val  = item.get("#text") or item.get("_")
                        if name is not None:
                            data[str(name)] = _str(val)
            elif isinstance(inner, dict):
                for k, v in inner.items():
                    if not k.startswith("@") and not k.startswith("#"):
                        data[k] = _str(v)

        event_entry = {
            "event_id":   eid,
            "type":       event_type,
            "channel":    channel,
            "basic_info": basic_info,
            "data":       data,
        }
        event_entry["evidence"]    = _extract_evidence_fields(event_entry)
        event_entry["asset_scope"] = _extract_asset_scope(basic_info, data)
        return event_entry

    except Exception:
        return None


# ==================== Evidence Extraction ====================

def _extract_evidence_fields(event_entry):
    data = event_entry["data"]
    info = event_entry["basic_info"]
    eid  = event_entry["event_id"]

    raw_ts = info.get("time_created")
    if raw_ts:
        raw_ts = raw_ts.replace("T", " ").rstrip("Z").split("+")[0].strip()
    evidence = {
        "timestamp": raw_ts,
        "computer":  info.get("computer"),
    }

    if eid in _GROUP_ADD_EIDS:
        evidence["added_user"] = _resolve_member(data)
        evidence["added_by"]   = data.get("SubjectUserName")
    elif eid in _GROUP_REMOVE_EIDS:
        evidence["removed_user"] = _resolve_member(data)
        evidence["removed_by"]   = data.get("SubjectUserName")
    elif eid == "4726":
        evidence["deleted_user"] = data.get("TargetUserName")
        evidence["deleted_by"]   = data.get("SubjectUserName")
    else:
        evidence["user"] = (
            data.get("User") or
            data.get("TargetUserName") or
            data.get("SubjectUserName")
        )

    if eid not in _CREDENTIAL_EIDS:
        evidence["process"] = (
            data.get("Image") or
            data.get("ProcessName") or
            data.get("NewProcessName")
        )

    evidence["parent_process"] = data.get("ParentImage") or data.get("ParentProcessName")
    evidence["source_image"]   = data.get("SourceImage")
    evidence["target_image"]   = data.get("TargetImage")
    evidence["command_line"]   = data.get("CommandLine")

    evidence["src_ip"]    = data.get("SourceIp") or data.get("IpAddress")
    evidence["dest_ip"]   = data.get("DestinationIp")
    evidence["dest_port"] = data.get("DestinationPort")

    evidence["pipe_name"] = data.get("PipeName")

    if event_entry["type"] == "Security":
        evidence["file_path"]       = data.get("TargetFilename")
        evidence["object_name"]     = data.get("ObjectName")
        evidence["share_name"]      = data.get("ShareName")
        evidence["relative_target"] = data.get("RelativeTargetName")
    else:
        evidence["file_path"] = data.get("TargetFilename") or data.get("ObjectName")

    evidence["reg_event_type"] = data.get("EventType")
    evidence["registry_key"]   = data.get("TargetObject")

    raw_logon = data.get("LogonType")
    if raw_logon:
        evidence["logon_type"] = _LOGON_TYPE_MAP.get(str(raw_logon), f"Type {raw_logon}")

    evidence["task_name"]    = data.get("TaskName")
    evidence["dns_query"]    = data.get("QueryName")
    evidence["image_loaded"] = data.get("ImageLoaded")

    signed = data.get("Signed")
    if signed and str(signed).lower() != "true":
        evidence["dll_signed"] = f"Signed: {signed} | Status: {data.get('SignatureStatus', 'Unknown')}"

    evidence["granted_access"]  = data.get("GrantedAccess")
    evidence["service_name"]    = data.get("ServiceName")
    evidence["service_path"]    = data.get("ImagePath")
    evidence["service_account"] = data.get("AccountName")

    if event_entry["type"] == "Defender":
        evidence["threat_name"]      = data.get("ThreatName")
        evidence["threat_severity"]  = data.get("SeverityName")
        evidence["action_taken"]     = data.get("ActionName")
        evidence["threat_file_path"] = data.get("Path")

        feature = data.get("Feature Name")
        config  = data.get("Configuration")
        if feature and config is not None:
            state = "Disabled" if str(config).strip() == "1" else "Enabled"
            evidence["feature_change"] = f"{feature} -> {state}"

        evidence["config_old_value"] = _parse_reg_val(data.get("Old Value"))
        evidence["config_new_value"] = _parse_reg_val(data.get("New Value"))

    return {k: v for k, v in evidence.items() if v not in (None, "", "-")}


# ==================== Parsing ====================

def parse_evtx(file_path):
    """
    Parse a single EVTX file using the Rust evtx library.
    records_json() yields dicts decoded entirely in Rust — no XML parsing in Python.
    """
    results = []
    try:
        parser = evtx_lib.PyEvtxParser(file_path)
        for record in parser.records_json():
            try:
                entry = _record_to_entry(json.loads(record["data"]))
                if entry is not None:
                    results.append(entry)
            except Exception:
                continue
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
    return results


def parse_evtx_parallel(file_paths, max_workers=None):
    """
    Parse multiple EVTX files concurrently in separate processes.
    Falls back to sequential for a single file.
    """
    if len(file_paths) == 1:
        return parse_evtx(file_paths[0])

    all_entries = []
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(parse_evtx, fp): fp for fp in file_paths}
        for future in as_completed(futures):
            try:
                all_entries.extend(future.result())
            except Exception as e:
                print(f"Worker failed for {futures[future]}: {e}", file=sys.stderr)
    return all_entries


# ==================== Analysis ====================

def analyze_events(events):
    """Bucket pre-parsed event_entry dicts by type and return summary counts."""
    buckets = {
        "Sysmon":      [],
        "System":      [],
        "Security":    [],
        "Application": [],
        "Defender":    [],
        "Windows":     [],
    }
    event_ids    = []
    os_version   = None
    os_build     = None
    computer_name = None

    for entry in events:
        eid = entry["event_id"]
        event_ids.append(eid)
        buckets.get(entry["type"], buckets["Windows"]).append(entry)

        data       = entry.get("data", {})
        basic_info = entry.get("basic_info", {})

        if not computer_name and basic_info.get("computer"):
            computer_name = basic_info["computer"]

        # ---- OS version detection (mirrors old XML parser logic) ----
        if not os_version:
            # Event 6009: System boot — unnamed Data elements: [major.minor, build, type, sp]
            # The Rust parser surfaces these as positional keys "Data_0", "Data_1", … or
            # as a list; we stored them by index during _record_to_entry if unnamed.
            # Try both the indexed-key style and the named fields.
            if eid == "6009":
                major_minor = data.get("Data_0") or data.get("0")
                build       = data.get("Data_1") or data.get("1")
                if major_minor and build:
                    full = f"{major_minor.rstrip('.')}.{build.strip()}"
                    os_version = map_build_to_windows_version(full)
                    os_build   = full

            # Fallback named fields present in some events
            if not os_version:
                if data.get("OSVersion"):
                    os_build   = data["OSVersion"]
                    os_version = map_build_to_windows_version(os_build)
                elif data.get("ProductName"):
                    os_version = data["ProductName"]
                elif data.get("MajorVersion") and data.get("MinorVersion"):
                    major = data["MajorVersion"]
                    minor = data["MinorVersion"]
                    build = data.get("BuildVersion", "0")
                    os_build   = f"{major}.{minor}.{build}"
                    os_version = map_build_to_windows_version(os_build)

    if not os_version and buckets["System"]:
        os_version = "Windows (version not in System logs)"

    return {
        "event_ids":           event_ids,
        "counts":              Counter(event_ids),
        "sysmon_events":       buckets["Sysmon"],
        "system_events":       buckets["System"],
        "security_events":     buckets["Security"],
        "application_events":  buckets["Application"],
        "defender_events":     buckets["Defender"],
        "windows_events":      buckets["Windows"],
        "total_events":        len(events),
        "total_sysmon":        len(buckets["Sysmon"]),
        "total_system":        len(buckets["System"]),
        "total_security":      len(buckets["Security"]),
        "total_application":   len(buckets["Application"]),
        "total_defender":      len(buckets["Defender"]),
        "total_other_windows": len(buckets["Windows"]),
        "os_version":          os_version,
        "os_build":            os_build,
        "computer_name":       computer_name,
    }


# ==================== Testing ====================

def main():
    if len(sys.argv) < 2:
        print("Usage: python parser.py <evtx_file1> [<evtx_file2> ...]")
        sys.exit(1)

    file_paths = sys.argv[1:]
    all_events = parse_evtx_parallel(file_paths)
    results    = analyze_events(all_events)

    print(f"Parsed {results['total_events']} total events from {len(file_paths)} file(s)")
    print(f"  Computer             : {results['computer_name'] or 'unknown'}")
    print(f"  OS Version           : {results['os_version'] or 'unknown'}")
    print(f"  OS Build             : {results['os_build'] or 'unknown'}")
    print(f"  - Sysmon Events          : {results['total_sysmon']}")
    print(f"  - System Events          : {results['total_system']}")
    print(f"  - Security Events        : {results['total_security']}")
    print(f"  - Application Events     : {results['total_application']}")
    print(f"  - Windows Defender Events: {results['total_defender']}")
    print(f"  - Other Windows          : {results['total_other_windows']}")

    print("\n=== Top 15 Event ID Counts ===")
    for eid, count in results["counts"].most_common(15):
        print(f"EventID {eid}: {count}")

    print("\n=== Evidence Preview (first 5 events) ===")
    preview = results["sysmon_events"] + results["security_events"] + results["system_events"]
    for event in preview[:5]:
        print("\n--- Evidence ---")
        for k, v in event["evidence"].items():
            print(f"  {k}: {v}")
        print("--- Asset/Scope ---")
        asset_scope = event.get("asset_scope", {})
        for k, v in asset_scope.get("asset", {}).items():
            print(f"  asset.{k}: {v}")
        for k, v in asset_scope.get("scope", {}).items():
            print(f"  scope.{k}: {v}")


if __name__ == "__main__":
    main()
