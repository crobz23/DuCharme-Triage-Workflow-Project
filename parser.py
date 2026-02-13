# parser.py - Windows, Sysmon, and System.evtx support
from Evtx.Evtx import Evtx
from collections import Counter
import xml.etree.ElementTree as ET
import re

SYS_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"ns": SYS_EVENT_NS}


def parse_evtx(file_path):
    """Parse a Windows EVTX file and return list of XML roots."""
    events = []
    try:
        with Evtx(file_path) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                    events.append(root)
                except ET.ParseError:
                    continue
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return events


def classify_event(root):
    """Classify event type based on Channel and Provider (now supports System, Security, Application, etc.)."""
    # Get Channel
    channel_elem = root.find(".//ns:Channel", NS)
    channel = channel_elem.text.strip() if channel_elem is not None and channel_elem.text else ""

    provider = root.find(".//ns:Provider", NS)
    provider_name = provider.attrib.get("Name", "") if provider is not None else ""

    if "Sysmon" in provider_name or channel.startswith("Microsoft-Windows-Sysmon"):
        return "Sysmon", channel
    elif channel == "System":
        return "System", channel
    elif channel == "Security":
        return "Security", channel
    elif channel == "Application":
        return "Application", channel
    else:
        return "Windows", channel


def extract_event_id(root):
    """Extract EventID from XML root."""
    event_id = root.find(".//ns:EventID", NS)
    if event_id is None:
        event_id = root.find(".//EventID")
    return event_id.text.strip() if event_id is not None else None


def extract_event_data(root):
    """
    Extract EventData (or UserData) fields into a dictionary.
    Works for Sysmon, System.evtx, Security, Application, and most other Windows events.
    """
    data = {}

    # Standard EventData
    for elem in root.findall(".//ns:EventData/ns:Data", NS):
        name = elem.attrib.get("Name")
        value = elem.text.strip() if elem.text else None
        if name:
            data[name] = value

    # Fallback for events that use UserData instead
    if not data:
        for elem in root.findall(".//ns:UserData/*", NS):
            # Some UserData events have direct child elements
            tag = elem.tag.split('}')[-1]  # remove namespace
            if elem.text:
                data[tag] = elem.text.strip()

    return data


def extract_basic_info(root):
    """Extract commonly useful fields from the <System> section."""
    system = root.find(".//ns:System", NS)
    if system is None:
        return {}

    time_elem = system.find(".//ns:TimeCreated", NS)
    computer_elem = system.find(".//ns:Computer", NS)
    computer = computer_elem.text.strip() if computer_elem is not None and computer_elem.text else ""
    
    provider_elem = system.find(".//ns:Provider", NS)
    provider_name = provider_elem.attrib.get("Name") if provider_elem is not None else None
    
    channel_elem = system.find(".//ns:Channel", NS)
    channel = channel_elem.text.strip() if channel_elem is not None and channel_elem.text else ""
    
    record_elem = system.find(".//ns:EventRecordID", NS)
    record_id = record_elem.text.strip() if record_elem is not None and record_elem.text else ""
    
    level_elem = system.find(".//ns:Level", NS)
    level = level_elem.text.strip() if level_elem is not None and level_elem.text else ""

    return {
        "provider": provider_name,
        "channel": channel,
        "computer": computer,
        "time_created": time_elem.get("SystemTime") if time_elem is not None else None,
        "record_id": record_id,
        "level": level,
    }


def is_system_account(username):
    """
    Determine if a username is a system/service account rather than a human user.
    Returns True for system accounts, False for likely human users.
    """
    if not username or username in ['-', '', 'None']:
        return True
    
    # Filter out email addresses (not usernames)
    if '@' in username:
        return True
    
    # Known system accounts
    system_accounts = {
        'SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE',
        'ANONYMOUS LOGON', 'NT AUTHORITY\\SYSTEM',
        'DWM-1', 'DWM-2', 'DWM-3', 'DWM-4',
        'UMFD-0', 'UMFD-1', 'UMFD-2', 'UMFD-3',
        'Guest', 'DefaultAccount', 'WDAGUtilityAccount'
    }
    
    # Windows built-in group names (not user accounts)
    windows_groups = {
        'Users', 'Administrators', 'Backup Operators',
        'Power Users', 'Remote Desktop Users', 'Guests',
        'Network Configuration Operators', 'Performance Monitor Users',
        'Performance Log Users', 'Distributed COM Users',
        'IIS_IUSRS', 'Cryptographic Operators', 'Event Log Readers',
        'Certificate Service DCOM Access', 'RDS Remote Access Servers',
        'RDS Endpoint Servers', 'RDS Management Servers',
        'Hyper-V Administrators', 'Access Control Assistance Operators',
        'Remote Management Users', 'System Managed Accounts Group'
    }
    
    if username in system_accounts or username in windows_groups:
        return True
    
    # Pattern-based detection
    username_lower = username.lower()
    
    # System/service patterns
    system_patterns = [
        'system', 'service', 'dwm-', 'umfd-',
        'font driver host', 'window manager',
        '$', '_$_'  # Computer accounts and special accounts
    ]
    
    for pattern in system_patterns:
        if pattern in username_lower:
            return True
    
    # Test account patterns
    test_patterns = ['test', 'dummy', 'doesnotexist', 'example']
    for pattern in test_patterns:
        if pattern in username_lower:
            return True
    
    return False


def is_privileged_account(username):
    """
    Determine if a username represents a privileged/administrative account.
    Returns True for admin accounts, False otherwise.
    """
    if not username:
        return False
    
    username_lower = username.lower()
    
    # Direct admin account names
    if username_lower in ['administrator', 'admin', 'root']:
        return True
    
    # Group patterns indicating elevated privileges
    privileged_patterns = [
        'admin', 'administrator', 'root', 'backup operator',
        'domain admin', 'enterprise admin', 'schema admin'
    ]
    
    for pattern in privileged_patterns:
        if pattern in username_lower:
            return True
    
    return False

def extract_asset_and_scope(root, basic_info, event_data):
    """
    Extract Asset and Scope information from the event.
    
    IMPROVED for incident triage:
    - Better user categorization (human vs system, privileged vs regular)
    - Focus on incident-relevant information
    - Clear separation of concerns for non-IT readers

    Asset:
        - Primary: Computer name
        - Secondary: IP address fields if available

    Scope:
        - Categorized users (privileged vs regular human users)
        - Domain, LogonType, ProcessName, etc.
        - Depends on event type and available fields
    """

    asset = {}
    scope = {}

    # ==================== ASSET EXTRACTION ====================

    computer = basic_info.get("computer")
    if computer:
        asset["hostname"] = computer

    ip_fields = [
        "IpAddress", "SourceIp", "DestinationIp",
        "SourceAddress", "DestAddress"
    ]

    for field in ip_fields:
        if field in event_data and event_data[field]:
            ip_value = event_data[field]
            # Skip placeholder values
            if ip_value not in ['-', '0.0.0.0', '127.0.0.1', '::1']:
                asset.setdefault("ip_addresses", []).append(ip_value)

    # ==================== SCOPE EXTRACTION ====================
    
    # Collect all potential users from various fields
    potential_users = []
    
    user_fields = [
        "TargetUserName", "SubjectUserName", "User",
        "AccountName", "UserName"
    ]
    
    for field in user_fields:
        if field in event_data and event_data[field]:
            username = event_data[field]
            if not is_system_account(username):
                potential_users.append(username)
    
    # Categorize users into privileged and regular
    if potential_users:
        privileged = []
        regular = []
        
        for user in potential_users:
            if is_privileged_account(user):
                privileged.append(user)
            else:
                regular.append(user)
        
        if privileged:
            scope["privileged_users"] = privileged
        if regular:
            scope["regular_users"] = regular
    
    # Extract domain information (cleaned)
    domain_fields = ["TargetDomainName", "SubjectDomainName", "Domain"]
    for field in domain_fields:
        if field in event_data and event_data[field]:
            domain = event_data[field]
            # Skip junk domains
            if domain not in ['-', '', 'NT AUTHORITY', 'Window Manager', 
                            'Font Driver Host', 'Builtin', 'MicrosoftAccount']:
                if domain != basic_info.get("computer"):  # Avoid hostname duplication
                    scope.setdefault("domains", []).append(domain)
    
    # LogonType (keep for access method categorization)
    if "LogonType" in event_data:
        scope["LogonType"] = event_data["LogonType"]
    
    # Process information (for threat analysis)
    if "ProcessName" in event_data:
        scope["ProcessName"] = event_data["ProcessName"]
    if "Image" in event_data:
        scope["Image"] = event_data["Image"]
    if "CommandLine" in event_data:
        scope["CommandLine"] = event_data["CommandLine"]
    
    # Network/target information
    if "TargetServerName" in event_data:
        scope["TargetServerName"] = event_data["TargetServerName"]
    if "WorkstationName" in event_data:
        scope["WorkstationName"] = event_data["WorkstationName"]

    return {
        "asset": asset,
        "scope": scope
    }


def analyze_events(events):
    """
    Analyze events with full support for System.evtx.
    Returns categorized events + statistics + OS information.
    """
    event_ids = []
    sysmon_events = []
    system_events = []
    security_events = []
    application_events = []
    other_windows_events = []
    
    # Track OS version information from multiple sources
    os_version = None
    os_build = None
    computer_name = None

    for root in events:
        eid = extract_event_id(root)
        if not eid:
            continue

        event_ids.append(eid)
        event_type, channel = classify_event(root)

        basic_info = extract_basic_info(root)
        event_data = extract_event_data(root)
        asset_scope = extract_asset_and_scope(root, basic_info, event_data)
        
        # Get computer name (for fallback)
        if not computer_name and basic_info.get('computer'):
            computer_name = basic_info['computer']
        
        # Try multiple Event IDs for OS detection
        # Event 6009: System boot with version info (special format)
        # Event 6005/6006: Event Log service started/stopped (often has version)
        # Event 1074: System has been shut down (may have OS info)
        if eid == '6009' and not os_version:
            try:
                # Event 6009 has a specific data format in EventData/Data fields:
                # Data[0]: Major.Minor (e.g., "10.00.")
                # Data[1]: Build number (e.g., "26200")
                # Data[2]: System type (e.g., "Multiprocessor Free")
                # Data[3]: Service pack (e.g., "0")
                
                # Try finding Data elements (they don't have Name attributes in Event 6009)
                data_elements = root.findall(".//ns:EventData/ns:Data", NS)
                
                # Also try without namespace as fallback
                if not data_elements:
                    data_elements = root.findall(".//EventData/Data")
                
                if len(data_elements) >= 2:
                    # Get text from first two Data elements
                    major_minor_elem = data_elements[0]
                    build_elem = data_elements[1]
                    
                    major_minor = major_minor_elem.text.strip() if major_minor_elem.text else None
                    build = build_elem.text.strip() if build_elem.text else None
                    
                    if major_minor and build:
                        # Clean up major.minor (remove trailing dots and whitespace)
                        major_minor = major_minor.rstrip('.').strip()
                        build = build.strip()
                        
                        # Combine into full version string
                        full_build = f"{major_minor}.{build}"
                        os_version = map_build_to_windows_version(full_build)
                        os_build = full_build
            except Exception as e:
                pass
        
        # Fallback: Try regex patterns in the full XML
        if eid in ['6005', '6006', '1074'] and not os_version:
            try:
                event_xml = ET.tostring(root, encoding='unicode')
                # Look for version patterns
                # Pattern 1: Microsoft Windows [Version 10.0.19045]
                version_match = re.search(r'Microsoft Windows.*?(\d+\.\d+\.\d+)', event_xml, re.IGNORECASE)
                if version_match:
                    build = version_match.group(1)
                    os_version = map_build_to_windows_version(build)
                    os_build = build
                else:
                    # Pattern 2: Just version number like "10.0.19045"
                    version_match = re.search(r'(?:Version|Build).*?(\d+\.\d+\.\d+)', event_xml, re.IGNORECASE)
                    if version_match:
                        build = version_match.group(1)
                        os_version = map_build_to_windows_version(build)
                        os_build = build
            except:
                pass
        
        # Try EventData fields for OS info
        if not os_version:
            if event_data.get('OSVersion'):
                os_build = event_data['OSVersion']
                os_version = map_build_to_windows_version(os_build)
            elif event_data.get('ProductName'):
                os_version = event_data['ProductName']
            elif event_data.get('MajorVersion') and event_data.get('MinorVersion'):
                major = event_data.get('MajorVersion')
                minor = event_data.get('MinorVersion')
                build = event_data.get('BuildVersion', '0')
                os_build = f"{major}.{minor}.{build}"
                os_version = map_build_to_windows_version(os_build)

        event_entry = {
            'event_id': eid,
            'type': event_type,
            'channel': channel,
            'basic_info': extract_basic_info(root),
            'data': extract_event_data(root),
            'asset_scope': asset_scope,
            'root': root
        }

        if event_type == "Sysmon":
            sysmon_events.append(event_entry)
        elif event_type == "System":
            system_events.append(event_entry)
        elif event_type == "Security":
            security_events.append(event_entry)
        elif event_type == "Application":
            application_events.append(event_entry)
        else:
            other_windows_events.append(event_entry)

    counts = Counter(event_ids)
    
    # If still no OS version, provide a reasonable default based on common event patterns
    if not os_version and system_events:
        # Default to generic "Windows (version not in logs)"
        os_version = "Windows (version not in System logs)"

    return {
        'event_ids': event_ids,
        'counts': counts,
        'sysmon_events': sysmon_events,
        'system_events': system_events,
        'security_events': security_events,
        'application_events': application_events,
        'windows_events': other_windows_events,   # legacy name for non-special Windows events
        'total_events': len(events),
        'total_sysmon': len(sysmon_events),
        'total_system': len(system_events),
        'total_security': len(security_events),
        'total_application': len(application_events),
        'total_other_windows': len(other_windows_events),
        'os_version': os_version,  # Add OS version to results
        'os_build': os_build,  # Add build number if available
        'computer_name': computer_name  # Add computer name
    }


def map_build_to_windows_version(build_string):
    """
    Map Windows build numbers to human-readable versions.
    
    Args:
        build_string: Version string like "10.0.19045" or "6.1.7601"
    
    Returns:
        Human-readable Windows version
    """
    if not build_string:
        return None
    
    try:
        # Extract major.minor from build string
        parts = build_string.split('.')
        if len(parts) < 2:
            return f"Windows (Build {build_string})"
        
        major = parts[0]
        minor = parts[1]
        build = parts[2] if len(parts) > 2 else "0"
        
        # Windows version mapping
        if major == '10' and minor == '0':
            build_num = int(build)
            if build_num >= 22000:
                return f"Windows 11 (Build {build})"
            else:
                return f"Windows 10 (Build {build})"
        elif major == '6' and minor == '3':
            return f"Windows 8.1 / Server 2012 R2 (Build {build})"
        elif major == '6' and minor == '2':
            return f"Windows 8 / Server 2012 (Build {build})"
        elif major == '6' and minor == '1':
            return f"Windows 7 / Server 2008 R2 (Build {build})"
        elif major == '6' and minor == '0':
            return f"Windows Vista / Server 2008 (Build {build})"
        elif major == '5' and minor == '2':
            return f"Windows Server 2003 (Build {build})"
        elif major == '5' and minor == '1':
            return f"Windows XP (Build {build})"
        else:
            return f"Windows {major}.{minor} (Build {build})"
    except:
        return f"Windows (Build {build_string})"


# ==================== Testing ====================
def main():
    # Change this to the proper System.evtx path when testing
    file_path = "System.evtx"

    events = parse_evtx(file_path)
    results = analyze_events(events)

    print(f"Parsed {results['total_events']} total events from {file_path}")
    print(f"  - Sysmon Events     : {results['total_sysmon']}")
    print(f"  - System Events     : {results['total_system']}")
    print(f"  - Security Events   : {results['total_security']}")
    print(f"  - Application Events: {results['total_application']}")
    print(f"  - Other Windows     : {results['total_other_windows']}")

    print("\n=== Top 15 Event ID Counts ===")
    for eid, count in results['counts'].most_common(15):
        print(f"EventID {eid}: {count}")

    # Preview System events
    if results['system_events']:
        print("\n=== System.evtx Preview (first 5) ===")
        for event in results['system_events'][:5]:
            info = event['basic_info']
            print(f"\nEventID {event['event_id']} | {info['time_created'][:19] if info['time_created'] else ''} | {info['computer']}")
            for k, v in list(event['data'].items())[:8]:   # limit output
                print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
