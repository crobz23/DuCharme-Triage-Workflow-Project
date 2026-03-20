# parser.py - Windows, Sysmon, System.evtx, and Windows Defender support
from Evtx.Evtx import Evtx
from collections import Counter
import xml.etree.ElementTree as ET
import sys

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
    except PermissionError:
        # Re-raise permission errors so GUI can handle them
        raise
    except Exception as e:
        # Silently fail for other errors - GUI will track them
        pass
    return events

def classify_event(root):
    """Classify event type based on Channel and Provider (now supports System, Security, Application, Defender, etc.)."""
    # Get Channel
    channel_elem = root.find(".//ns:Channel", NS)
    channel = channel_elem.text.strip() if channel_elem is not None and channel_elem.text else ""
    
    provider = root.find(".//ns:Provider", NS)
    provider_name = provider.attrib.get("Name", "") if provider is not None else ""
    
    if "Sysmon" in provider_name or channel.startswith("Microsoft-Windows-Sysmon"):
        return "Sysmon", channel
    elif "Defender" in provider_name or "Defender" in channel:
        return "Defender", channel
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
    Works for Sysmon, System.evtx, Security, Application, Windows Defender, and most other Windows events.
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
    try:
        system = root.find(".//ns:System", NS)
        if system is None:
            # Try without namespace
            system = root.find(".//System")
        if system is None:
            return {}
        
        time_elem = system.find(".//ns:TimeCreated", NS)
        if time_elem is None:
            time_elem = system.find(".//TimeCreated")
        
        computer_elem = system.find(".//ns:Computer", NS)
        if computer_elem is None:
            computer_elem = system.find(".//Computer")
        computer = computer_elem.text.strip() if computer_elem is not None and computer_elem.text else ""
        
        provider_elem = system.find(".//ns:Provider", NS)
        if provider_elem is None:
            provider_elem = system.find(".//Provider")
        provider_name = provider_elem.attrib.get("Name") if provider_elem is not None else None
        
        channel_elem = system.find(".//ns:Channel", NS)
        if channel_elem is None:
            channel_elem = system.find(".//Channel")
        channel = channel_elem.text.strip() if channel_elem is not None and channel_elem.text else ""
        
        record_elem = system.find(".//ns:EventRecordID", NS)
        if record_elem is None:
            record_elem = system.find(".//EventRecordID")
        record_id = record_elem.text.strip() if record_elem is not None and record_elem.text else ""
        
        level_elem = system.find(".//ns:Level", NS)
        if level_elem is None:
            level_elem = system.find(".//Level")
        level = level_elem.text.strip() if level_elem is not None and level_elem.text else ""
        
        return {
            "provider": provider_name,
            "channel": channel,
            "computer": computer,
            "time_created": time_elem.get("SystemTime") if time_elem is not None else None,
            "record_id": record_id,
            "level": level,
        }
    except Exception:
        # If any error occurs, return empty dict to avoid crashing
        return {
            "provider": None,
            "channel": "",
            "computer": "",
            "time_created": None,
            "record_id": "",
            "level": "",
        }

def map_build_to_windows_version(build_string):
    """Map Windows build numbers to human-readable versions."""
    if not build_string:
        return None
    try:
        parts = build_string.split('.')
        if len(parts) < 2:
            return f"Windows (Build {build_string})"
        major = parts[0]
        minor = parts[1]
        build = parts[2] if len(parts) > 2 else "0"
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


def analyze_events(events):
    """
    Analyze events with full support for System.evtx and Windows Defender logs.
    Returns categorized events + statistics, including os_version and computer_name.
    """
    import re
    event_ids = []
    sysmon_events = []
    system_events = []
    security_events = []
    application_events = []
    defender_events = []
    other_windows_events = []

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

        # Track computer name
        if not computer_name and basic_info.get('computer'):
            computer_name = basic_info['computer']

        # === OS DETECTION ===
        # EID 6009: Data[0]=major.minor, Data[1]=build
        if eid == '6009' and not os_version:
            try:
                data_elements = root.findall(".//ns:EventData/ns:Data", NS)
                if not data_elements:
                    data_elements = root.findall(".//EventData/Data")
                if len(data_elements) >= 2:
                    major_minor = data_elements[0].text.strip() if data_elements[0].text else None
                    build = data_elements[1].text.strip() if data_elements[1].text else None
                    if major_minor and build:
                        major_minor = major_minor.rstrip('.').strip()
                        build = build.strip()
                        full_build = f"{major_minor}.{build}"
                        os_version = map_build_to_windows_version(full_build)
                        os_build = full_build
            except Exception:
                pass

        # EID 6005/6006/1074: try regex on full XML text
        if eid in ['6005', '6006', '1074'] and not os_version:
            try:
                event_xml = ET.tostring(root, encoding='unicode')
                vm = re.search(r'Microsoft Windows.*?(\d+\.\d+\.\d+)', event_xml, re.IGNORECASE)
                if not vm:
                    vm = re.search(r'(?:Version|Build).*?(\d+\.\d+\.\d+)', event_xml, re.IGNORECASE)
                if vm:
                    os_version = map_build_to_windows_version(vm.group(1))
                    os_build = vm.group(1)
            except Exception:
                pass

        # Fallback: EventData fields
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
            'basic_info': basic_info,
            'data': event_data,
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
        elif event_type == "Defender":
            defender_events.append(event_entry)
        else:
            other_windows_events.append(event_entry)
    
    counts = Counter(event_ids)

    if not os_version and system_events:
        os_version = "Windows (version not in System logs)"

    return {
        'event_ids': event_ids,
        'counts': counts,
        'sysmon_events': sysmon_events,
        'system_events': system_events,
        'security_events': security_events,
        'application_events': application_events,
        'defender_events': defender_events,
        'windows_events': other_windows_events,
        'total_events': len(events),
        'total_sysmon': len(sysmon_events),
        'total_system': len(system_events),
        'total_security': len(security_events),
        'total_application': len(application_events),
        'total_defender': len(defender_events),
        'total_other_windows': len(other_windows_events),
        'os_version': os_version,
        'os_build': os_build,
        'computer_name': computer_name,
    }

# ==================== Testing ====================
def main():
    if len(sys.argv) < 2:
        print("Usage: python parser.py <evtx_file1> [<evtx_file2> ...]")
        sys.exit(1)
    
    file_paths = sys.argv[1:]
    all_events = []
    
    for file_path in file_paths:
        events = parse_evtx(file_path)
        all_events.extend(events)
    
    results = analyze_events(all_events)
    
    print(f"Parsed {results['total_events']} total events from {', '.join(file_paths)}")
    print(f"  - Sysmon Events         : {results['total_sysmon']}")
    print(f"  - System Events         : {results['total_system']}")
    print(f"  - Security Events       : {results['total_security']}")
    print(f"  - Application Events    : {results['total_application']}")
    print(f"  - Windows Defender Events: {results['total_defender']}")
    print(f"  - Other Windows         : {results['total_other_windows']}")
    
    print("\n=== Top 15 Event ID Counts ===")
    for eid, count in results['counts'].most_common(15):
        print(f"EventID {eid}: {count}")
    
    # Preview System events (merged from all files)
    if results['system_events']:
        print("\n=== System.evtx Preview (first 5) ===")
        for event in results['system_events'][:5]:
            info = event['basic_info']
            print(f"\nEventID {event['event_id']} | {info['time_created'][:19] if info['time_created'] else ''} | {info['computer']}")
            for k, v in list(event['data'].items())[:8]:   # limit output
                print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
