# parser.py - Windows and Sysmon support
from Evtx.Evtx import Evtx
from collections import Counter
import xml.etree.ElementTree as ET

SYS_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"ns": SYS_EVENT_NS}


def parse_evtx(file_path):
    """Parse a Windows EVTX file (Windows or Sysmon) and return XML roots."""
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
    """Determine if event is Sysmon or standard Windows event."""
    provider = root.find(".//ns:Provider", NS)
    if provider is not None:
        name = provider.attrib.get("Name", "")
        if "Sysmon" in name:
            return "Sysmon"
    return "Windows"


def extract_event_id(root):
    """Extract EventID from XML root (works for both Windows and Sysmon)."""
    event_id = root.find(".//ns:EventID", NS)
    if event_id is None:
        event_id = root.find(".//EventID")
    return event_id.text.strip() if event_id is not None else None


def extract_event_ids(events):
    """Extract Event IDs from list of XML roots - LEGACY FUNCTION for backwards compatibility."""
    event_ids = []
    for root in events:
        eid = extract_event_id(root)
        if eid:
            event_ids.append(eid)
    return event_ids


def extract_sysmon_event_data(root):
    """Extract Sysmon EventData fields into a dictionary."""
    data = {}
    for elem in root.findall(".//ns:EventData/ns:Data", NS):
        name = elem.attrib.get("Name")
        value = elem.text
        if name:
            data[name] = value
    return data


def analyze_events(events):
    """
    Analyze a list of XML event roots.
    Returns dict with event_ids, counts, sysmon_events, windows_events.
    """
    event_ids = []
    sysmon_events = []
    windows_events = []
    
    for root in events:
        eid = extract_event_id(root)
        if not eid:
            continue
            
        event_ids.append(eid)
        event_type = classify_event(root)
        
        if event_type == "Sysmon":
            sysmon_data = extract_sysmon_event_data(root)
            sysmon_events.append({
                'event_id': eid,
                'data': sysmon_data,
                'root': root
            })
        else:
            windows_events.append({
                'event_id': eid,
                'root': root
            })
    
    counts = Counter(event_ids)
    
    return {
        'event_ids': event_ids,
        'counts': counts,
        'sysmon_events': sysmon_events,
        'windows_events': windows_events,
        'total_events': len(events),
        'total_sysmon': len(sysmon_events),
        'total_windows': len(windows_events)
    }


# Keep old main() for testing parser independently
def main():
    file_path = "Microsoft-Windows-Sysmon-Operational.evtx"
    events = parse_evtx(file_path)
    
    results = analyze_events(events)
    
    print(f"Parsed {results['total_events']} total events")
    print(f"  - Windows Events: {results['total_windows']}")
    print(f"  - Sysmon Events: {results['total_sysmon']}")
    
    print("\n=== Event ID Counts ===")
    for eid, count in results['counts'].most_common():
        print(f"EventID {eid}: {count}")
    
    print("\n=== Sysmon Event Preview ===")
    for event in results['sysmon_events'][:5]:
        print(f"\nSysmon EventID {event['event_id']}")
        for k, v in event['data'].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
