# parser.py
from Evtx.Evtx import Evtx
from collections import Counter
import xml.etree.ElementTree as ET

def parse_evtx(file_path):
    """Parse a Windows EVTX file and return a list of XML event strings."""
    events = []
    try:
        with Evtx(file_path) as log:
            for record in log.records():
                xml_data = record.xml()
                events.append(xml_data)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
    return events


def extract_event_ids(events):
    """Extract Event IDs from the XML strings using proper XML parsing."""
    event_ids = []
    for xml_data in events:
        try:
            # Parse XML properly
            root = ET.fromstring(xml_data)
            
            # Find EventID in the System section
            # Handle namespaces
            namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Try with namespace first
            event_id_elem = root.find('.//ns:EventID', namespaces)
            
            # If not found, try without namespace
            if event_id_elem is None:
                event_id_elem = root.find('.//EventID')
            
            if event_id_elem is not None and event_id_elem.text:
                event_ids.append(event_id_elem.text.strip())
                
        except Exception as e:
            # Fallback to string parsing if XML parsing fails
            try:
                start = xml_data.find("<EventID>") + len("<EventID>")
                end = xml_data.find("</EventID>")
                if start > 0 and end > 0:
                    event_ids.append(xml_data[start:end].strip())
            except Exception as e2:
                print(f"Error extracting Event ID: {e2}")
                
    return event_ids


def main():
    file_path = "Security.evtx"  # Adjust path if needed
    events = parse_evtx(file_path)

    # Print first 10 events (preview)
    print("=== First 10 Events ===")
    for i, xml in enumerate(events[:10], 1):
        print(f"\n--- Event {i} ---\n{xml}")

    # Verify XML readability
    print(f"\nParsed {len(events)} events total.")

    # Extract Event IDs
    event_ids = extract_event_ids(events)
    print(f"\nExtracted {len(event_ids)} Event IDs.")

    # Count occurrences
    counts = Counter(event_ids)
    print("\n=== Event ID Counts ===")
    for eid, count in counts.most_common():
        print(f"EventID {eid}: {count}")


if __name__ == "__main__":
    main()
