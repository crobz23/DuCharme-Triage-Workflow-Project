# parser.py
from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from collections import Counter

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
    """Extract Event IDs from the XML strings."""
    event_ids = []
    for xml_data in events:
        try:
            # Look for <EventID>number</EventID> in XML
            start = xml_data.find("<EventID>") + len("<EventID>")
            end = xml_data.find("</EventID>")
            if start > 0 and end > 0:
                event_ids.append(xml_data[start:end])
        except Exception as e:
            print(f"Error extracting Event ID: {e}")
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