# DuCharme Triage Assistant

**Version 6.0** | Trine University Senior Capstone Project

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

### Version 6.0 (Current)

**Threat Analysis:**
- Threats are now matched using an `EventType:EventID` key (e.g.,`Sysmon:1` or `Security:1102`) instead of Event ID alone, eliminating false positives caused by overlapping IDs across log channels
- For Sysmon events, the analysis module now inspects the actual event data fields (process names, command lines, image paths) for specific IOC strings defined in the CSV. Security events still match on Event ID alone
- A new `EventType` column has been added to both CSV files to support composite key matching

**report.py:**
- CVSS scores replaced with Impact × Confidence scoring throughout the Indicators & Scoring section
- Confidence boost annotations shown inline (e.g., `2/4 → 3/4 (high event frequency)`)
- Risk level headers are now color-coded: Critical (dark red), High (bright red), Medium (gold), Low (green)
- Each indicator now includes an event ID description pulled from the same lookup table used by the Filter by Event ID popup window
- All section tables wrapped with `KeepTogether` to prevent sections from splitting across pages
- 500-character limit added to incident context fields to prevent PDF generation errors; GUI notifies the user of this limit

**parser.py:**
- Windows Defender log support added as the fourth supported log source alongside Security, System, and Sysmon
- `PermissionError` is now passed to the GUI so it can display the appropriate "run as administrator" message in the results instead of silently failing

**gui.py:**
- Time Window Filtering added — a new "Time Filtering" button opens a dialog with quick presets (Last 24 Hours, Last 7 Days, Last 30 Days) and a fully custom date/time range picker; the dialog remembers previously entered values
- Default Windows Logs button added — automatically loads only the four supported log types from `C:\Windows\System32\winevt\Logs` instead of all 400+ files in that folder
- Event ID and Time filters stack. Each filter preserves the other when applied
- "Clear Filters" button resets both filters simultaneously
- Sysmon Event IDs are now annotated with a `(Sysmon)` label in the results and filter dialog based on which log file the event actually came from, not guessed from the ID number
- Channel-accurate descriptions — For example, Event ID 1 in a Sysmon context shows "A program was started" rather than "A system error occurred"

---

## What This Tool Does

When something suspicious happens on a computer, the system creates event logs. These logs contain thousands of entries that are nearly impossible to read manually.

This tool analyzes those logs for you and tells you:
- Is there malware on the system?
- Is someone trying to break in?
- What happened, when did it happen, and how serious is it?
- Ranks the threats based on severity using an Impact × Confidence matrix
- What you should do next

Instead of spending hours digging through logs, you get a clean PDF report with threat scores and recommendations. Any IT Help Desk can isolate a machine from the network, plug a USB with the tool in, and run it to analyze threats.

---

## How It Works

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│           INPUT: .evtx Log File(s) or Directory             │
│  (Security.evtx, System.evtx, Sysmon, Defender)             │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────┐
              │    PARSER MODULE        │
              │     (parser.py)         │
              │                         │
              │  • Reads each .evtx     │
              │  • Parses XML records   │
              │  • Classifies by type   │
              │    (Sysmon / Security / │
              │     System / Defender)  │
              │  • Extracts timestamps  │
              │  • Gets asset/scope     │
              │  • Merges all files     │
              └────────────┬────────────┘
                           │
          ┌────────────────┴────────────────┐
          │                                 │
          ▼                                 ▼
┌──────────────────────┐        ┌───────────────────────┐
│  ANALYSIS MODULE     │        │  TIMELINE MODULE      │
│   (analysis.py)      │        │   (analysis.py)       │
│                      │        │                       │
│ Loads Detection CSVs │        │  • Sorts by time      │
│ ┌─────────────────┐  │        │  • Groups into        │
│ │ malware_        │  │        │    5-min windows      │
│ │ indicators.csv  │  │        │  • Detects event      │
│ └─────────────────┘  │        │    clustering         │
│ ┌─────────────────┐  │        └──────────┬────────────┘
│ │ breach_         │  │                   │
│ │ indicators.csv  │  │◄──────────────────┘
│ └─────────────────┘  │   (clustering fed back for
│                      │    confidence boosting)
│  • Matches by        │
│    EventType:EventID │
│  • Checks IOC data   │
│    fields            │
│  • Reads Impact &    │
│    BaseConfidence    │
│  • Boosts confidence │
│    by frequency &    │
│    clustering        │
│  • Runs matrix:      │
│    Impact×Confidence │
│  • Determines risk   │
│  • Groups by MITRE   │
│    category          │
└──────────┬───────────┘
           │
           └─────────┬─────────────────────────┐
                     │                         │
                     ▼                         ▼
         ┌────────────────────┐    ┌──────────────────────┐
         │   GUI DISPLAY      │    │   REPORT MODULE      │
         │     (gui.py)       │    │     (report.py)      │
         │                    │    │                      │
         │  • Shows results   │    │  Prompts for Context │
         │  • Matrix risk     │    │  ┌────────────────┐  │
         │    levels          │    │  │ Incident       │  │
         │  • Top threats     │    │  │ Context Dialog │  │
         │  • Filter by       │    │  └────────────────┘  │
         │    Event ID        │    │                      │
         │  • Time filtering  │    │  Generates PDF:      │
         │  • Event Type      │    │  • File info         │
         │    Distinction     │    │  • Asset & Scope     │
         └────────────────────┘    │  • Incident Context  │
                                   │  • Timeline          │
                                   │  • Threat Indicators │
                                   │    with Impact /     │
                                   │    Confidence scores │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │  OUTPUT: PDF Report  │
                                   │  triage_report_*.pdf │
                                   └──────────────────────┘
```

---

## Getting Started

### What You Need

- A Windows computer
- Windows event log files (.evtx format)

### Installation

1. Go to [our GitHub repository](https://github.com/crobz23/DuCharme-Triage-Workflow-Project)
2. Click the "Releases" button on the right panel and select "DuCharme_Triage_Assistant_V6.exe"
3. Save the file to your computer and run the .exe

---

## How to Use

### Basic Workflow

**Step 1: Start the application**

Double-click `DuCharme_Triage_Assistant_V6.exe` to launch the tool. A window will open with the DuCharme Triage Assistant interface.

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
- Event ID breakdown — Sysmon Event IDs are annotated with `(Sysmon)` to distinguish them from Windows System IDs that share the same number
- Threat analysis with Impact × Confidence matrix risk levels
- Which threats had their confidence score boosted due to frequency or clustering

**Step 4: Filter (optional)**

Two filtering options are available and can be used together in any order:

- **Filter by Event ID** — select specific Event IDs to focus on
- **Time Filtering** — narrow results to a specific time window using quick presets (Last 24 Hours, Last 7 Days, Last 30 Days) or a custom date and time range

Both filters stack — applying one does not reset the other. Use the "Clear Filters" button to reset both at once.

**Step 5: Generate Report**

Click "Generate Report (PDF)" to create a professional report. You'll be prompted to:
1. Fill in incident context (who reported it, what they saw, etc.) — each field has a 500-character limit
2. Choose where to save the PDF

The report includes:
- File information
- Timeline of events
- Threat indicators with Impact, Confidence, matrix risk level, and Event ID descriptions
- Risk levels color-coded by severity
- Asset and scope details (what computers, users, IPs were involved)

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
- The same Event ID appears 5 or more times → +1
- The same Event ID appears 10 or more times → +1
- The same Event ID appears 50 or more times → +2
- 20 or more events of the same type occur in a single 5-minute window → +1 (active attack clustering)

Confidence is capped at 4. The reasons for any boost are stored alongside the indicator so the help desk can see exactly why a score was elevated.

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

The tool uses two CSV files to define what it looks for:

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

**CSV Format:**

| Column Name | What It Means | Example Value |
|-------------|---------------|---------------|
| EventType | The log channel the event comes from | Sysmon |
| EventID | The event's identification number | 4625 |
| Description | Brief explanation | "Failed Login Attempt" |
| Threat | What kind of attack this indicates | "Brute Force Attack" |
| Score | CVSS severity reference (0–10 scale) | 7.0 |
| Impact | How damaging if confirmed (1–4 scale) | 2 |
| BaseConfidence | Starting confidence this is malicious (1–4 scale) | 1 |
| Category | MITRE ATT&CK attack category | "Credential Access" |
| Indicators | Specific strings to search for in event data that are Indicators of Compromise | "mimikatz.exe; psexec.exe" |

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
- Impact values
- BaseConfidence values
- Specific score assignments

---

## Troubleshooting

### "No events found" error

**Problem**: The log file couldn't be parsed.

**Solution**:
- Make sure you're loading an actual .evtx file (not a .txt or .csv)
- The file might be corrupted — try a different log file
- You might need administrator privileges to access certain log files

### "Permission Denied" when using Default Windows Logs

**Problem**: The tool cannot read logs directly from `C:\Windows\System32\winevt\Logs` without elevated privileges.

**Solution**:
- Close the tool, right-click the executable, and select "Run as administrator"
- Alternatively, export the logs from Event Viewer (right-click a log → "Save All Events As..." → save as .evtx) and load the exported files using Browse File instead

### Tool is slow or freezing

**Problem**: Large log files (100MB+) can take a while to process.

**Solution**: This is normal for logs with hundreds of events. Give it a minute or two. If loading a full directory, processing time scales with the number and size of files selected. Use the Default Windows Logs button or Browse Directory to limit the load to the four supported log types when scanning a system folder.

### "Generate Report" button is grayed out

**Problem**: You need to analyze a log file first before generating a report.

**Solution**: Click "Analyze" first, then the report button will become available.

### PDF won't generate

**Problem**: The PDF generation library may have encountered an error.

**Solution**: Try re-downloading the latest .exe from the GitHub releases page.

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
| 10 (Sysmon) | Process memory access | Credential theft (LSASS)  |

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

Version 6.0 | Last updated: Mar. 2026
