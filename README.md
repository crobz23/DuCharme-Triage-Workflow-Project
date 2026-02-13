# DuCharme Triage Assistant

**Version 4.0** | Trine University Senior Capstone Project

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

### Version 4.0 (Current)

**New Features:**
- Threat analysis now includes breach detection (failed logins, privilege escalation, account attacks)
- Parser now extracts asset and scope details from logs
- Menu prompting for "Incident Context" input from user before generating reports
- System.evtx logs can now be parsed
- More user-friendly Event ID descriptions in filtering menu
- Added "Asset and Scope" and "Incident Context" sections to report

---

## What This Tool Does

When something suspicious happens on a computer, the system creates event logs. These logs contain thousands of entries that are nearly impossible to read manually. 

This tool analyzes those logs for you and tells you:
- Is there malware on the system?
- Is someone trying to break in?
- What happened, when did it happen, and how serious is it?
- Ranks the threats based on severity
- What you should do next

Instead of spending hours digging through logs, you get a clean PDF report with threat scores and recommendations. It was built for non-technical people in mind.

---

## How It Works

### Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                  INPUT: .evtx Log File                      │
│         (Security.evtx, System.evtx, Sysmon)                │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────┐
              │    PARSER MODULE        │
              │     (parser.py)         │
              │                         │
              │  • Extracts events      │
              │  • Parses XML           │
              │  • Extracts timestamps  │
              │  • Gets asset/scope     │
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
│ ┌─────────────────┐  │        │  • Groups events      │
│ │ malware_        │  │        │  • Finds patterns     │
│ │ indicators.csv  │  │        └───────────────────────┘
│ └─────────────────┘  │
│ ┌─────────────────┐  │
│ │ breach_         │  │
│ │ indicators.csv  │  │
│ └─────────────────┘  │
│                      │
│  • Matches Event IDs │
│  • Calculates scores │
│  • Determines risk   │
│  • Groups threats    │
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
         │  • Risk levels     │    │  ┌────────────────┐  │
         │  • Top threats     │    │  │ Incident       │  │
         │  • Filter events   │    │  │ Context Dialog │  │
         └────────────────────┘    │  └────────────────┘  │
                                   │                      │
                                   │  Generates PDF:      │
                                   │  • File info         │
                                   │  • Asset & Scope     │
                                   │  • Incident Context  │
                                   │  • Timeline          │
                                   │  • Threat Indicators │
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

- A computer running Windows, Mac, or Linux
- Python 3.9 or newer installed ([download here](https://www.python.org/downloads/))
- Windows event log files (.evtx format)

### Installation

**Option 1: Download from GitHub**

1. Go to [our GitHub repository](https://github.com/crobz23/DuCharme-Triage-Workflow-Project)
2. Click the "Releases" button on the right panel and select "DuCharme_Triage_Assistant_4.0.exe"
3. Save the file to your computer and run the .exe

**Option 2: Clone the repository** (if you're familiar with Git)

```bash
git clone https://github.com/crobz23/DuCharme-Triage-Workflow-Project.git
cd DuCharme-Triage-Workflow-Project
```

**If using Option 2: Install Required Packages**

Open your terminal or command prompt in the project folder and run:

```bash
pip install -r requirements.txt
```

This installs the libraries the tool needs to run (ReportLab for PDFs, python-evtx for log parsing, etc.).

---

## How to Use

### Basic Workflow

**Step 1: Start the application**

```bash
python main.py
```

A window will open with the DuCharme Triage Assistant interface.

**Step 2: Load your log file**

Click "Browse" and select a Windows event log file (.evtx). These are usually located at:
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Security events)
- `C:\Windows\System32\winevt\Logs\System.evtx` (System events)
- Or Sysmon logs if you have Sysmon installed

**Step 3: Analyze**

Click the "Analyze" button. The tool will parse the log file and show you:
- How many events were found
- Event ID breakdown
- Threat analysis with risk levels and scores

**Step 4: Filter (optional)**

Use the "Filter by Event ID" button if you want to focus on specific event types. For example, if you only care about login events, you can filter to show just those. If you want to read a short description of what the event ID mean, you can view it in this menu.

**Step 5: Generate Report**

Click "Generate Report (PDF)" to create a professional report. You'll be prompted to:
1. Fill in incident context (who reported it, what they saw, etc.)
2. Choose where to save the PDF

The report includes:
- File information
- Timeline of events
- Threat indicators with severity scores
- Asset and scope details (what computers, users, IPs were involved)

---

## Understanding the Results

### Risk Levels

The tool assigns an overall risk level based on what it finds:

- **Low**: Normal activity, nothing alarming. Maybe keep an eye on it.
- **Medium**: Some suspicious behavior detected. Investigate further.
- **High**: Strong indicators of malware or breach. Take action soon.
- **Critical**: Active compromise detected. Respond immediately.

### Threat Categories

Events are grouped into categories based on how attackers typically operate:

- **Execution**: Malicious programs or scripts running
- **Persistence**: Attacker trying to maintain access (scheduled tasks, services)
- **Credential Access**: Attempts to steal passwords or login credentials
- **Defense Evasion**: Hiding tracks (clearing logs, code injection)
- **Command and Control**: Malware calling home to attacker servers
- **Lateral Movement**: Attacker moving between systems
- **Impact**: Destructive actions (file deletion, ransomware)

### CVSS Scores

Each threat gets a score from 0-10 based on how serious it is:
- **0.0-3.9**: Low severity
- **4.0-6.9**: Medium severity
- **7.0-8.9**: High severity
- **9.0-10.0**: Critical severity

Higher scores mean you should prioritize investigating those events.

---

## Threat Detection

### The CSV Files

The tool uses two CSV files to define what it looks for:

**malware_indicators.csv** - Detects malware and hacking tools
- Suspicious programs (mimikatz, psexec, etc.)
- Encoded PowerShell commands
- Code injection
- Malicious services and scheduled tasks

**breach_indicators.csv** - Detects break-in attempts
- Failed login attempts (brute force)
- Account lockouts
- Privilege escalation
- Unauthorized account creation

**CSV Format:**

| Column Name | What It Means | Example Value |
|-------------|---------------|---------------|
| EventID | The event's identification number | 4625 |
| Description | Brief explanation | "Failed Login Attempt" |
| Threat | What kind of attack this indicates | "Brute Force Attack" |
| Score | How dangerous this is (0 to 10 scale) | 7 |
| Category | What type of attack category | "Credential Access" |
| Indicators | Specific things or processes to look for | "Multiple rapid failures, Dictionary attack patterns" |

**Column Sources:**

The columns are a mix between industry standards and our own creation. Triage wise, the top threats are ranked by the highest CVSS score.

**Standardized:**
- EventID (Microsoft)
- Category (MITRE)
- CVSSScore methodology (FIRST.org industry standard calculator)

**Our creation:**
- Description
- Threat
- Indicators
- Specific CVSS score values

---

## Troubleshooting

### "Module not found" error

**Problem**: Python can't find the required libraries.

**Solution**: Make sure you ran `pip install -r requirements.txt` in the correct folder.

### "No events found" error

**Problem**: The log file couldn't be parsed.

**Solution**: 
- Make sure you're loading an actual .evtx file (not a .txt or .csv)
- The file might be corrupted - try a different log file
- You might need administrator privileges to access certain log files

### Tool is slow or freezing

**Problem**: Large log files (100MB+) can take a while to process.

**Solution**: This is normal for logs with hundreds of events. Give it a minute or two. If it's taking more than 5 minutes, the file might be too large.

### "Generate Report" button is grayed out

**Problem**: You need to analyze a log file first before generating a report.

**Solution**: Click "Analyze" first, then the report button will become available.

### PDF won't generate

**Problem**: ReportLab library might not be installed correctly.

**Solution**: 
```bash
pip install reportlab --upgrade
```

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

**Quick Commands:**

```bash
# Start the tool
python main.py

# Update dependencies
pip install -r requirements.txt --upgrade

# Check Python version
python --version
```

---

## Credits

**Development Team** 
- Collin Robinson - Project Manager, Analysis Engine, Integrator, Tester
- Matthew Domsich - Timeline Analysis, Parsing, Researcher
- Nathan Bradshaw - Report Generation, GUI Designer

**Sponsor**
- Eric Gaby

**Special Thanks**
- Dr. David Corcoran (Advisor)
- Dr. William Topp (Advisor)
- Senior Capstone

---

Version 4.0 | Last updated: Feb. 2026
