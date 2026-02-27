# DuCharme Triage Assistant

**Version 5.0** | Trine University Senior Capstone Project

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

### Version 5.0

**New Features:**
- Multi-file support — analyze multiple .evtx files in a single session; results are merged and displayed together
- Directory parsing — select an entire folder of .evtx files instead of loading them one at a time
- Threat scoring now uses an Impact × Confidence risk matrix instead of raw CVSS scores alone
- breach_indicators.csv added as a second threat database covering account-based attacks (brute force, privilege escalation, account lockouts, log clearing)
- Dynamic confidence boosting — confidence scores are raised automatically when events repeat frequently or cluster in short time windows
- Events from all log types (Security, System, Sysmon, Application) are now combined and analyzed together across multi-file loads


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
│       (Security.evtx, System.evtx, Sysmon, etc.)            │
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
              │     System / )       │
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
│  • Matches Event IDs │
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
         │  • Filter events   │    │  └────────────────┘  │
         └────────────────────┘    │                      │
                                   │  Generates PDF:      │
                                   │  • File info         │
                                   │  • Asset & Scope     │
                                   │  • Incident Context  │
                                   │  • Timeline          │
                                   │  • Threat Indicators │
                                   │    with matrix scores│
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
2. Click the "Releases" button on the right panel and select "DuCharme_Triage_Assistant_V5.exe"
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
1. Launch the .exe

or

```bash
python main.py
```

A window will open with the DuCharme Triage Assistant interface.

**Step 2: Load your log file(s)**

Click "Browse" and select one or more Windows event log files (.evtx), or select an entire folder to load all .evtx files inside it at once. You can mix log types. Security, System, and Sysmon logs can all be loaded together, and the results will be merged automatically.

Common log locations:
- `C:\Windows\System32\winevt\Logs\Security.evtx` (Security events)
- `C:\Windows\System32\winevt\Logs\System.evtx` (System events)
- Or Sysmon logs if you have Sysmon installed

**Step 3: Analyze**

Click the "Analyze" button. The tool will parse all selected log files and show you:
- How many total events were found across all files
- Event ID breakdown by log type
- Threat analysis with Impact × Confidence matrix risk levels
- Which threats had their confidence score boosted due to frequency or clustering

**Step 4: Filter (optional)**

Use the "Filter by Event ID" button if you want to focus on specific event types. For example, if you only care about login events, you can filter to show just those. Short descriptions of each Event ID are available in this menu.

**Step 5: Generate Report**

Click "Generate Report (PDF)" to create a professional report. You'll be prompted to:
1. Fill in incident context (who reported it, what they saw, etc.)
2. Choose where to save the PDF

The report includes:
- File information
- Timeline of events
- Threat indicators with Impact, Confidence, and Matrix risk level
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

Each threat carries a reference CVSS score from 0–10 based on its known severity:
- **0.0–3.9**: Low severity
- **4.0–6.9**: Medium severity
- **7.0–8.9**: High severity
- **9.0–10.0**: Critical severity

CVSS scores are kept for reference, but the final risk level shown in the app and report is determined by the Impact × Confidence matrix, not the CVSS score alone.

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
3 = High, 
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
| EventID | The event's identification number | 4625 |
| Description | Brief explanation | "Failed Login Attempt" |
| Threat | What kind of attack this indicates | "Brute Force Attack" |
| Score | CVSS severity reference (0–10 scale) | 7.0 |
| Impact | How damaging if confirmed (1–4 scale) | 2 |
| BaseConfidence | Starting confidence this is malicious (1–4 scale) | 1 |
| Category | MITRE ATT&CK attack category | "Credential Access" |
| Indicators | Specific behaviors or patterns to look for | "Multiple rapid failures; Account enumeration" |

**Column Sources:**

The columns are a mix between industry standards and our own creation. Triage-wise, threats are ranked by matrix risk level first, then by Impact as a tiebreaker.

Standardized:
- EventID (Microsoft)
- Category (MITRE ATT&CK)
- CVSS Score methodology (FIRST.org industry standard calculator)

Our creation:
- Description
- Threat
- Indicators
- Impact values
- BaseConfidence values
- Specific score assignments

---

## Troubleshooting

### "Module not found" error

**Problem**: Python can't find the required libraries.

**Solution**: Make sure you ran `pip install -r requirements.txt` in the correct folder.

### "No events found" error

**Problem**: The log file couldn't be parsed.

**Solution**:
- Make sure you're loading an actual .evtx file (not a .txt or .csv)
- The file might be corrupted — try a different log file
- You might need administrator privileges to access certain log files

### Tool is slow or freezing

**Problem**: Large log files (100MB+) can take a while to process.

**Solution**: This is normal for logs with hundreds of events. Give it a minute or two. If loading a full directory, processing time scales with the number and size of files selected.

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
- Collin Robinson — Project Manager, Analysis Engine, Integrator, Tester
- Matthew Domsich — Timeline Analysis, Parsing, Researcher
- Nathan Bradshaw — Report Generation, GUI Designer

**Sponsor**
- Eric Gaby

**Special Thanks**
- Dr. David Corcoran (Advisor)
- Dr. William Topp (Advisor)
- Senior Capstone Classmates

---

Version 5.0 | Last updated: Feb. 2026
