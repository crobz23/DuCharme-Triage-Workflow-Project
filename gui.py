# gui.py
import os
import re
from collections import Counter
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk

from parser import _CREDENTIAL_EIDS

# Log files supported by the parser. When scanning a directory only these
# files will be loaded — everything else is ignored.
WINDOWS_EVENT_DESCRIPTIONS = {
    # System.evtx
    '1': 'A system error occurred', '6': 'A driver was loaded',
    '7': 'A service was started or stopped', '10': 'A COM+ catalog error occurred',
    '11': 'A disk controller error was detected', '12': 'The Service Control Manager started',
    '13': 'The Service Control Manager stopped', '15': 'A disk device error occurred',
    '41': 'The computer restarted unexpectedly', '42': 'The computer is entering sleep mode',
    '51': 'A disk paging error occurred', '55': 'A file system corruption was detected',
    '104': 'The System log was cleared', '107': 'The computer woke up from sleep',
    '109': 'A kernel power transition occurred', '1001': 'A Windows Error Reporting crash occurred',
    '1014': 'A DNS client resolution timeout occurred', '1100': 'Event logging was shut down',
    '1101': 'Audit events were dropped', '1102': 'The Security audit log was cleared',
    '1530': 'A user profile could not be loaded', '6005': 'The Event Log service started',
    '6006': 'The Event Log service stopped', '6008': 'An unexpected system shutdown occurred',
    '6009': 'System boot information was logged', '6013': 'System uptime was recorded',
    '7000': 'A service failed to start', '7001': 'A service depends on another service that failed',
    '7009': 'A service timeout occurred during startup', '7011': 'A service timeout occurred during operation',
    '7022': 'A service hung on starting', '7023': 'A service terminated with an error',
    '7024': 'A service terminated with a service-specific error',
    '7026': 'A boot-start or system-start driver failed to load',
    '7030': 'A service was configured incorrectly', '7031': 'A service terminated unexpectedly',
    '7032': 'The Service Control Manager attempted corrective action',
    '7034': 'A service crashed unexpectedly', '7035': 'A service control was sent',
    '7036': 'A service entered running or stopped state', '7040': 'A service startup type was changed',
    '7045': 'A new service was installed',
    # Security
    '4103': 'A PowerShell script was executed', '4104': 'A PowerShell command was executed',
    '4105': 'A PowerShell script started', '4106': 'A PowerShell script stopped',
    '4616': 'The system time was changed', '4624': 'A user successfully logged in',
    '4625': 'A user failed to log in', '4634': 'A user session ended',
    '4647': 'A user logged out', '4648': 'A user logged in with different credentials',
    '4656': 'A file or folder was accessed', '4657': 'A system setting was changed',
    '4663': 'A file or folder was accessed', '4670': 'File or folder permissions were changed',
    '4672': 'A user was given special access rights', '4673': 'A privileged operation was attempted',
    '4688': 'A program was started', '4689': 'A program was closed',
    '4698': 'A scheduled task was created', '4699': 'A scheduled task was deleted',
    '4700': 'A scheduled task was enabled', '4701': 'A scheduled task was disabled',
    '4702': 'A scheduled task was updated', '4719': 'An audit policy was changed',
    '4720': 'A user account was created', '4722': 'A user account was enabled',
    '4723': 'A password change was attempted', '4724': 'A password reset was attempted',
    '4725': 'A user account was disabled', '4726': 'A user account was deleted',
    '4728': 'A user was added to a global security group',
    '4732': 'A user was added to a local security group',
    '4733': 'A user was removed from a group', '4735': 'A security group was changed',
    '4737': 'A global security group was changed', '4738': 'A user account was modified',
    '4740': 'A user account was locked', '4755': 'A universal security group was changed',
    '4756': 'A user was added to a universal group', '4757': 'A user was removed from a universal group',
    '4765': 'A security identifier history was added', '4767': 'A user account was unlocked',
    '4768': 'A Kerberos login ticket was requested', '4769': 'A Kerberos service ticket was requested',
    '4771': 'A Kerberos pre-authentication failed', '4776': 'A login attempt was validated',
    '4778': 'A remote session was reconnected', '4779': 'A remote session was disconnected',
    '4794': 'A password recovery mode was attempted', '5136': 'A directory object was modified',
    '5137': 'A directory object was created', '5140': 'A network folder was accessed',
    '5141': 'A directory object was deleted', '5142': 'A network folder was shared',
    '5145': 'A network folder access was checked',
    '5379': 'Credential Manager credentials were read',
    # Windows Defender
    '1005': 'Windows Defender detected a script-based threat',
    '1006': 'Windows Defender detected a network-based threat',
    '1008': 'Windows Defender blocked a network connection',
    '1013': 'Windows Defender detection history was cleared',
    '1116': 'Windows Defender detected malware or potentially unwanted software',
    '1117': 'Windows Defender took action to protect against malware',
    '1118': 'Windows Defender failed to remediate a threat',
    '1119': 'Windows Defender encountered a critical error trying to take action on malware',
    '1120': 'Windows Defender failed to remove malware from quarantine',
    '1121': 'Windows Defender blocked a potentially malicious behavior',
    '1122': 'Windows Defender logged a potentially malicious behavior',
    '1123': 'Windows Defender blocked unauthorized changes to protected folders',
    '1124': 'Windows Defender blocked an exploit attempt',
    '1150': 'Windows Defender could not clean or quarantine a detected threat',
    '2050': 'Windows Defender real-time protection was disabled',
    '3007': 'Windows Defender detected an advanced persistent threat (APT)',
    '3020': 'Windows Defender blocked a PowerShell or script-based attack',
    '5001': 'Windows Defender Tamper Protection was successfully disabled',
    '5004': 'Windows Defender Tamper Protection disable attempt was detected',
    '5007': 'Windows Defender configuration was changed',
    '5010': 'Windows Defender scanning was disabled',
}

SYSMON_EVENT_DESCRIPTIONS = {
    '1': 'A program was started', '2': 'A file timestamp was changed',
    '3': 'A network connection was made', '4': 'A Sysmon service state changed',
    '5': 'A program was closed', '6': 'A driver was loaded',
    '7': 'A library file was loaded', '8': 'A program injected code into another program',
    '9': 'A disk was accessed directly', '10': 'A program accessed another program',
    '11': 'A file was created', '12': 'A registry entry was created or deleted',
    '13': 'A registry value was set', '14': 'A registry entry was renamed',
    '15': 'A file stream was created', '16': 'A Sysmon configuration was changed',
    '17': 'A communication pipe was created', '18': 'A communication pipe was connected',
    '19': 'A WMI event filter was detected', '20': 'A WMI event consumer was detected',
    '21': 'A WMI event binding was detected', '22': 'A DNS query was made',
    '23': 'A file was deleted', '24': 'A clipboard change was detected',
    '25': 'A program was tampered with', '26': 'A file deletion was logged',
    '27': 'An executable file was blocked', '28': 'A file shredding was blocked',
    '29': 'An executable file was detected',
}

SUPPORTED_LOG_NAMES = {
    'security.evtx',
    'system.evtx',
    'microsoft-windows-sysmon%4operational.evtx',
    'microsoft-windows-windows defender%4operational.evtx',
}

FIELD_LABELS = {
    "user":             "User",
    "added_user":       "Added User",
    "added_by":         "Added By",
    "process":          "Process",
    "source_image":     "Source",
    "target_image":     "Target",
    "command_line":     "Command",
    "src_ip":           "Source IP",
    "dest_ip":          "Dest IP",
    "dest_port":        "Port",
    "dns_query":        "DNS Query",
    "file_path":        "File",
    "image_loaded":     "DLL Loaded",
    "registry_key":     "Registry Key",
    "service_name":     "Service",
    "service_path":     "Service Path",
    "service_account":  "Service Account",
    "task_name":        "Task Name",
    "logon_type":       "Logon Type",
    "removed_user":     "Removed User",
    "removed_by":       "Removed By",
    "deleted_user":     "Deleted User",
    "deleted_by":       "Deleted By",
    "threat_name":      "Threat",
    "threat_severity":  "Severity",
    "action_taken":     "Action",
    "threat_file_path": "Threat File",
    "config_old_value": "Config Before",
    "config_new_value": "Config After",
    "feature_change":   "Protection Change",
    "share_name":       "Share",
    "relative_target":  "Pipe / Path",
}

# Event IDs where the process field is noise (logon/auth events)
# Imported from parser to avoid duplication — see parser._CREDENTIAL_EIDS

# EID 1 parent-chain heuristic sets — defined once here, used in both
# extract_deep_dive_data (deep-dive filter) and the matching comment below.
# Must stay in sync with the equivalent sets in analysis.py.
_EID1_SUSPICIOUS_SPAWNERS = {
    'jjs.exe', 'wmic.exe', 'mshta.exe', 'cscript.exe', 'wscript.exe',
    'regsvr32.exe', 'rundll32.exe', 'msiexec.exe', 'installutil.exe',
    'schtasks.exe', 'at.exe', 'odbcconf.exe', 'pcalua.exe', 'forfiles.exe',
}
_EID1_RECON_SHELLS = {
    'cmd.exe', 'powershell.exe', 'whoami.exe', 'net.exe',
    'ipconfig.exe', 'systeminfo.exe', 'tasklist.exe',
    'nltest.exe', 'arp.exe', 'route.exe', 'netstat.exe',
}
_EID1_INSTALLER_ROOTS = (
    'c:\\program files\\', 'c:\\program files (x86)\\',
    'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
)
_EID1_DISCOVERY_CMDS = (
    'whoami', 'systeminfo', 'ipconfig', 'net user', 'net group',
    'nltest', 'arp ', 'route print', 'tasklist', 'netstat', '/c ', '/k ',
)


def _is_supported_log(filename):
    """Return True if the filename matches a supported log."""
    return filename.lower() in SUPPORTED_LOG_NAMES


def _format_network_ips(ips, malware_analysis, total_observed=0):
    """Build the human-readable network connections string for the scope section.

    Only IPs drawn from Sysmon EID 3 events that the malware engine actually
    flagged are included — so this field shows confirmed suspicious outbound
    connections rather than all external traffic.

    Up to 10 flagged IPs shown; count note appended when there are more.
    total_observed is the count of all unique external IPs seen in EID 3 events
    (flagged or not), shown for analyst context.
    Returns a plain 'none detected' string when no flagged IPs exist.
    """
    if not ips:
        if total_observed:
            return (f'No suspicious external network connections detected'
                    f'  ({total_observed} total unique external IP(s) observed)')
        return 'No suspicious external network connections detected'

    sorted_ips = sorted(ips)
    shown = sorted_ips[:10]
    result = ', '.join(shown)
    if len(sorted_ips) > 10:
        result += f' ... and {len(sorted_ips) - 10} more'
    result += f'  ({len(sorted_ips)} suspicious IP(s) flagged by threat engine'
    if total_observed > len(sorted_ips):
        result += f'; {total_observed} total unique external IP(s) observed'
    result += ')'
    return result


class TriageToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DuCharme Triage Assistant")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables
        self.file_path = tk.StringVar()
        self.selected_file = None
        self.all_results = None
        self.malware_analysis = None  # Store malware analysis results
        self.assessment_data = None   # Store CSV-driven assessment from generate_assessment()
        self.timeline_data = None  # Store timeline data
        self.deep_dive_data = None  # Store evidence for deep dives section
        self.available_event_ids = []
        self.selected_event_ids = []
        # Time filter variables
        self.time_filter_active = False
        self.time_filter_start = None
        self.time_filter_end = None
        
        # Remember last time filter values
        self.last_from_month = 1
        self.last_from_day = 1
        self.last_from_year = 2026
        self.last_from_hour = 0
        self.last_from_minute = 0
        self.last_to_month = 1
        self.last_to_day = 1
        self.last_to_year = 2026
        self.last_to_hour = 23
        self.last_to_minute = 59
        
        # Store original unfiltered results
        self.original_results = None
        self.original_malware_analysis = None
        self.original_timeline_data = None
        self.original_deep_dive_data = None
        
        # Create GUI elements
        self.create_widgets()
    
    def safe_sort_event_ids(self, event_ids):
        """Safely sort event IDs, handling 'Unknown' and other non-numeric values"""
        def sort_key(x):
            try:
                return (0, int(x))  # Numeric IDs come first, sorted numerically
            except (ValueError, TypeError):
                return (1, x)  # Non-numeric IDs come last, sorted alphabetically
        return sorted(event_ids, key=sort_key)
        
    def create_widgets(self):
        # Header Frame
        header_frame = tk.Frame(self.root, bg="#1e40af", pady=10)
        header_frame.pack(fill=tk.X)
        
        header_label = tk.Label(
            header_frame, 
            text="DuCharme Triage Assistant",
            font=("Arial", 16, "bold"),
            bg="#1e40af",
            fg="white"
        )
        header_label.pack()
        
        # Main Content Frame
        main_frame = tk.Frame(self.root, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File Selection Section
        file_frame = tk.LabelFrame(main_frame, text="Select Log File or Directory", padx=10, pady=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File path entry
        file_entry = tk.Entry(file_frame, textvariable=self.file_path, state='readonly', width=60)
        file_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        
        # Browse file button
        browse_btn = tk.Button(
            file_frame,
            text="Browse File...",
            command=self.browse_file,
            bg="#3b82f6",
            fg="white",
            padx=15,
            pady=5
        )
        browse_btn.pack(side=tk.LEFT)

        # Browse directory button
        browse_dir_btn = tk.Button(
            file_frame,
            text="Browse Directory...",
            command=self.browse_directory,
            bg="#3b82f6",
            fg="white",
            padx=15,
            pady=5
        )
        browse_dir_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # Default Windows Logs Section
        default_logs_frame = tk.LabelFrame(main_frame, text="Or Select Default Windows Log Location", padx=10, pady=10)
        default_logs_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Default Windows Logs button
        default_logs_btn = tk.Button(
            default_logs_frame,
            text="📁 Default Windows Logs",
            command=self.load_default_windows_logs,
            bg="white",
            fg="#374151",
            relief=tk.RAISED,
            padx=15,
            pady=8
        )
        default_logs_btn.pack(side=tk.LEFT)
        
        # Control Frame (Analyze + Filter)
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Analyze Button
        analyze_btn = tk.Button(
            control_frame,
            text="Analyze",
            command=self.analyze_log,
            bg="#1e40af",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=30,
            pady=10
        )
        analyze_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Filter Button
        self.filter_btn = tk.Button(
            control_frame,
            text="🔍 Filter by Event ID",
            command=self.open_filter_dialog,
            bg="white",
            fg="#374151",
            relief=tk.RAISED,
            padx=15,
            pady=10,
            state=tk.DISABLED
        )
        self.filter_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Time Filtering Button
        self.time_filter_btn = tk.Button(
            control_frame,
            text="📅 Time Filtering",
            command=self.open_time_filter_dialog,
            bg="white",
            fg="#374151",
            relief=tk.RAISED,
            padx=15,
            pady=10,
            state=tk.DISABLED
        )
        self.time_filter_btn.pack(side=tk.LEFT)
        
        # Filter badge (shows count of selected filters)
        self.filter_badge = tk.Label(
            control_frame,
            text="",
            bg="#1e40af",
            fg="white",
            font=("Arial", 8, "bold"),
            padx=6,
            pady=2
        )
        
        # Results Section
        results_frame = tk.LabelFrame(main_frame, text="Results", padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Scrolled text for results
        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Courier", 9),
            bg="#f8fafc"
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.insert(tk.END, "No results yet. Select a log file and click Analyze.")
        self.results_text.config(state=tk.DISABLED)
        
        # Button Frame
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        # Clear Filters button (combines Event ID filter and Time filter)
        self.clear_filters_btn = tk.Button(
            button_frame,
            text="Clear Filters",
            command=self.clear_all_filters,
            padx=15,
            pady=5,
            state=tk.DISABLED
        )
        self.clear_filters_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear results button
        clear_btn = tk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results,
            padx=15,
            pady=5
        )
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Generate Report button
        self.report_btn = tk.Button(
            button_frame,
            text="📄 Generate Report (PDF)",
            command=self.generate_pdf_report,
            padx=15,
            pady=5,
            state=tk.DISABLED
        )
        self.report_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Exit button
        exit_btn = tk.Button(
            button_frame,
            text="Exit",
            command=self.exit_app,
            bg="#dc2626",
            fg="white",
            padx=15,
            pady=5
        )
        exit_btn.pack(side=tk.RIGHT)
        
    def browse_file(self):
        """Open file dialog to select .evtx file"""
        filename = filedialog.askopenfilename(
            title="Select Windows Event Log File",
            filetypes=[
                ("Event Log Files", "*.evtx"),
                ("All Files", "*.*")
            ]
        )
        if filename:
            self.selected_file = filename
            self.file_path.set(filename)
            
    def browse_directory(self):
        """Open directory dialog to select a folder containing .evtx files"""
        directory = filedialog.askdirectory(
            title="Select Directory Containing Event Log Files"
        )
        if directory:
            evtx_files = [
                os.path.join(directory, f)
                for f in os.listdir(directory)
                if f.lower().endswith('.evtx')
            ]
            if not evtx_files:
                messagebox.showwarning("No Files Found", "No .evtx files were found in the selected directory.")
                return
            self.selected_file = evtx_files
            self.file_path.set(f"{directory} ({len(evtx_files)} .evtx file(s))")

    def analyze_log(self):
        """Trigger log analysis"""
        if not self.selected_file:
            messagebox.showwarning("No File Selected", "Please select a log file or directory first.")
            return

        # Determine list of files to analyze
        if isinstance(self.selected_file, list):
            # Already a list of files from browse_directory
            files_to_analyze = self.selected_file
            for f in files_to_analyze:
                if not os.path.exists(f):
                    messagebox.showerror("File Not Found", f"The file does not exist:\n{f}")
                    return
        elif os.path.isdir(self.selected_file):
            # It's a directory path (from Default Windows Logs)
            try:
                evtx_files = [
                    os.path.join(self.selected_file, f)
                    for f in os.listdir(self.selected_file)
                    if _is_supported_log(f)
                ]
                if not evtx_files:
                    self.results_text.config(state=tk.NORMAL)
                    self.results_text.delete(1.0, tk.END)
                    self.results_text.insert(tk.END, f"Error: No supported .evtx files found in:\n{self.selected_file}")
                    self.results_text.config(state=tk.DISABLED)
                    messagebox.showwarning("No Files Found", f"No supported .evtx files found in:\n{self.selected_file}")
                    return
                files_to_analyze = evtx_files
            except PermissionError as e:
                error_msg = (
                    f"Permission Denied - Administrator Required\n\n"
                    f"Cannot access Windows logs folder:\n{self.selected_file}\n\n"
                    f"Error: {str(e)}\n\n"
                    f"To access system logs:\n"
                    f"1. Close this program\n"
                    f"2. Right-click the executable\n"
                    f"3. Select 'Run as administrator'\n\n"
                    f"Alternative:\n"
                    f"Export logs from Event Viewer:\n"
                    f"- Open Event Viewer (eventvwr.msc)\n"
                    f"- Right-click a log → 'Save All Events As...'\n"
                    f"- Save as .evtx file\n"
                    f"- Use 'Browse File' to select the exported file"
                )
                self.results_text.config(state=tk.NORMAL)
                self.results_text.delete(1.0, tk.END)
                self.results_text.insert(tk.END, error_msg)
                self.results_text.config(state=tk.DISABLED)
                messagebox.showerror("Permission Denied", error_msg)
                return
            except Exception as e:
                error_msg = f"Error accessing directory:\n{self.selected_file}\n\nError: {str(e)}"
                self.results_text.config(state=tk.NORMAL)
                self.results_text.delete(1.0, tk.END)
                self.results_text.insert(tk.END, error_msg)
                self.results_text.config(state=tk.DISABLED)
                messagebox.showerror("Error", error_msg)
                return
        else:
            # Single file path
            if not os.path.exists(self.selected_file):
                messagebox.showerror("File Not Found", "The selected file does not exist.")
                return
            files_to_analyze = [self.selected_file]

        # Clear previous results and filters
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Analyzing {len(files_to_analyze)} file(s)...\n")
        self.results_text.update()

        # Import parser and run analysis
        try:
            from parser import parse_evtx, analyze_events

            all_events = []
            successful_files = 0
            failed_files = []
            
            for filepath in files_to_analyze:
                try:
                    file_events = parse_evtx(filepath)
                    if file_events:
                        all_events.extend(file_events)
                        successful_files += 1
                    else:
                        failed_files.append((filepath, "No events parsed"))
                except PermissionError:
                    failed_files.append((filepath, "Permission denied"))
                except Exception as e:
                    failed_files.append((filepath, str(e)))

            # Show parsing summary if there were failures
            if failed_files:
                self.results_text.insert(tk.END, f"\nParsing Summary:\n")
                self.results_text.insert(tk.END, f"  Successfully parsed: {successful_files} file(s)\n")
                self.results_text.insert(tk.END, f"  Failed to parse: {len(failed_files)} file(s)\n\n")
            
            if not all_events:
                if failed_files:
                    self.results_text.insert(tk.END, f"\nPermission Denied - Administrator Required\n")
                    self.results_text.insert(tk.END, f"=" * 60 + "\n\n")
                    self.results_text.insert(tk.END, f"Cannot access Windows logs folder:\n")
                    
                    # Get the directory path if it's a directory
                    if len(files_to_analyze) > 0 and os.path.dirname(files_to_analyze[0]):
                        dir_path = os.path.dirname(files_to_analyze[0])
                        self.results_text.insert(tk.END, f"{dir_path}\n\n")
                    
                    self.results_text.insert(tk.END, f"Error: No events could be parsed from any files.\n")
                    self.results_text.insert(tk.END, f"Reason: Permission denied on {len(failed_files)} file(s)\n\n")
                    
                    self.results_text.insert(tk.END, f"To access system logs:\n")
                    self.results_text.insert(tk.END, f"1. Close this program\n")
                    self.results_text.insert(tk.END, f"2. Right-click the executable\n")
                    self.results_text.insert(tk.END, f"3. Select 'Run as administrator'\n\n")
                    
                    self.results_text.insert(tk.END, f"Alternative:\n")
                    self.results_text.insert(tk.END, f"Export logs from Event Viewer:\n")
                    self.results_text.insert(tk.END, f"- Open Event Viewer (eventvwr.msc)\n")
                    self.results_text.insert(tk.END, f"- Right-click a log → 'Save All Events As...'\n")
                    self.results_text.insert(tk.END, f"- Save as .evtx file\n")
                    self.results_text.insert(tk.END, f"- Use 'Browse File' to select the exported file\n")
                else:
                    self.results_text.insert(tk.END, "\nError: No events found or file could not be parsed.\n")
                self.results_text.config(state=tk.DISABLED)
                return
            
            # Continue with analysis if we have events
            self.results_text.insert(tk.END, f"\nProceeding with {len(all_events)} events from {successful_files} file(s)...\n")
            self.results_text.update()
            
            # Analyze events
            self.all_results = analyze_events(all_events)
            
            # Extract timeline from parsed event dicts
            from analysis import analyze_malware, extract_timeline, generate_assessment

            self.timeline_data = extract_timeline(all_events)
            
            # Run malware analysis with timeline data for confidence boosting
            self.malware_analysis = analyze_malware(self.all_results, self.timeline_data)
            self.assessment_data = generate_assessment(self.malware_analysis)

            # Extract deep dive evidence from parsed events
            self.deep_dive_data = self.extract_deep_dive_data(self.all_results)

            # Store original unfiltered results for time filtering
            self.original_results = self.all_results
            self.original_malware_analysis = self.malware_analysis
            self.original_timeline_data = self.timeline_data
            self.original_deep_dive_data = self.deep_dive_data
            
            # Extract available Event IDs and enable filter and report button
            self.available_event_ids = self.safe_sort_event_ids(self.all_results['counts'].keys())
            self.selected_event_ids = []
            self.filter_btn.config(state=tk.NORMAL)
            self.time_filter_btn.config(state=tk.NORMAL)  # Enable time filter
            self.report_btn.config(state=tk.NORMAL)
            self.clear_filters_btn.config(state=tk.DISABLED)
            self.update_filter_badge()
            
            # Generate and display results (including malware analysis and timeline)
            display_path = self.selected_file if isinstance(self.selected_file, str) else f"{len(self.selected_file)} files from directory"
            output = self.generate_results(display_path, self.all_results)
            output += self.generate_timeline_summary(self.timeline_data)
            output += self.generate_malware_summary(self.malware_analysis)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, output)
            self.results_text.config(state=tk.DISABLED)
            
        except Exception as e:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error during analysis:\n{str(e)}")
            self.results_text.config(state=tk.DISABLED)
            messagebox.showerror("Analysis Error", f"An error occurred:\n{str(e)}")
    
    def get_event_description(self, event_id, prefer_sysmon=False):
        """Get description for a given Event ID"""
        primary, fallback = (SYSMON_EVENT_DESCRIPTIONS, WINDOWS_EVENT_DESCRIPTIONS) if prefer_sysmon else (WINDOWS_EVENT_DESCRIPTIONS, None)
        desc = primary.get(event_id)
        if desc:
            return desc
        if fallback:
            return fallback.get(event_id, "An event was recorded")
        return "An event was recorded"
    
    def open_filter_dialog(self):
        """Open Event ID filter dialog"""
        if not self.available_event_ids:
            messagebox.showinfo("No Events", "No Event IDs available to filter.")
            return
        
        # Create filter dialog window
        filter_window = tk.Toplevel(self.root)
        filter_window.title("Filter by Event ID")
        filter_window.geometry("400x550")  # Increased height to ensure Apply button is visible
        filter_window.resizable(True, True)  # Allow resizing in case user needs more space
        
        # Make it modal
        filter_window.transient(self.root)
        filter_window.grab_set()
        
        # Track if window is alive
        window_alive = {'alive': True}
        
        # Header frame
        header_frame = tk.Frame(filter_window, padx=15, pady=10, bg="#f8fafc")
        header_frame.pack(fill=tk.X)
        
        tk.Label(
            header_frame,
            text="Select Event IDs",
            font=("Arial", 11, "bold"),
            bg="#f8fafc"
        ).pack(side=tk.LEFT)
        
        # Select All / Clear buttons
        button_frame = tk.Frame(header_frame, bg="#f8fafc")
        button_frame.pack(side=tk.RIGHT)
        
        check_vars = {}
        
        def select_all():
            for var in check_vars.values():
                var.set(True)
        
        def clear_all():
            for var in check_vars.values():
                var.set(False)
        
        tk.Button(
            button_frame,
            text="Select All",
            command=select_all,
            fg="#1e40af",
            relief=tk.FLAT,
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="Clear",
            command=clear_all,
            fg="#64748b",
            relief=tk.FLAT,
            cursor="hand2"
        ).pack(side=tk.LEFT)
        
        # Search frame
        search_frame = tk.Frame(filter_window, padx=15, pady=5, bg="#f8fafc")
        search_frame.pack(fill=tk.X)
        
        # Create a local StringVar for the search
        local_search_var = tk.StringVar()
        
        search_entry = tk.Entry(
            search_frame,
            textvariable=local_search_var,
            font=("Arial", 9)
        )
        search_entry.pack(fill=tk.X, pady=5)
        search_entry.insert(0, "🔍 Search event ID...")
        search_entry.config(fg='gray')
        
        # Search entry focus handlers
        def on_search_focus_in(event):
            if search_entry.get() == "🔍 Search event ID...":
                search_entry.delete(0, tk.END)
                search_entry.config(fg='black')
        
        def on_search_focus_out(event):
            if search_entry.get() == "":
                search_entry.insert(0, "🔍 Search event ID...")
                search_entry.config(fg='gray')
        
        search_entry.bind('<FocusIn>', on_search_focus_in)
        search_entry.bind('<FocusOut>', on_search_focus_out)
        
        # Checkbox list frame with scrollbar
        list_frame = tk.Frame(filter_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
        
        # Determine if we need scrollbar (more than 10 items)
        needs_scrollbar = len(self.available_event_ids) > 10
        
        if needs_scrollbar:
            # Create scrollbar and canvas
            scrollbar = tk.Scrollbar(list_frame, orient="vertical", width=20)
            scrollbar.pack(side="right", fill="y")
            
            canvas = tk.Canvas(list_frame, highlightthickness=0, height=300, bg="white", yscrollcommand=scrollbar.set)
            canvas.pack(side="left", fill="both", expand=True)
            
            scrollbar.config(command=canvas.yview)
            
            scrollable_frame = tk.Frame(canvas, bg="white")
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            # FIXED: Set width to None to let it auto-size
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            
            # Enable mousewheel scrolling
            def on_mousewheel(event):
                canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            
            def bind_mousewheel(event):
                canvas.bind_all("<MouseWheel>", on_mousewheel)
            
            def unbind_mousewheel(event):
                canvas.unbind_all("<MouseWheel>")
            
            canvas.bind("<Enter>", bind_mousewheel)
            canvas.bind("<Leave>", unbind_mousewheel)
        else:
            # No scrollbar needed - use simple frame
            scrollable_frame = tk.Frame(list_frame, bg="white")
            scrollable_frame.pack(fill="both", expand=True)
            canvas = None
            scrollbar = None
        
        # Create checkboxes for each Event ID
        checkboxes = {}

        sysmon_eids = self._sysmon_eids(self.all_results) if self.all_results else set()

        for event_id in self.available_event_ids:
            var = tk.BooleanVar(value=(event_id in self.selected_event_ids))
            check_vars[event_id] = var

            description = self.get_event_description(event_id, prefer_sysmon=(event_id in sysmon_eids))
            label_text = self._eid_label(event_id, sysmon_eids)

            # Create a frame for each checkbox + description
            cb_frame = tk.Frame(scrollable_frame, bg="white")
            cb_frame.pack(anchor='w', padx=10, pady=5, fill=tk.X)

            # Checkbox with event ID
            cb = tk.Checkbutton(
                cb_frame,
                text=label_text,
                variable=var,
                font=("Arial", 10, "bold"),
                anchor='w',
                bg="white"
            )
            cb.pack(anchor='w', fill=tk.X)

            # Description label
            desc_label = tk.Label(
                cb_frame,
                text=description,
                font=("Arial", 8),
                fg="#64748b",
                bg="white",
                anchor='w'
            )
            desc_label.pack(anchor='w', padx=(22, 0))

            checkboxes[event_id] = cb_frame  # Store the frame instead of just checkbox
        
        # Filter function - COMPLETELY FIXED VERSION
        def filter_checkboxes(*args):
            """Filter checkboxes based on search term"""
            # Check if window is still alive before accessing widgets
            if not window_alive['alive']:
                return
            
            try:
                search_term = local_search_var.get()
                if search_term == "🔍 Search event ID...":
                    search_term = ""
                
                for event_id, cb_frame in checkboxes.items():
                    description = self.get_event_description(event_id, prefer_sysmon=(event_id in sysmon_eids))
                    
                    # Search in both event ID and description
                    if (search_term.lower() in event_id.lower() or 
                        search_term.lower() in description.lower()):
                        cb_frame.pack(anchor='w', padx=10, pady=5, fill=tk.X)
                    else:
                        cb_frame.pack_forget()
                
                # Only update canvas if it exists, window is alive, AND canvas still exists
                if canvas and needs_scrollbar and window_alive['alive']:
                    try:
                        # Check if canvas widget still exists before accessing it
                        if canvas.winfo_exists():
                            scrollable_frame.update_idletasks()
                            canvas.configure(scrollregion=canvas.bbox("all"))
                        else:
                            window_alive['alive'] = False
                    except tk.TclError:
                        # Canvas has been destroyed
                        window_alive['alive'] = False
            except (tk.TclError, RuntimeError):
                # Widget destroyed, stop processing
                window_alive['alive'] = False
        
        # Store trace ID so we can remove it later
        trace_id = local_search_var.trace('w', filter_checkboxes)
        
        # Force scrollbar to be visible even with few items
        if canvas and needs_scrollbar:
            scrollable_frame.update_idletasks()
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        # Footer with selection count and apply button
        footer_frame = tk.Frame(filter_window, padx=15, pady=10, bg="#f8fafc")
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        selection_label = tk.Label(
            footer_frame,
            text=f"{len(self.selected_event_ids)} selected",
            bg="#f8fafc",
            fg="#64748b"
        )
        selection_label.pack(side=tk.LEFT)
        
        def apply_filter():
            """Apply the filter and close dialog"""
            window_alive['alive'] = False  # Mark window as closing
            # Remove the trace to prevent further callbacks
            try:
                local_search_var.trace_remove('write', trace_id)
            except:
                pass
            if canvas:
                canvas.unbind_all("<MouseWheel>")
            self.selected_event_ids = [
                event_id for event_id, var in check_vars.items() if var.get()
            ]
            self.update_filter_badge()
            self.apply_event_filter()
            filter_window.destroy()
        
        def on_window_close():
            """Handle window close event"""
            window_alive['alive'] = False
            # Remove the trace to prevent further callbacks
            try:
                local_search_var.trace_remove('write', trace_id)
            except:
                pass
            if canvas:
                canvas.unbind_all("<MouseWheel>")
            filter_window.destroy()
        
        # Bind window close event
        filter_window.protocol("WM_DELETE_WINDOW", on_window_close)
        
        tk.Button(
            footer_frame,
            text="Apply Filter",
            command=apply_filter,
            bg="#1e40af",
            fg="white",
            padx=20,
            pady=5
        ).pack(side=tk.RIGHT)
        
        # Don't auto-focus search - let user interact with checkboxes freely
    
    def apply_event_filter(self):
        """Apply Event ID filter, stacking on top of any active time filter."""
        if not self.all_results:
            return

        base_results = self.all_results
        display_path = self.selected_file if isinstance(self.selected_file, str) else f"{len(self.selected_file)} files from directory"

        if not self.selected_event_ids:
            output = self.generate_results(display_path, base_results)
            output += self.generate_timeline_summary(self.timeline_data)
            output += self.generate_malware_summary(self.malware_analysis)
        else:
            output = self.generate_filtered_results(display_path, base_results, self.selected_event_ids)

        # Prepend time filter header if time filter is also active
        if self.time_filter_active:
            try:
                start_formatted = datetime.fromisoformat(self.time_filter_start.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                end_formatted = datetime.fromisoformat(self.time_filter_end.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
            except:
                start_formatted = self.time_filter_start
                end_formatted = self.time_filter_end
            header = f"\n{'=' * 60}\n"
            header += f"TIME FILTERED RESULTS\n"
            header += f"{'=' * 60}\n"
            header += f"Time Range: {start_formatted} to {end_formatted}\n"
            header += f"Filtered Events: {base_results['total_events']} of {self.original_results['total_events']} original events\n"
            header += f"{'=' * 60}\n\n"
            output = header + output

        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)

        self.update_clear_filters_button()


    def _restore_original_results(self):
        """Restore all_results and related state to the unfiltered originals."""
        self.all_results = self.original_results
        self.malware_analysis = self.original_malware_analysis
        self.timeline_data = self.original_timeline_data
        self.deep_dive_data = self.original_deep_dive_data
        self.available_event_ids = self.safe_sort_event_ids(self.original_results['counts'].keys())

    def clear_time_filter(self):
        """Clear time filter and restore original results"""
        if not self.time_filter_active:
            return
        
        # Restore original results
        self._restore_original_results()
        self.time_filter_active = False
        self.time_filter_start = None
        self.time_filter_end = None
        
        # Update button states
        self.time_filter_btn.config(text="📅 Time Filtering")
        self.update_clear_filters_button()
        
        # Re-display — respect any active event ID filter
        display_path = self.selected_file if isinstance(self.selected_file, str) else f"{len(self.selected_file)} files from directory"
        if self.selected_event_ids:
            output = self.generate_filtered_results(display_path, self.original_results, self.selected_event_ids)
        else:
            output = self.generate_results(display_path, self.original_results)
            output += self.generate_timeline_summary(self.original_timeline_data)
            output += self.generate_malware_summary(self.original_malware_analysis)
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)
        
        messagebox.showinfo("Time Filter Cleared", "Restored all events from original analysis.")
    
    def clear_all_filters(self):
        """Clear both Event ID filter and Time filter"""
        # Clear time filter if active
        if self.time_filter_active:
            self.time_filter_active = False
            self.time_filter_start = None
            self.time_filter_end = None
            self.time_filter_btn.config(text="📅 Time Filtering")
            
            # Restore original results
            self._restore_original_results()
        
        # Clear Event ID filter
        self.selected_event_ids = []
        self.update_filter_badge()
        
        # Re-display full results
        display_path = self.selected_file if isinstance(self.selected_file, str) else f"{len(self.selected_file)} files from directory"
        output = self.generate_results(display_path, self.all_results)
        output += self.generate_timeline_summary(self.timeline_data)
        output += self.generate_malware_summary(self.malware_analysis)
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)
        
        # Update button state
        self.update_clear_filters_button()
    
    def update_clear_filters_button(self):
        """Enable/disable Clear Filters button based on whether any filters are active"""
        state = tk.NORMAL if (self.time_filter_active or self.selected_event_ids) else tk.DISABLED
        self.clear_filters_btn.config(state=state)
    
    def update_filter_badge(self):
        """Update filter badge display"""
        if self.selected_event_ids:
            self.filter_badge.config(text=str(len(self.selected_event_ids)))
            self.filter_badge.pack(side=tk.LEFT, padx=(5, 0))
            self.filter_btn.config(text=f"🔍 Filter by Event ID ({len(self.selected_event_ids)})")
        else:
            self.filter_badge.pack_forget()
            self.filter_btn.config(text="🔍 Filter by Event ID")
    
    @staticmethod
    def _sysmon_eids(results):
        """Return the set of event IDs that came from the Sysmon channel."""
        return {e.get('event_id', '') for e in results.get('sysmon_events', [])}

    @staticmethod
    def _eid_label(eid, sysmon_eids):
        """Return 'Event ID N (Sysmon)' or 'Event ID N' depending on channel."""
        suffix = " (Sysmon)" if eid in sysmon_eids else ""
        return f"Event ID {eid}{suffix}"

    def generate_filtered_results(self, file_path, results, selected_ids):
        """Generate filtered results showing only selected Event IDs"""
        # Handle both single file and directory/multiple files
        if isinstance(file_path, list):
            file_size = sum(os.path.getsize(f) / 1024 for f in file_path if os.path.isfile(f))
            file_name = f"{len(file_path)} files from directory"
            path_display = file_name
        elif isinstance(file_path, str) and os.path.isfile(file_path):
            file_size = os.path.getsize(file_path) / 1024
            file_name = os.path.basename(file_path)
            path_display = file_path
        else:
            # Display string like "4 files from directory"
            file_size = None
            file_name = file_path
            path_display = file_path
        
        filtered_counts = {eid: count for eid, count in results['counts'].items() if eid in selected_ids}
        filtered_total = sum(filtered_counts.values())
        
        output = f"""Analysis Results for: {file_name}
{"=" * 60}
🔍 FILTERED VIEW - Showing {len(selected_ids)} Event ID(s)

File Information:
- File Name: {file_name}
- File Path: {path_display}
- File Size: {f"{file_size:.2f} KB" if file_size is not None else "Multiple files"}
- Analysis Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Filter Summary:
- Total Events in File: {results['total_events']}
- Events Matching Filter: {filtered_total}
- Event IDs Filtered: {', '.join(selected_ids)}

Filtered Event ID Breakdown:
{"=" * 60}
"""
        
        sysmon_eids = self._sysmon_eids(results)

        for eid in self.safe_sort_event_ids(filtered_counts.keys()):
            count = filtered_counts[eid]
            output += f"{self._eid_label(eid, sysmon_eids)}: {count} occurrences\n"
        
        if not filtered_counts:
            output += "No events match the selected filter.\n"
        
        output += f"\n{'=' * 60}\n"
        output += f"Showing {filtered_total} of {results['total_events']} total events.\n"
        output += "Click 'Clear Filter' to see all results.\n"
        
        return output
    
    def generate_results(self, file_path, results):
        """Generate formatted results string"""
        # Handle display path for multiple files
        if "files from directory" in file_path:
            # Multiple files case - use display text
            file_display = file_path
            file_size_text = "Multiple files"
        else:
            # Single file case
            try:
                file_size = os.path.getsize(file_path) / 1024
                file_size_text = f"{file_size:.2f} KB"
                file_display = os.path.basename(file_path)
            except:
                file_size_text = "Unknown"
                file_display = file_path
        
        output = f"""Analysis Results for: {file_display}
{"=" * 60}

File Information:
- File(s): {file_display}
- File Path: {file_path if not "files from directory" in file_path else "Multiple files from directory"}
- File Size: {file_size_text}
- Analysis Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Event Summary:
- Total Events Parsed: {results['total_events']}
- Sysmon Events: {results['total_sysmon']}
- Security Events: {results['total_security']}
- System Events: {results['total_system']}
- Windows Defender Events: {results['total_defender']}
- Unique Event IDs Found: {len(results['counts'])}

Event ID Breakdown:
{"=" * 60}
"""
        
        # Build a set of event IDs that actually came from the Sysmon channel.
        # This is accurate regardless of ID range — avoids false (Sysmon) tags
        # on Windows System IDs that happen to share the same number.
        sysmon_eids = self._sysmon_eids(results)

        for eid in self.safe_sort_event_ids(results['counts'].keys()):
            count = results['counts'][eid]
            output += f"{self._eid_label(eid, sysmon_eids)}: {count} occurrences\n"

        output += f"\n{'=' * 60}\n"
        output += "Analysis Complete.\n"
        output += "Use 'Filter by Event ID' button to view specific events.\n"
        
        return output
    
    def generate_timeline_summary(self, timeline_data):
        """Generate formatted timeline summary"""
        if not timeline_data or not timeline_data.get('chronological_events'):
            return ""
        
        output = f"\n{'=' * 60}\nTIMELINE ANALYSIS\n{'=' * 60}\n"
        
        chronological = timeline_data['chronological_events']
        grouped = timeline_data['grouped_events']
        
        output += f"Total Events with Timestamps: {len(chronological)}\n"
        output += f"Time Windows (5 min intervals): {len(grouped)}\n\n"
        
        # Show first 10 events chronologically
        output += "First 10 Events (Chronological):\n"
        for i, event in enumerate(chronological[:10], 1):
            timestamp_str = event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            output += f"{i}. {timestamp_str} - Event ID: {event['event_id']}\n"
        
        if len(chronological) > 10:
            output += f"... and {len(chronological) - 10} more events\n"
        
        output += f"\n{'=' * 60}\n"
        output += "Time Window Analysis:\n"
        
        # Show top 5 busiest time windows
        sorted_windows = sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        
        output += "Top 5 Busiest Time Windows:\n"
        for i, (window_start, events) in enumerate(sorted_windows, 1):
            window_str = window_start.strftime('%Y-%m-%d %H:%M')
            output += f"{i}. {window_str} - {len(events)} events\n"
            
            # Show event ID breakdown for this window
            event_counts = Counter(e['event_id'] for e in events)
            top_events = event_counts.most_common(3)
            output += "   Most common: "
            output += ", ".join([f"Event {eid} ({count}x)" for eid, count in top_events])
            output += "\n"
        
        output += f"\n{'=' * 60}\n"
        
        return output
    
    def generate_malware_summary(self, malware_analysis):
        """Generate streamlined threat analysis summary for IT teams"""
        if not malware_analysis:
            return ""

        # Risk level indicators
        risk_icons = {
            "Critical": "CRITICAL",
            "High":     "HIGH",
            "Medium":   "MEDIUM",
            "Low":      "LOW",
        }
        risk_level = malware_analysis['risk_level']
        risk_display = risk_icons.get(risk_level, risk_level)

        output  = f"\n{'=' * 60}\n"
        output += f"THREAT ANALYSIS\n"
        output += f"{'=' * 60}\n"
        output += f"Overall Risk Level: {risk_display}\n"
        output += f"Total Threat Events: {malware_analysis['total_event_occurrences']} events across {malware_analysis['total_malware_events']} threat types\n"

        # ── Top threats ────────────────────────────────────────────────────
        output += f"\n{'─' * 60}\n"
        output += "Top Threats (by priority):\n"
        top_threats = malware_analysis.get('malware_indicators', [])[:5]

        for i, threat in enumerate(top_threats, 1):
            risk_icon = risk_icons.get(threat['matrix_risk'], threat['matrix_risk'])
            
            # Show impact and confidence for transparency
            impact = threat['impact']
            base_conf = threat['base_confidence']
            actual_conf = threat['actual_confidence']
            boost_reasons = threat.get('boost_reasons', [])
            
            # Build confidence display with specific boost explanation
            if actual_conf > base_conf and boost_reasons:
                # Join multiple reasons with " + " if both frequency and clustering
                reason_text = " + ".join(boost_reasons)
                conf_display = f"{base_conf}/4 → {actual_conf}/4 ({reason_text})"
            else:
                conf_display = f"{actual_conf}/4"
            
            eid_label = f"{threat['event_id']} (Sysmon)" if threat.get('event_type') == 'Sysmon' else threat['event_id']
            output += (
                f"\n{i}. [{risk_icon}] Event ID {eid_label} - {threat['threat']}\n"
                f"   Category: {threat['category']}\n"
                f"   Impact: {impact}/4 | Confidence: {conf_display}\n"
                f"   Occurrences: {threat['count']}\n"
            )


        # ── Top threat evidence ────────────────────────────────────────────
        if self.all_results:
            # Search directly across all parsed events — not just deep dive buckets
            # so Defender events, 1102, and other non-bucketed threats are included
            all_events = (
                self.all_results.get('sysmon_events', []) +
                self.all_results.get('security_events', []) +
                self.all_results.get('system_events', []) +
                self.all_results.get('defender_events', [])
            )

            output += f"\n{'-' * 60}\n"
            output += "Evidence for Top Threats:\n"

            SKIP_DEDUP_KEYS = {"computer"}

            def render_evidence(ev, eid):
                """Return a list of formatted field lines for one evidence dict."""
                lines = []
                for key, label in FIELD_LABELS.items():
                    value = ev.get(key)
                    if not value or str(value).strip().lower() in ("none", "", "-"):
                        continue
                    if key == "process" and eid in _CREDENTIAL_EIDS:
                        continue
                    display_val = str(value)
                    if display_val.startswith("S-1-") and key in ("added_user", "removed_user"):
                        label = label.replace("User", "Member SID")
                    if len(display_val) > 80:
                        display_val = display_val[:77] + "..."
                    lines.append(f"   {label:<16} {display_val}\n")
                return lines

            shown = 0
            for threat in top_threats:
                eid = threat['event_id']
                # Use only the events that actually passed indicator matching.
                # Falling back to EID-only filtering shows every process launch /
                # file create / registry write with that ID — the root cause of the
                # false-positive evidence display.
                matched = threat.get('matched_events')
                if matched is not None:
                    matches = [e for e in matched if e.get('evidence')]
                else:
                    # Legacy fallback for any indicator that predates matched_events
                    matches = [e for e in all_events if e.get('event_id') == eid and e.get('evidence')]
                if not matches:
                    continue

                # Build evidence lines for every occurrence, deduplicating on visible fields
                all_occurrence_lines = []
                seen_fingerprints = set()
                for ev in [m['evidence'] for m in matches]:
                    lines = render_evidence(ev, eid)
                    if not lines:
                        continue
                    # Fingerprint on the actual displayed content, not timestamp/computer
                    fp = tuple(sorted(
                        (k, v) for k, v in ev.items()
                        if k not in SKIP_DEDUP_KEYS and v and str(v).strip().lower() not in ("none", "", "-")
                    ))
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)
                    all_occurrence_lines.append(lines)

                if not all_occurrence_lines:
                    continue  # No useful fields for any occurrence — skip block

                risk_icon = risk_icons.get(threat['matrix_risk'], threat['matrix_risk'])
                eid_label = f"{eid} (Sysmon)" if threat.get('event_type') == 'Sysmon' else eid
                output += f"\n[{risk_icon}] {threat['threat']} (Event {eid_label}):\n"

                # Service installs (7045): each service is a distinct entry —
                # render them as grouped mini-blocks separated by a blank line.
                # Other high-count indicators (file drops, timestomping): cap at
                # 5 unique entries and show a summary for the rest.
                _SERVICE_EIDS  = {'7045'}
                _MAX_SHOW      = 5

                if eid in _SERVICE_EIDS:
                    # Group: one block per unique service path — deduplicate across
                    # attack waves so the same service/path pair only appears once.
                    seen_paths = set()
                    deduped_service_lines = []
                    for ev_raw, lines in zip([m['evidence'] for m in matches], all_occurrence_lines):
                        svc_path = str(ev_raw.get('service_path') or '').lower().strip()
                        if svc_path and svc_path in seen_paths:
                            continue
                        if svc_path:
                            seen_paths.add(svc_path)
                        deduped_service_lines.append(lines)
                    for i, lines in enumerate(deduped_service_lines):
                        if i > 0:
                            output += "\n"
                        output += "".join(lines)
                else:
                    total = len(all_occurrence_lines)
                    for lines in all_occurrence_lines[:_MAX_SHOW]:
                        output += "".join(lines)
                    if total > _MAX_SHOW:
                        output += f"   ... and {total - _MAX_SHOW} more unique occurrence(s) not shown\n"

                shown += 1

            if shown == 0:
                output += "  No evidence fields extracted for top threats.\n"

        output += f"\n{'=' * 60}\n"
        return output
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "No results yet. Select a log file and click Analyze.")
        self.results_text.config(state=tk.DISABLED)
        
        self.all_results = None
        self.malware_analysis = None
        self.assessment_data = None
        self.timeline_data = None
        self.deep_dive_data = None
        self.available_event_ids = []
        self.selected_event_ids = []
        
        # Reset time filter state
        self.time_filter_active = False
        self.time_filter_start = None
        self.time_filter_end = None
        self.original_results = None
        self.original_malware_analysis = None
        self.original_timeline_data = None
        self.original_deep_dive_data = None
        
        # Disable buttons
        self.filter_btn.config(state=tk.DISABLED)
        self.time_filter_btn.config(state=tk.DISABLED, text="📅 Time Filtering")
        self.report_btn.config(state=tk.DISABLED)
        self.clear_filters_btn.config(state=tk.DISABLED)
        self.update_filter_badge()
    
    def load_default_windows_logs(self):
        """Load default Windows event logs location"""
        default_path = r"C:\Windows\System32\winevt\Logs"
        
        if not os.path.exists(default_path):
            messagebox.showerror(
                "Path Not Found",
                f"Default Windows logs path not found:\n{default_path}\n\nThis feature requires Windows OS."
            )
            return
        
        try:
            # Only load supported log files
            files = [f for f in os.listdir(default_path) if _is_supported_log(f)]
            if not files:
                messagebox.showwarning(
                    "No Supported Files Found",
                    f"No supported log files found in:\n{default_path}\n\n"
                    "The tool scans for:\n"
                    "  • Security.evtx\n"
                    "  • System.evtx\n"
                    "  • Microsoft-Windows-Sysmon%4Operational.evtx\n"
                    "  • Microsoft-Windows-Windows Defender%4Operational.evtx"
                )
                return

            self.selected_file = [os.path.join(default_path, f) for f in files]
            self.file_path.set(f"{default_path} ({len(files)} .evtx file(s))")
            messagebox.showinfo(
                "Windows Logs Loaded",
                f"Loaded default Windows logs location:\n{default_path}\n\nFound {len(files)} log file(s).\n\nClick 'Analyze' to process."
            )
        except PermissionError:
            messagebox.showerror(
                "Permission Denied - Administrator Required",
                "Cannot access Windows logs folder.\n\n"
                "To access system logs, you must:\n"
                "1. Close this program\n"
                "2. Right-click the program executable\n"
                "3. Select 'Run as administrator'\n\n"
                "Alternative:\n"
                "Export logs from Event Viewer and use 'Browse File' instead:\n"
                "- Open Event Viewer (eventvwr.msc)\n"
                "- Right-click a log → 'Save All Events As...'\n"
                "- Save as .evtx file\n"
                "- Use Browse to select the exported file"
            )
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Error accessing Windows logs:\n{str(e)}\n\n"
                "Try running as Administrator or export logs manually from Event Viewer."
            )
    
    def open_time_filter_dialog(self):
        """Open Time Filtering dialog with quick presets and custom date range"""
        if not self.all_results:
            messagebox.showwarning("No Data", "Please analyze a log file first.")
            return
        
        # Create dialog window
        time_dialog = tk.Toplevel(self.root)
        time_dialog.title("Time Filtering")
        time_dialog.geometry("600x550")
        time_dialog.resizable(False, False)
        time_dialog.transient(self.root)
        time_dialog.grab_set()
        
        # Center the dialog
        time_dialog.update_idletasks()
        x = (time_dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (time_dialog.winfo_screenheight() // 2) - (550 // 2)
        time_dialog.geometry(f"+{x}+{y}")
        
        # Main frame
        main_frame = tk.Frame(time_dialog, padx=20, pady=20, bg="white")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="Select Time Window",
            font=("Arial", 14, "bold"),
            bg="white"
        )
        title_label.pack(pady=(0, 20))
        
        # Quick filters section
        quick_frame = tk.LabelFrame(main_frame, text="Quick Filters", padx=15, pady=15, bg="white")
        quick_frame.pack(fill=tk.X, pady=(0, 20))
        
        quick_btn_frame = tk.Frame(quick_frame, bg="white")
        quick_btn_frame.pack()
        
        tk.Button(quick_btn_frame, text="Last 24 Hours", command=lambda: apply_quick_filter(24), 
                 width=15, pady=5).pack(side=tk.LEFT, padx=5)
        tk.Button(quick_btn_frame, text="Last 7 Days", command=lambda: apply_quick_filter(168), 
                 width=15, pady=5).pack(side=tk.LEFT, padx=5)
        tk.Button(quick_btn_frame, text="Last 30 Days", command=lambda: apply_quick_filter(720), 
                 width=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Custom date range section
        custom_frame = tk.LabelFrame(main_frame, text="Custom Date Range", padx=15, pady=15, bg="white")
        custom_frame.pack(fill=tk.X)
        
        # From date/time
        from_label = tk.Label(custom_frame, text="From:", font=("Arial", 10, "bold"), bg="white")
        from_label.grid(row=0, column=0, sticky='w', pady=5)
        
        from_date_frame = tk.Frame(custom_frame, bg="white")
        from_date_frame.grid(row=1, column=0, columnspan=4, sticky='w', pady=5)
        
        from_month = ttk.Combobox(from_date_frame, values=list(range(1, 13)), width=10, state='readonly')
        from_month.current(self.last_from_month - 1)  # Index is 0-based
        from_month.pack(side=tk.LEFT, padx=(0, 5))
        tk.Label(from_date_frame, text="/", bg="white").pack(side=tk.LEFT)
        
        from_day = ttk.Combobox(from_date_frame, values=list(range(1, 32)), width=10, state='readonly')
        from_day.current(self.last_from_day - 1)  # Index is 0-based
        from_day.pack(side=tk.LEFT, padx=5)
        tk.Label(from_date_frame, text="/", bg="white").pack(side=tk.LEFT)
        
        from_year = ttk.Combobox(from_date_frame, values=list(range(2020, 2031)), width=10, state='readonly')
        from_year.current(self.last_from_year - 2020)  # Index based on range starting at 2020
        from_year.pack(side=tk.LEFT, padx=5)
        
        from_time_frame = tk.Frame(custom_frame, bg="white")
        from_time_frame.grid(row=2, column=0, columnspan=4, sticky='w', pady=5)
        
        from_hour = ttk.Combobox(from_time_frame, values=[f"{h:02d}" for h in range(24)], width=8, state='readonly')
        from_hour.current(self.last_from_hour)
        from_hour.pack(side=tk.LEFT, padx=(0, 5))
        tk.Label(from_time_frame, text=":", bg="white").pack(side=tk.LEFT)
        
        from_minute = ttk.Combobox(from_time_frame, values=[f"{m:02d}" for m in range(60)], width=8, state='readonly')
        from_minute.current(self.last_from_minute)
        from_minute.pack(side=tk.LEFT, padx=5)
        
        # To date/time
        to_label = tk.Label(custom_frame, text="To:", font=("Arial", 10, "bold"), bg="white")
        to_label.grid(row=3, column=0, sticky='w', pady=(15, 5))
        
        to_date_frame = tk.Frame(custom_frame, bg="white")
        to_date_frame.grid(row=4, column=0, columnspan=4, sticky='w', pady=5)
        
        to_month = ttk.Combobox(to_date_frame, values=list(range(1, 13)), width=10, state='readonly')
        to_month.current(self.last_to_month - 1)  # Index is 0-based
        to_month.pack(side=tk.LEFT, padx=(0, 5))
        tk.Label(to_date_frame, text="/", bg="white").pack(side=tk.LEFT)
        
        to_day = ttk.Combobox(to_date_frame, values=list(range(1, 32)), width=10, state='readonly')
        to_day.current(self.last_to_day - 1)  # Index is 0-based
        to_day.pack(side=tk.LEFT, padx=5)
        tk.Label(to_date_frame, text="/", bg="white").pack(side=tk.LEFT)
        
        to_year = ttk.Combobox(to_date_frame, values=list(range(2020, 2031)), width=10, state='readonly')
        to_year.current(self.last_to_year - 2020)  # Index based on range starting at 2020
        to_year.pack(side=tk.LEFT, padx=5)
        
        to_time_frame = tk.Frame(custom_frame, bg="white")
        to_time_frame.grid(row=5, column=0, columnspan=4, sticky='w', pady=5)
        
        to_hour = ttk.Combobox(to_time_frame, values=[f"{h:02d}" for h in range(24)], width=8, state='readonly')
        to_hour.current(self.last_to_hour)
        to_hour.pack(side=tk.LEFT, padx=(0, 5))
        tk.Label(to_time_frame, text=":", bg="white").pack(side=tk.LEFT)
        
        to_minute = ttk.Combobox(to_time_frame, values=[f"{m:02d}" for m in range(60)], width=8, state='readonly')
        to_minute.current(self.last_to_minute)
        to_minute.pack(side=tk.LEFT, padx=5)
        
        # Helper functions
        def apply_quick_filter(hours):
            """Apply quick time filter based on hours"""
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            apply_time_filter(start_time.isoformat(), end_time.isoformat())
            time_dialog.destroy()
        
        def apply_custom_range():
            """Apply custom date range filter"""
            try:
                start_str = f"{from_year.get()}-{int(from_month.get()):02d}-{int(from_day.get()):02d}T{from_hour.get()}:{from_minute.get()}:00"
                end_str = f"{to_year.get()}-{int(to_month.get()):02d}-{int(to_day.get()):02d}T{to_hour.get()}:{to_minute.get()}:59"
                
                start_time = datetime.fromisoformat(start_str)
                end_time = datetime.fromisoformat(end_str)
                
                if start_time >= end_time:
                    messagebox.showerror("Invalid Range", "Start time must be before end time.")
                    return
                
                # Save the values for next time
                self.last_from_month = int(from_month.get())
                self.last_from_day = int(from_day.get())
                self.last_from_year = int(from_year.get())
                self.last_from_hour = int(from_hour.get())
                self.last_from_minute = int(from_minute.get())
                self.last_to_month = int(to_month.get())
                self.last_to_day = int(to_day.get())
                self.last_to_year = int(to_year.get())
                self.last_to_hour = int(to_hour.get())
                self.last_to_minute = int(to_minute.get())
                
                apply_time_filter(start_time.isoformat(), end_time.isoformat())
                time_dialog.destroy()
            except ValueError as e:
                messagebox.showerror("Invalid Date", f"Invalid date/time values:\n{e}")
        
        def apply_time_filter(start_iso, end_iso):
            """Filter events by time range"""
            if not self.original_results:
                return
            
            try:
                # Parse start and end times
                start_dt = datetime.fromisoformat(start_iso.replace('Z', '+00:00'))
                end_dt = datetime.fromisoformat(end_iso.replace('Z', '+00:00'))
                
                # Store filter state
                self.time_filter_active = True
                self.time_filter_start = start_iso
                self.time_filter_end = end_iso
                
                # Filter each event list by time
                filtered_results = {
                    'total_events': 0,
                    'sysmon_events': [],
                    'security_events': [],
                    'system_events': [],
                    'defender_events': [],
                    'other_windows_events': [],
                    'total_sysmon': 0,
                    'total_security': 0,
                    'total_system': 0,
                    'total_defender': 0,
                    'total_other_windows': 0,
                    'counts': {},
                    'os_version': self.original_results.get('os_version', 'Unknown'),
                }
                
                # Filter each event list by time using a single helper
                def _filter_events(event_list):
                    out = []
                    for event in event_list:
                        ts = event['basic_info'].get('time_created', '')
                        if not ts:
                            continue
                        try:
                            if start_dt <= datetime.fromisoformat(ts.replace('Z', '+00:00')) <= end_dt:
                                out.append(event)
                        except (ValueError, TypeError):
                            continue
                    return out

                for key in ('sysmon_events', 'security_events', 'system_events',
                            'defender_events', 'other_windows_events'):
                    filtered_results[key] = _filter_events(self.original_results.get(key, []))
                
                # Update counts
                filtered_results['total_sysmon'] = len(filtered_results['sysmon_events'])
                filtered_results['total_security'] = len(filtered_results['security_events'])
                filtered_results['total_system'] = len(filtered_results['system_events'])
                filtered_results['total_defender'] = len(filtered_results['defender_events'])
                filtered_results['total_other_windows'] = len(filtered_results['other_windows_events'])
                filtered_results['total_events'] = (
                    filtered_results['total_sysmon'] +
                    filtered_results['total_security'] +
                    filtered_results['total_system'] +
                    filtered_results['total_defender']
                )
                # Rebuild event ID counts
                for event in (filtered_results['sysmon_events'] + 
                             filtered_results['security_events'] + 
                             filtered_results['system_events'] +
                             filtered_results['defender_events']):
                    # Event ID is at top level of event dictionary
                    event_id = event.get('event_id', 'Unknown')
                    filtered_results['counts'][event_id] = filtered_results['counts'].get(event_id, 0) + 1
                
                # Check if any events remain
                if filtered_results['total_events'] == 0:
                    try:
                        start_formatted = datetime.fromisoformat(start_iso.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                        end_formatted = datetime.fromisoformat(end_iso.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        start_formatted = start_iso
                        end_formatted = end_iso
                    
                    messagebox.showwarning(
                        "No Events Found",
                        f"No events found in the specified time range:\n\n"
                        f"From: {start_formatted}\n"
                        f"To: {end_formatted}\n\n"
                        f"Try expanding your time window."
                    )
                    return
                
                # Re-run analysis on filtered events
                from analysis import analyze_malware, extract_timeline, generate_assessment
                
                # Rebuild timeline from filtered event dicts
                all_events = (filtered_results['sysmon_events'] +
                             filtered_results['security_events'] +
                             filtered_results['system_events'] +
                             filtered_results['defender_events'])

                filtered_timeline = extract_timeline(all_events) if all_events else None
                filtered_malware = analyze_malware(filtered_results, filtered_timeline)
                filtered_deep_dive = self.extract_deep_dive_data(filtered_results)

                # Update displayed results
                self.all_results = filtered_results
                self.malware_analysis = filtered_malware
                self.assessment_data = generate_assessment(filtered_malware)
                self.timeline_data = filtered_timeline
                self.deep_dive_data = filtered_deep_dive
                
                # Update available event IDs
                self.available_event_ids = self.safe_sort_event_ids(filtered_results['counts'].keys())
                
                # Re-display results — respect any active event ID filter
                display_path = self.selected_file if isinstance(self.selected_file, str) else f"{len(self.selected_file)} files from directory"
                
                try:
                    start_formatted = datetime.fromisoformat(start_iso.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                    end_formatted = datetime.fromisoformat(end_iso.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    start_formatted = start_iso
                    end_formatted = end_iso

                header = f"\n{'=' * 60}\n"
                header += f"TIME FILTERED RESULTS\n"
                header += f"{'=' * 60}\n"
                header += f"Time Range: {start_formatted} to {end_formatted}\n"
                header += f"Filtered Events: {filtered_results['total_events']} of {self.original_results['total_events']} original events\n"
                header += f"{'=' * 60}\n\n"

                if self.selected_event_ids:
                    body = self.generate_filtered_results(display_path, filtered_results, self.selected_event_ids)
                else:
                    body = self.generate_results(display_path, filtered_results)
                    body += self.generate_timeline_summary(filtered_timeline)
                    body += self.generate_malware_summary(filtered_malware)

                output = header + body
                
                self.results_text.config(state=tk.NORMAL)
                self.results_text.delete(1.0, tk.END)
                self.results_text.insert(tk.END, output)
                self.results_text.config(state=tk.DISABLED)
                
                # Update time filter button to show it's active
                self.time_filter_btn.config(text="📅 Time Filtering (Active)")
                self.update_clear_filters_button()
                
                messagebox.showinfo(
                    "Time Filter Applied",
                    f"Showing {filtered_results['total_events']} events from the time range:\n\n"
                    f"From: {start_formatted}\n"
                    f"To: {end_formatted}\n\n"
                    f"Click 'Clear Filters' to restore all events."
                )
                
            except Exception as e:
                messagebox.showerror("Filter Error", f"Error applying time filter:\n{str(e)}")
        
        # Button frame
        button_frame = tk.Frame(main_frame, bg="white")
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        # Clear Time Filter button (left side)
        tk.Button(button_frame, text="Clear Time Filter", command=lambda: [self.clear_time_filter(), time_dialog.destroy()],
                 bg="white", fg="#374151", padx=20, pady=8, relief=tk.SOLID, borderwidth=1
                 ).pack(side=tk.LEFT)
        
        # Exit button (right side)
        tk.Button(button_frame, text="Exit", command=time_dialog.destroy,
                 bg="white", fg="#374151", padx=20, pady=8, relief=tk.SOLID, borderwidth=1
                 ).pack(side=tk.RIGHT)
        
        # Apply Custom Range button (right side, before Exit)
        tk.Button(button_frame, text="Apply Custom Range", command=apply_custom_range,
                 bg="#2563eb", fg="white", padx=20, pady=8, relief=tk.FLAT
                 ).pack(side=tk.RIGHT, padx=(0, 10))
    
    def collect_incident_context(self):
        """Collect incident context information via dialog"""
        # Create dialog window
        context_dialog = tk.Toplevel(self.root)
        context_dialog.title("Incident Context Information")
        context_dialog.geometry("700x600")
        context_dialog.resizable(False, False)
        context_dialog.transient(self.root)
        context_dialog.grab_set()
        
        # Center the dialog
        context_dialog.update_idletasks()
        x = (context_dialog.winfo_screenwidth() // 2) - (700 // 2)
        y = (context_dialog.winfo_screenheight() // 2) - (600 // 2)
        context_dialog.geometry(f"+{x}+{y}")
        
        # Result storage
        result = {'submitted': False}
        
        # Main frame
        main_frame = tk.Frame(context_dialog, padx=30, pady=20, bg="white")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title with close button
        title_frame = tk.Frame(main_frame, bg="white")
        title_frame.pack(fill=tk.X, pady=(0, 20))
        
        title_label = tk.Label(
            title_frame,
            text="Incident Context Information",
            font=("Arial", 16, "bold"),
            bg="white"
        )
        title_label.pack(side=tk.LEFT)
        
        close_btn = tk.Button(
            title_frame,
            text="✕",
            font=("Arial", 14),
            bg="white",
            fg="#64748b",
            relief=tk.FLAT,
            cursor="hand2",
            command=context_dialog.destroy
        )
        close_btn.pack(side=tk.RIGHT)

        CHAR_LIMIT = 500

        placeholders = {
            'reporter': "e.g., John Smith via email, Security Operations Center alert, etc.",
            'observed': "e.g., Multiple failed login attempts, unusual network traffic, suspicious process execution, etc.",
            'cause':    "e.g., Phishing attempt, credential compromise, malware infection, etc. (Leave blank if unknown)",
            'impact':   "e.g., System downtime, data breach risk, productivity loss, etc. (Leave blank if unknown)",
        }

        field_labels = [
            ("Reported by / How it was reported", 'reporter'),
            ("What was observed",                 'observed'),
            ("Possible cause (if known)",          'cause'),
            ("Impact to Business Operations (if known)", 'impact'),
        ]

        text_widgets = {}
        counter_labels = {}

        def make_field(parent, label_text, key):
            """Build one labelled text area with a live character counter."""
            header_row = tk.Frame(parent, bg="white")
            header_row.pack(fill=tk.X, pady=(0, 3))

            tk.Label(
                header_row,
                text=label_text,
                font=("Arial", 10),
                bg="white",
                fg="#374151"
            ).pack(side=tk.LEFT)

            counter = tk.Label(
                header_row,
                text=f"0 / {CHAR_LIMIT}",
                font=("Arial", 9),
                bg="white",
                fg="#6b7280"
            )
            counter.pack(side=tk.RIGHT)

            widget = tk.Text(
                parent, height=3, wrap=tk.WORD,
                font=("Arial", 10), relief=tk.SOLID, borderwidth=1
            )
            widget.pack(fill=tk.X, pady=(0, 15))
            widget.insert("1.0", placeholders[key])
            widget.config(fg='gray')

            text_widgets[key] = widget
            counter_labels[key] = counter

        for lbl, key in field_labels:
            make_field(main_frame, lbl, key)

        # ── Placeholder and counter logic ──────────────────────────────────────

        def get_real_text(key):
            """Return actual user text, empty string if still showing placeholder."""
            raw = text_widgets[key].get("1.0", "end-1c")
            return "" if raw == placeholders[key] else raw

        def update_counter(key, *_):
            length = len(get_real_text(key))
            over   = length > CHAR_LIMIT
            counter_labels[key].config(
                text=f"{length} / {CHAR_LIMIT}",
                fg="#dc2626" if over else "#6b7280"
            )
            refresh_generate_btn()

        def refresh_generate_btn():
            any_over = any(len(get_real_text(k)) > CHAR_LIMIT for k in placeholders)
            if any_over:
                generate_btn.config(
                    state=tk.DISABLED,
                    bg="#9ca3af",
                    cursor="arrow"
                )
            else:
                generate_btn.config(
                    state=tk.NORMAL,
                    bg="#2563eb",
                    cursor="hand2"
                )

        def on_focus_in(key):
            w = text_widgets[key]
            if w.get("1.0", "end-1c") == placeholders[key]:
                w.delete("1.0", tk.END)
                w.config(fg='black')

        def on_focus_out(key):
            w = text_widgets[key]
            if w.get("1.0", "end-1c").strip() == "":
                w.insert("1.0", placeholders[key])
                w.config(fg='gray')
                counter_labels[key].config(text=f"0 / {CHAR_LIMIT}", fg="#6b7280")
                refresh_generate_btn()

        for key, widget in text_widgets.items():
            widget.bind("<FocusIn>",  lambda e, k=key: on_focus_in(k))
            widget.bind("<FocusOut>", lambda e, k=key: on_focus_out(k))
            widget.bind("<KeyRelease>", lambda e, k=key: update_counter(k))

        # Button frame
        button_frame = tk.Frame(main_frame, bg="white")
        button_frame.pack(fill=tk.X, pady=(20, 0))

        def on_cancel():
            result['submitted'] = False
            context_dialog.destroy()

        def on_generate():
            result['submitted'] = True
            result['reporter'] = get_real_text('reporter')
            result['observed'] = get_real_text('observed')
            result['cause']    = get_real_text('cause')
            result['impact']   = get_real_text('impact')
            context_dialog.destroy()

        # Cancel button
        cancel_btn = tk.Button(
            button_frame,
            text="Cancel",
            command=on_cancel,
            font=("Arial", 10),
            bg="white",
            fg="#374151",
            padx=20,
            pady=8,
            relief=tk.SOLID,
            borderwidth=1,
            cursor="hand2"
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(10, 0))

        # Generate Report button (created before refresh_generate_btn is called above)
        generate_btn = tk.Button(
            button_frame,
            text="Generate Report",
            command=on_generate,
            font=("Arial", 10, "bold"),
            bg="#2563eb",
            fg="white",
            padx=20,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2"
        )
        generate_btn.pack(side=tk.RIGHT)
        
        # Wait for dialog to close
        context_dialog.wait_window()
        
        return result if result['submitted'] else None
    
    def extract_deep_dive_data(self, results):
        """
        Organize parsed event evidence into categories matching the
        Deep Dives sections of the report template (sections 6.1-6.6).

        Only includes individual events whose relevant field (TargetFilename,
        ImageLoaded, ImagePath, etc.) actually matches an indicator string from
        the CSV — the same check performed in analysis.py.  The CSV indicator
        strings are the sole source of truth; no exclusion lists are needed.
        """
        deep_dives = {
            'suspicious_execution': [],   # 6.1 - Sysmon:1, Security:4688, Security:4104
            'persistence_account':  [],    # 6.2a - account-based persistence (4720, 4698, 13)
            'persistence_services':  [],    # 6.2b - service-based persistence (7045)
            'credential_dumps':    [],    # 6.3a - Credential theft: lsass access, mimikatz, ppldump (EID 10/11 Credential Access)
            'credential_logon':    [],    # 6.3b - Auth/logon events: DCSync 4662, 4624, 4625, 4648, 4728
            'network_observations': [],   # 6.4 - Sysmon:3, Sysmon:22
            'enumeration':         [],    # 6.5 - AD/share enumeration: 5145, BloodHound, PowerView
            'av_protections': [],         # 6.6 - Defender events
            'removable_media': [],        # 6.7 - placeholder for future USB detection
        }

        EXECUTION_IDS   = {'1', '2', '4688', '4104', '11'}  # 2 = Sysmon file creation time changed (timestomping); 11 = Sysmon file created (malware dropper)
        PERSISTENCE_IDS = {'7045', '4698', '13', '4720'}  # 4720 = account created = persistence mechanism
        CREDENTIAL_IDS  = {'4625', '4728', '4732', '4740', '4771', '4726'}
        # These EIDs are too noisy/low-signal to show in credential deep dives
        # 4672: special privileges assigned — fires on every admin logon automatically
        CREDENTIAL_SKIP_IDS = {'4672'}
        NETWORK_IDS     = {'3', '22'}

        # Build a set of composite keys that actually fired in the threat analysis,
        # and a lookup of ALL indicator rows per composite key for per-event routing.
        # Format matches analysis.py: "EventType:EventID" e.g. "Sysmon:1", "Security:4625"
        # Note: multiple indicator rows can share the same composite key (e.g. EID 10 has
        # both a Credential Access row for lsass and a Lateral Movement row for non-lsass).
        # We store all of them so each event can be matched to the correct row.
        matched_keys = set()
        # composite_key -> list of (indicator_strings, category) tuples, one per CSV row
        indicator_rows = {}
        if self.malware_analysis:
            for indicator in self.malware_analysis.get('malware_indicators', []):
                etype = indicator.get('event_type', '')
                eid   = indicator.get('event_id', '')
                if etype and eid:
                    key = f"{etype}:{eid}"
                    matched_keys.add(key)
                    strings     = [s.lower() for s in indicator.get('indicators_to_check', [])]
                    category    = indicator.get('category', '')
                    finding     = indicator.get('finding', '')
                    description = indicator.get('description', '')
                    indicator_rows.setdefault(key, []).append((strings, category, finding, description))

        all_events = (
            results.get('sysmon_events', []) +
            results.get('security_events', []) +
            results.get('system_events', []) +
            results.get('defender_events', [])
        )

        for event in all_events:
            eid   = event.get('event_id', '')
            etype = event.get('type', '')
            evidence = event.get('evidence', {})
            if not evidence:
                continue

            composite_key = f"{etype}:{eid}"

            # Only include this event if its type:id combination matched a threat indicator.
            # Defender events always go through since they are inherently security-relevant.
            if etype != 'Defender' and composite_key not in matched_keys:
                continue

            # Drop evidence entries that carry no useful fields beyond timestamp and computer
            meaningful_keys = set(evidence.keys()) - {'timestamp', 'computer'}
            if not meaningful_keys:
                continue

            # Skip inherently noisy low-signal EIDs regardless of matched key
            if eid in CREDENTIAL_SKIP_IDS:
                continue

            # ── Per-event indicator re-validation ────────────────────────────────
            # The composite_key gate only checks whether *any* event of this type:id
            # fired a threat indicator — not whether *this specific event* matches.
            # Re-check each individual event's relevant field against the indicator
            # strings from the CSV.  The CSV strings are the sole source of truth —
            # no exclusion lists or process allowlists needed here.

            data         = event.get('data', {})
            rows_for_key = indicator_rows.get(composite_key, [])
            all_strings  = [s for (strings, *_) in rows_for_key for s in strings]

            # ── EID 2: Timestomping (no indicators — fires on every timestamp change) ──
            # Filter out known-noisy applications that legitimately rewrite timestamps.
            if eid == '2':
                image = os.path.basename(str(data.get('Image') or '')).lower()
                fp    = str(data.get('TargetFilename') or '').lower()
                _NOISY_PROCS = {
                    'discord.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe',
                    'brave.exe', 'code.exe', 'slack.exe', 'teams.exe',
                    'onedrive.exe', 'dropbox.exe', 'steamwebhelper.exe',
                    'steam.exe', 'epicgameslauncher.exe',
                }
                _NOISY_PATHS = ('\\appdata\\roaming\\discord\\', '\\appdata\\local\\discord\\',
                                '\\appdata\\local\\google\\chrome\\', '\\appdata\\local\\microsoft\\edge\\')
                if image in _NOISY_PROCS or any(p in fp for p in _NOISY_PATHS):
                    continue

            elif eid == '1':
                image_full  = str(data.get('Image') or '').lower()
                image       = os.path.basename(image_full)
                cmdline     = str(data.get('CommandLine') or '').lower()
                parent_full = str(data.get('ParentImage') or '').lower()
                parent      = os.path.basename(parent_full)

                _heuristic_match = False

                # Heuristic A: suspicious spawner → recon shell
                if parent in _EID1_SUSPICIOUS_SPAWNERS and image in _EID1_RECON_SHELLS:
                    if not any(parent_full.startswith(r) for r in _EID1_INSTALLER_ROOTS):
                        _heuristic_match = True
                    elif any(d in cmdline for d in _EID1_DISCOVERY_CMDS):
                        _heuristic_match = True

                # Heuristic B: MSI .tmp extraction chain
                if not _heuristic_match:
                    if parent_full.endswith('.tmp') or image_full.endswith('.tmp'):
                        if image in _EID1_RECON_SHELLS:
                            _heuristic_match = True
                    if parent in {'msiexec.exe'} and image in {
                        'cmd.exe', 'whoami.exe', 'powershell.exe', 'net.exe'
                    }:
                        if any(d in cmdline for d in _EID1_DISCOVERY_CMDS):
                            _heuristic_match = True

                # Fall back to CSV string match if heuristic didn't fire
                if not _heuristic_match:
                    if all_strings and not any(s in image or s in cmdline for s in all_strings):
                        continue

            elif eid == '8':
                target = os.path.basename(str(data.get('TargetImage') or '')).lower()
                if all_strings and not any(s in target for s in all_strings):
                    continue

            elif eid == '10':
                target = os.path.basename(str(data.get('TargetImage') or '')).lower()
                source = os.path.basename(str(data.get('SourceImage') or '')).lower()
                if all_strings and not any(s in target or s in source for s in all_strings):
                    continue

            elif eid == '11':
                fp    = str(data.get('TargetFilename', '')).lower()
                fname = os.path.basename(fp)
                image = os.path.basename(str(data.get('Image') or '')).lower()
                _EXEC_EXTS = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.cmd', '.hta', '.js', '.jar'}
                _PYINSTALLER_PATTERN = '\\temp\\_mei'
                matched_11 = False
                for ind in all_strings:
                    if ind.endswith('\\'):
                        if ind in fp and any(fp.endswith(ext) for ext in _EXEC_EXTS):
                            if _PYINSTALLER_PATTERN not in fp:
                                matched_11 = True
                                break
                    else:
                        # Keyword match (mimikatz etc.) — check filename only, not full path
                        if ind in fname:
                            matched_11 = True
                            break
                if all_strings and not matched_11:
                    continue

            elif eid == '12':
                reg_key = str(data.get('TargetObject', '')).lower()
                if all_strings and not any(s in reg_key for s in all_strings):
                    continue

            elif eid == '13':
                reg_key = str(data.get('TargetObject', '')).lower()
                if all_strings and not any(s in reg_key for s in all_strings):
                    continue
                # Mirror the suppression logic from analysis.py so the deep dive
                # doesn't display events that the scorer already rejected.
                _SERVICE_SENTINEL_DD = 'currentcontrolset\\services\\'
                if _SERVICE_SENTINEL_DD in reg_key:
                    # Only show \ImagePath keys — everything else under \services\
                    # (BTHPORT\FriendlyName, WinSock AppId_Catalog, etc.) is noise.
                    if not reg_key.endswith('\\imagepath'):
                        continue
                    _details_dd = str(data.get('Details') or '').lower().strip('"').strip()
                    _TRUSTED_SVC_ROOTS_DD = (
                        'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
                        'c:\\windows\\', 'c:\\program files\\',
                        'c:\\program files (x86)\\', 'c:\\programdata\\',
                        '\\systemroot\\', '\\??\\',
                        '%systemroot%\\', '%windir%\\',
                        '%programfiles%\\', '%programfiles(x86)%\\',
                        '%commonprogramfiles%\\', '%commonprogramfiles(x86)%\\',
                    )
                    _SUSPICIOUS_WIN_SUBDIRS_DD = (
                        'c:\\windows\\temp\\', 'c:\\windows\\tasks\\',
                    )
                    if not _details_dd:
                        continue
                    # Suspicious Windows subdirs override the broad c:\windows\ allow
                    if not any(_details_dd.startswith(s) for s in _SUSPICIOUS_WIN_SUBDIRS_DD):
                        if any(_details_dd.startswith(r) for r in _TRUSTED_SVC_ROOTS_DD):
                            continue
                    # Trusted writers: processes that are part of Windows or OEM firmware
                    # (wpbbin.exe = UEFI Platform Binary Table; services.exe = SCM).
                    _image_dd2 = str(data.get('Image') or '').lower()
                    _TRUSTED_SVC_WRITERS_DD = {
                        # wpbbin.exe is the UEFI Platform Binary Table executor —
                        # placed by firmware, not attacker-controllable without
                        # physical hardware access. Its service registrations are OEM-legitimate.
                        'c:\\windows\\system32\\wpbbin.exe',
                    }
                    if _image_dd2 in _TRUSTED_SVC_WRITERS_DD:
                        continue
                    # Per-user service instances (_XXXXXX suffix) — always suppress
                    _svc_name_dd = reg_key.split('\\services\\', 1)[-1].split('\\')[0]
                    if re.search(r'_[0-9a-f]{4,8}$', _svc_name_dd, re.IGNORECASE):
                        continue

            elif eid == '7':
                dll_path = str(data.get('ImageLoaded', '')).lower()
                _EXEC_EXTS = {'.dll'}
                matched_7 = False
                for ind in all_strings:
                    ind_l = ind.lower()
                    if ind_l.endswith('\\'):
                        if ind_l in dll_path and any(dll_path.endswith(e) for e in _EXEC_EXTS):
                            matched_7 = True
                            break
                    else:
                        if ind_l in dll_path:
                            matched_7 = True
                            break
                if all_strings and not matched_7:
                    continue

            elif eid == '7045':
                svc_path = str(data.get('ImagePath', '')).lower()
                if all_strings and not any(s in svc_path for s in all_strings):
                    continue

            elif eid == '3':
                image     = os.path.basename(str(data.get('Image') or '')).lower()
                dest_port = str(data.get('DestinationPort') or '')
                dest_ip   = str(data.get('DestinationIp') or '').lower()
                cmdline   = str(data.get('CommandLine') or '').lower()
                targeted  = f"{image} :{dest_port} {dest_ip} {cmdline}"
                if all_strings and not any(s in targeted for s in all_strings):
                    continue

            elif eid == '18':
                pipe = str(data.get('PipeName') or '').lower()
                if all_strings and not any(s in pipe for s in all_strings):
                    continue

            elif eid == '22':
                query = str(data.get('QueryName') or '').lower()
                if all_strings and not any(s in query for s in all_strings):
                    continue

            elif eid == '23':
                fp = str(data.get('TargetFilename') or '').lower()
                if all_strings and not any(s in fp for s in all_strings):
                    continue

            elif all_strings:
                TARGETED_FIELDS = {
                    'Image', 'CommandLine', 'TargetFilename', 'TargetObject',
                    'ImageLoaded', 'PipeName', 'QueryName', 'DestinationIp',
                    'DestinationPort', 'ImagePath', 'ServiceName',
                    'ThreatName', 'Path', 'ObjectName',
                    'ShareName', 'RelativeTargetName', 'IpAddress',
                }
                targeted = ' '.join(
                    str(v).lower() for k, v in data.items()
                    if v and k in TARGETED_FIELDS
                )
                if not any(s in targeted for s in all_strings):
                    continue

            # ── Row-matching: targeted field search for best indicator row ────
            TARGETED_FIELDS_FOR_ROW = {
                'Image', 'CommandLine', 'TargetFilename', 'TargetObject',
                'ImageLoaded', 'PipeName', 'QueryName', 'DestinationIp',
                'DestinationPort', 'ImagePath', 'ServiceName',
                'ThreatName', 'Path', 'ObjectName', 'SourceImage', 'TargetImage',
                'ShareName', 'RelativeTargetName', 'IpAddress',
            }
            ev_text = ' '.join(
                str(v).lower() for k, v in data.items()
                if v and k in TARGETED_FIELDS_FOR_ROW
            )

            rows_for_key = indicator_rows.get(composite_key, [])
            matched_category    = ''
            matched_finding     = ''
            matched_description = ''
            matched_any         = False
            fallback_cat         = ''
            fallback_finding     = ''
            fallback_description = ''
            fallback_set         = False
            # Pass 1: string-matched rows win over catch-all rows.
            for (strings, cat, finding, description) in rows_for_key:
                if strings and any(ind in ev_text for ind in strings):
                    matched_category    = cat
                    matched_finding     = finding
                    matched_description = description
                    matched_any         = True
                    break
                elif not strings and not fallback_set:
                    fallback_cat         = cat
                    fallback_finding     = finding
                    fallback_description = description
                    fallback_set         = True
            # Pass 2: no string match — use catch-all fallback
            if not matched_any and fallback_set:
                matched_category    = fallback_cat
                matched_finding     = fallback_finding
                matched_description = fallback_description
                matched_any         = True

            # Pass 3: EID 1 heuristic match — no CSV string matched but the
            # parent-chain heuristic already accepted this event above.
            # Use the first available row's metadata (always "Hacking Tool Launched"
            # / Execution) and annotate the description to explain the detection.
            if not matched_any and eid == '1' and rows_for_key:
                strings, cat, finding, description = rows_for_key[0]
                matched_category    = cat
                matched_finding     = finding
                matched_description = (
                    "Detected via parent-chain heuristic: a suspicious spawner process "
                    "or MSI-extracted binary launched a discovery/shell command. "
                    "The process name was not in the named-tool indicator list — "
                    "manual review of the process tree is recommended."
                )
                matched_any = True

            if not matched_any:
                continue

            category = matched_category

            # Route directly from the MITRE category of the matched indicator row.
            _CATEGORY_TO_BUCKET = {
                'Execution':            'suspicious_execution',
                'Defense Evasion':      'suspicious_execution',
                'Impact':               'suspicious_execution',
                'Credential Access':    'credential_dumps',
                'Privilege Escalation': 'credential_logon',
                'Lateral Movement':     'network_observations',
                'Command and Control':  'network_observations',
                'Enumeration':          'enumeration',
                'Discovery':            'enumeration',
                'Persistence':          'persistence_services',
            }

            bucket = _CATEGORY_TO_BUCKET.get(category, 'suspicious_execution')

            # Persistence: account-based EIDs go to account subsection
            if bucket == 'persistence_services' and eid in ('4720', '4698'):
                bucket = 'persistence_account'

            # DCSync and auth events are logon activity, not credential dumps
            if bucket == 'credential_dumps' and eid in ('4662', '4624', '4625', '4648', '4728', '4732', '4740', '4771'):
                bucket = 'credential_logon'

            # EID 10 (process access): only keep in credential_dumps if target is lsass.
            # PowerShell/whoami/explorer targets are lateral movement execution, not credential theft.
            if eid == '10' and bucket == 'credential_dumps':
                target = evidence.get('target_image', '') or ''
                if 'lsass' not in target.lower():
                    bucket = 'network_observations'

            if etype != 'Defender':
                evidence['_category'] = category
                evidence['_finding']      = matched_finding
                evidence['_description']  = matched_description
                deep_dives[bucket].append(evidence)
            elif etype == 'Defender':
                before = evidence.get('config_old_value', '')
                after  = evidence.get('config_new_value', '')

                # Drop no-op config events (before == after, nothing actually changed)
                if before and after and before == after:
                    continue

                # Drop incomplete config events that only have one side — parse artifacts
                # where the raw event only logged Old Value OR New Value but not both
                has_before = bool(before)
                has_after  = bool(after)
                is_partial_config = (has_before != has_after) and not evidence.get('feature_change')
                if is_partial_config:
                    continue

                # Drop re-enable events — a protection being turned back ON after
                # being disabled is the test script or admin restoring settings,
                # not an attacker action. The disable event is already captured.
                feature_change = evidence.get('feature_change', '')
                if feature_change and '-> Enabled' in feature_change:
                    continue

                # For 5007 config changes: only keep events where a
                # security-relevant protection key was turned off.
                # Two requirements must both be met:
                #   1. The after-value must contain (disabled) — parser.py stamps
                #      this on any Disable* key set to 0x1, or any non-Disable*
                #      key set to 0x0. Either way it means the feature is now OFF.
                #   2. The key name must be on the security-relevant allowlist —
                #      this prevents benign internal keys like ToastOrSsoTrigger,
                #      PlatformRollbackMethod, ServiceStartStates (update artefacts)
                #      from appearing as attacker activity.
                _SECURITY_RELEVANT_KEYS = {
                    # Real-time and scanning protections
                    'disablerealtimemonitoring', 'disablebehaviormonitoring',
                    'disableioavprotection', 'disablescriptscanning',
                    'disablearchivescanning', 'disableemailscanning',
                    'disableblockatfirstseen', 'disableintrusionpreventionsystem',
                    # AMSI / script protection
                    'amsienable', 'enablescriptblocklogging',
                    # Network / exploit protection
                    'enablenetworkprotection', 'puaprotection',
                    'mpenableexploitprotection',
                    # Cloud / sample submission
                    'mapsreporting', 'submitsamplesconsent',
                    # Controlled folder access (ransomware protection)
                    'enablecontrolledfolderaccess',
                    # Tamper protection
                    'tamperprotection',
                }
                if before or after:
                    if after and '(disabled)' not in after:
                        # Protection wasn't turned off — skip (re-enable or no-op)
                        continue
                    # Extract just the key name from "KeyName: value" format
                    after_key = after.split(':')[0].strip().lower().replace(' ', '') if after else ''
                    before_key = before.split(':')[0].strip().lower().replace(' ', '') if before else ''
                    relevant_key = after_key or before_key
                    if relevant_key and relevant_key not in _SECURITY_RELEVANT_KEYS:
                        # Benign internal Defender config key — not attacker-relevant
                        continue

                evidence['_category']    = matched_category
                evidence['_finding']     = matched_finding
                evidence['_description'] = matched_description
                deep_dives['av_protections'].append(evidence)
            else:
                # Catch-all: event matched a threat indicator but doesn't belong to a
                # specific category — surface it in suspicious execution so it always
                # appears in both the GUI and the report rather than being silently dropped.
                deep_dives['suspicious_execution'].append(evidence)

        return deep_dives

    def get_asset_scope_summary(self):
        """
        Extract asset and scope information from parsed events.
        Returns professional summary suitable for incident response reporting.
        
        IMPROVED: Better user categorization (privileged vs regular), 
        more relevant for incident triage, digestible for non-IT stakeholders.
        """
        if not self.all_results:
            return None
        
        hostnames = set()
        ips = set()
        all_eid3_ips = set()   # every external IP seen in Sysmon EID 3, flagged or not
        privileged_users = set()
        regular_users = set()
        domains = set()
        logon_types_raw = set()
        
        # Track time range
        earliest_time = None
        latest_time = None
        
        # Collect from all event types
        all_events = (
            self.all_results.get('sysmon_events', []) +
            self.all_results.get('security_events', []) +
            self.all_results.get('system_events', []) +
            self.all_results.get('defender_events', []) +
            self.all_results.get('windows_events', [])
        )
        
        # Well-known built-in/system accounts to exclude from user lists
        SYSTEM_ACCOUNTS = {
            '-', 'system', 'local service', 'network service', 'anonymous logon',
            'window manager', 'dwm-1', 'dwm-2', 'dwm-3', 'umfd-0', 'umfd-1',
            'font driver host', ''
        }

        for event in all_events:
            event_id = event.get('event_id', '')

            # Get timestamp and hostname from basic_info (always populated by parser)
            basic_info = event.get('basic_info', {})
            time_created = basic_info.get('time_created')
            if time_created:
                if earliest_time is None or time_created < earliest_time:
                    earliest_time = time_created
                if latest_time is None or time_created > latest_time:
                    latest_time = time_created

            # Hostname comes from basic_info['computer']
            computer = basic_info.get('computer', '')
            if computer:
                hostnames.add(computer)

            event_data = event.get('data', {})

            # --- Extract users, domains, IPs, logon types from event data fields ---

            # Logon events — collect logon type from 4625 too, but NOT the username (account doesn't exist)
            if event_id == '4625':
                logon_type = event_data.get('LogonType', '')
                if logon_type:
                    logon_types_raw.add(logon_type)

            # Logon events (Security EIDs 4624, 4648) — 4625 excluded from user/IP collection
            if event_id in ['4624', '4648', '4634', '4647', '4672']:
                username = event_data.get('TargetUserName') or event_data.get('SubjectUserName', '')
                domain = event_data.get('TargetDomainName') or event_data.get('SubjectDomainName', '')
                logon_type = event_data.get('LogonType', '')
                ip_addr = event_data.get('IpAddress', '')

                if username and username.lower() not in SYSTEM_ACCOUNTS and not username.endswith('$'):
                    # 4672 = special privileges → privileged
                    if event_id == '4672':
                        privileged_users.add(username)
                    else:
                        regular_users.add(username)

                if domain:
                    domains.add(domain)

                if logon_type:
                    logon_types_raw.add(logon_type)

                if ip_addr and ip_addr not in ['-', '::1', '127.0.0.1', '0.0.0.0']:
                    ips.add(ip_addr)

            # Privilege escalation / admin group membership (4732, 4728, 4756)
            if event_id in ['4732', '4728', '4756']:
                username = event_data.get('MemberName') or event_data.get('TargetUserName', '')
                if username and '\\' in username:
                    username = username.split('\\')[-1]
                if username and username.lower() not in SYSTEM_ACCOUNTS and not username.endswith('$'):
                    privileged_users.add(username)

            # Process creation (4688) — subject user
            if event_id == '4688':
                username = event_data.get('SubjectUserName', '')
                domain = event_data.get('SubjectDomainName', '')
                if username and username.lower() not in SYSTEM_ACCOUNTS and not username.endswith('$'):
                    regular_users.add(username)
                if domain:
                    domains.add(domain)

            # Sysmon events — user field
            if event.get('type') == 'Sysmon':
                username = event_data.get('User', '')
                if username:
                    # Format is usually DOMAIN\user
                    parts = username.split('\\')
                    if len(parts) == 2:
                        domain_part, user_part = parts
                        if domain_part:
                            domains.add(domain_part)
                        if user_part and user_part.lower() not in SYSTEM_ACCOUNTS and not user_part.endswith('$'):
                            regular_users.add(user_part)
                    elif username.lower() not in SYSTEM_ACCOUNTS:
                        regular_users.add(username)

                # Sysmon EID 3 = network connection — only collect destination IPs
                # from events the malware engine actually flagged as suspicious.
                # We iterate the indicator's matched_events list directly so each
                # IP is only included if it contributed to a real threat match,
                # rather than collecting all external traffic (346 IPs) or gating
                # on whether any Sysmon:3 indicator fired at all (old bug).
                # (The actual collection happens after the loop via malware_analysis.)
                # All external IPs (flagged or not) are captured in all_eid3_ips for context.
                if event_id == '3':
                    dest = event_data.get('DestinationIp', '')
                    if dest and dest not in ('-', '::1', '127.0.0.1', '0.0.0.0'):
                        all_eid3_ips.add(dest)

            # OS version — stored at results level, no per-event collection needed

        # Collect flagged external IPs from Sysmon EID 3 malware indicators.
        # Done once after the loop — no need to re-run per event.
        if self.malware_analysis:
            for ind in self.malware_analysis.get('malware_indicators', []):
                if ind.get('event_type') == 'Sysmon' and str(ind.get('event_id')) == '3':
                    for ev in ind.get('matched_events', []):
                        dest = ev.get('data', {}).get('DestinationIp', '')
                        if dest and dest not in ('-', '::1', '127.0.0.1', '0.0.0.0'):
                            ips.add(dest)
        # Clean up domains — remove junk values and hostnames
        junk_domains = {
            '-', '', 'WORKGROUP', 'NT AUTHORITY', 'Window Manager',
            'Font Driver Host', 'Builtin', 'MicrosoftAccount'
        }
        # Also remove anything that looks like a hostname (already shown in hostname field)
        cleaned_domains = set()
        for domain in domains:
            # Skip if it's junk
            if domain in junk_domains:
                continue
            # Skip if it matches any hostname (avoid duplication)
            if domain in hostnames:
                continue
            cleaned_domains.add(domain)
        
        domains = cleaned_domains

        # ==================== BUILD HUMAN-READABLE SUMMARY ====================
        
        # User summary with context
        user_summary_parts = []
        
        if privileged_users:
            priv_count = len(privileged_users)
            priv_list = ', '.join(sorted(privileged_users)[:5])
            if priv_count > 5:
                priv_list += f' ... and {priv_count - 5} more'
            user_summary_parts.append(f"<b>{priv_count} Administrator(s):</b> {priv_list}")
        
        if regular_users:
            reg_count = len(regular_users)
            reg_list = ', '.join(sorted(regular_users)[:5])
            if reg_count > 5:
                reg_list += f' ... and {reg_count - 5} more'
            user_summary_parts.append(f"<b>{reg_count} Regular User(s):</b> {reg_list}")
        
        if not privileged_users and not regular_users:
            users_display = 'No human user activity detected in logs'
        else:
            users_display = '<br/>'.join(user_summary_parts)
        
        # Categorize logon types for simpler reporting
        has_local = False
        has_remote = False
        has_network = False
        has_automated = False
        
        for lt in logon_types_raw:
            if lt in ['2', '7', '11']:  # Local interactive types
                has_local = True
            elif lt == '10':  # Remote Desktop
                has_remote = True
            elif lt == '3':  # Network access
                has_network = True
            elif lt in ['4', '5']:  # Automated
                has_automated = True
        
        # Build simple, clear summary
        access_summary = []
        if has_local:
            access_summary.append("Local access (user at keyboard)")
        if has_remote:
            access_summary.append("Remote Desktop connections")
        if has_network:
            access_summary.append("Network file/printer access")
        if has_automated:
            access_summary.append("Automated tasks/services")
        
        access_methods_text = ', '.join(access_summary) if access_summary else 'No login activity detected'
        
        # Get channel/provider info for "Tool Version"
        has_sysmon = self.all_results.get('total_sysmon', 0) > 0
        has_security = self.all_results.get('total_security', 0) > 0
        has_system = self.all_results.get('total_system', 0) > 0
        has_defender = self.all_results.get('total_defender', 0) > 0

        log_sources = []
        if has_sysmon:
            log_sources.append('Sysmon')
        if has_security:
            log_sources.append('Security')
        if has_system:
            log_sources.append('System')
        if has_defender:
            log_sources.append('Defender')
        
        return {
            'hostname': ', '.join(sorted(hostnames)) if hostnames else 'Unknown',
            'os_version': self.all_results.get('os_version') or 'Not detected in logs',
            'users_logged_in': users_display,
            'privileged_user_count': len(privileged_users),
            'regular_user_count': len(regular_users),
            'network_ips': _format_network_ips(ips, self.malware_analysis, total_observed=len(all_eid3_ips)),
            'ip_count': len(ips) if ips else 0,
            'domains': ', '.join(sorted(domains)) if domains else 'WORKGROUP',
            'access_methods': access_methods_text,
            'log_sources': ', '.join(log_sources) if log_sources else 'Windows Event Logs',
            'analysis_timeframe': f"{earliest_time[:19] if earliest_time and isinstance(earliest_time, str) else 'Unknown'} to {latest_time[:19] if latest_time and isinstance(latest_time, str) else 'Unknown'}",
            'total_events': self.all_results.get('total_events', 0)
        }
    
    def generate_pdf_report(self):
        """Generate a PDF report of the analysis results"""
        if not self.all_results or not self.selected_file:
            messagebox.showwarning("No Data", "Please analyze a log file first.")
            return
        
        # Collect incident context information
        incident_context = self.collect_incident_context()
        
        # If user cancelled the context dialog, don't generate report
        if incident_context is None:
            return
        
        # Extract asset and scope information from parsed events
        asset_scope = self.get_asset_scope_summary()
        
        try:
            # Ask user where to save the PDF
            default_name = f"triage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            save_path = filedialog.asksaveasfilename(
                title="Save PDF Report",
                defaultextension=".pdf",
                filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
                initialfile=default_name
            )
            
            if not save_path:
                return  # User cancelled
            
            # Import and call report module
            from report import create_test_pdf

            # Resolve file_path: if a directory was selected, selected_file is a list.
            # Pass the directory path (common parent) instead of the list.
            if isinstance(self.selected_file, list):
                report_file_path = os.path.dirname(self.selected_file[0]) if self.selected_file else None
            else:
                report_file_path = self.selected_file

            # Always report on the full unfiltered analysis — filters are a
            # view-only tool and must never affect the PDF output.  Use the
            # original_* snapshots taken at analysis time; fall back to the
            # live attributes only if no filter has ever been applied (i.e.
            # original_* were never stored separately from the live ones).
            report_results    = self.original_results          or self.all_results
            report_malware    = self.original_malware_analysis or self.malware_analysis
            report_timeline   = self.original_timeline_data    or self.timeline_data
            report_deep_dive  = self.original_deep_dive_data   or self.deep_dive_data
            from analysis import generate_assessment
            report_assessment = generate_assessment(report_malware) if report_malware else self.assessment_data

            # Generate the PDF with full unfiltered analysis data
            pdf_path = create_test_pdf(
                filename=save_path,
                file_path=report_file_path,
                results=report_results,
                malware_analysis=report_malware,
                timeline_data=report_timeline,
                incident_context=incident_context,
                asset_scope=asset_scope,
                deep_dive_data=report_deep_dive,
                assessment_data=report_assessment
            )
            
            messagebox.showinfo(
                "Success",
                f"PDF report generated successfully!\n\nSaved to:\n{pdf_path}"
            )
            
        except Exception as e:
            messagebox.showerror(
                "PDF Generation Error",
                f"Failed to generate PDF report:\n{str(e)}"
            )
    
    def exit_app(self):
        """Exit the application"""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            self.root.quit()
    
    def run(self):
        """Start the GUI event loop"""
        self.root.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
