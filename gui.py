# gui.py
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import os

# Log files supported by the parser. When scanning a directory only these
# files will be loaded — everything else is ignored.
SUPPORTED_LOG_NAMES = {
    'security.evtx',
    'system.evtx',
    'microsoft-windows-sysmon%4operational.evtx',
    'microsoft-windows-windows defender%4operational.evtx',
}

def _is_supported_log(filename):
    """Return True if the filename matches a supported log."""
    return filename.lower() in SUPPORTED_LOG_NAMES


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
        self.timeline_data = None  # Store timeline data
        self.available_event_ids = []
        self.selected_event_ids = []
        self.filter_search_var = tk.StringVar()
        
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

            events = all_events
            
            # Show parsing summary if there were failures
            if failed_files:
                self.results_text.insert(tk.END, f"\nParsing Summary:\n")
                self.results_text.insert(tk.END, f"  Successfully parsed: {successful_files} file(s)\n")
                self.results_text.insert(tk.END, f"  Failed to parse: {len(failed_files)} file(s)\n\n")
            
            if not events:
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
            self.results_text.insert(tk.END, f"\nProceeding with {len(events)} events from {successful_files} file(s)...\n")
            self.results_text.update()
            
            # Analyze events
            self.all_results = analyze_events(events)
            
            # Extract timeline from raw XML events (needed for confidence boosting)
            # Need to get raw XML strings from events
            from analysis import analyze_malware, extract_timeline
            import xml.etree.ElementTree as ET
            
            raw_events = []
            for event in events:
                try:
                    raw_events.append(ET.tostring(event, encoding='unicode'))
                except:
                    continue
            
            self.timeline_data = extract_timeline(raw_events)
            
            # Run malware analysis with timeline data for confidence boosting
            self.malware_analysis = analyze_malware(self.all_results, self.timeline_data)
            
            # Store original unfiltered results for time filtering
            self.original_results = self.all_results
            self.original_malware_analysis = self.malware_analysis
            self.original_timeline_data = self.timeline_data
            
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
        # Windows Security Event IDs
        windows_events = {
        # System.evtx Events (user-friendly for non-IT people)
        '1': 'A system error occurred',
        '6': 'A driver was loaded',
        '7': 'A service was started or stopped',
        '10': 'A COM+ catalog error occurred',
        '11': 'A disk controller error was detected',
        '12': 'The Service Control Manager started',
        '13': 'The Service Control Manager stopped',
        '15': 'A disk device error occurred',
        '41': 'The computer restarted unexpectedly',
        '42': 'The computer is entering sleep mode',
        '51': 'A disk paging error occurred',
        '55': 'A file system corruption was detected',
        '104': 'The System log was cleared',
        '107': 'The computer woke up from sleep',
        '109': 'A kernel power transition occurred',
        '1001': 'A Windows Error Reporting crash occurred',
        '1014': 'A DNS client resolution timeout occurred',
        '1100': 'Event logging was shut down',
        '1101': 'Audit events were dropped',
        '1102': 'The Security audit log was cleared',
        '1530': 'A user profile could not be loaded',
        '6005': 'The Event Log service started',
        '6006': 'The Event Log service stopped',
        '6008': 'An unexpected system shutdown occurred',
        '6009': 'System boot information was logged',
        '6013': 'System uptime was recorded',
        '7000': 'A service failed to start',
        '7001': 'A service depends on another service that failed',
        '7009': 'A service timeout occurred during startup',
        '7011': 'A service timeout occurred during operation',
        '7022': 'A service hung on starting',
        '7023': 'A service terminated with an error',
        '7024': 'A service terminated with a service-specific error',
        '7026': 'A boot-start or system-start driver failed to load',
        '7030': 'A service was configured incorrectly',
        '7031': 'A service terminated unexpectedly',
        '7032': 'The Service Control Manager attempted corrective action',
        '7034': 'A service crashed unexpectedly',
        '7035': 'A service control was sent',
        '7036': 'A service entered running or stopped state',
        '7040': 'A service startup type was changed',
        '7045': 'A new service was installed',
        # Security Event IDs (technical format)
        '4103': 'A PowerShell script was executed',
        '4104': 'A PowerShell command was executed',
        '4105': 'A PowerShell script started',
        '4106': 'A PowerShell script stopped',
        '4616': 'The system time was changed',
        '4624': 'A user successfully logged in',
        '4625': 'A user failed to log in',
        '4634': 'A user session ended',
        '4647': 'A user logged out',
        '4648': 'A user logged in with different credentials',
        '4656': 'A file or folder was accessed',
        '4657': 'A system setting was changed',
        '4663': 'A file or folder was accessed',
        '4670': 'File or folder permissions were changed',
        '4672': 'A user was given special access rights',
        '4673': 'A privileged operation was attempted',
        '4688': 'A program was started',
        '4689': 'A program was closed',
        '4698': 'A scheduled task was created',
        '4699': 'A scheduled task was deleted',
        '4700': 'A scheduled task was enabled',
        '4701': 'A scheduled task was disabled',
        '4702': 'A scheduled task was updated',
        '4719': 'An audit policy was changed',
        '4720': 'A user account was created',
        '4722': 'A user account was enabled',
        '4723': 'A password change was attempted',
        '4724': 'A password reset was attempted',
        '4725': 'A user account was disabled',
        '4726': 'A user account was deleted',
        '4728': 'A user was added to a global security group',
        '4732': 'A user was added to a local security group',
        '4733': 'A user was removed from a group',
        '4735': 'A security group was changed',
        '4737': 'A global security group was changed',
        '4738': 'A user account was modified',
        '4740': 'A user account was locked',
        '4755': 'A universal security group was changed',
        '4756': 'A user was added to a universal group',
        '4757': 'A user was removed from a universal group',
        '4765': 'A security identifier history was added',
        '4767': 'A user account was unlocked',
        '4768': 'A Kerberos login ticket was requested',
        '4769': 'A Kerberos service ticket was requested',
        '4771': 'A Kerberos pre-authentication failed',
        '4776': 'A login attempt was validated',
        '4778': 'A remote session was reconnected',
        '4779': 'A remote session was disconnected',
        '4794': 'A password recovery mode was attempted',
        '5136': 'A directory object was modified',
        '5137': 'A directory object was created',
        '5140': 'A network folder was accessed',
        '5141': 'A directory object was deleted',
        '5142': 'A network folder was shared',
        '5145': 'A network folder access was checked',
        }
        
        # Sysmon Event IDs
        sysmon_events = {
            '1': 'A program was started',
            '2': 'A file timestamp was changed',
            '3': 'A network connection was made',
            '4': 'A Sysmon service state changed',
            '5': 'A program was closed',
            '6': 'A driver was loaded',
            '7': 'A library file was loaded',
            '8': 'A program injected code into another program',
            '9': 'A disk was accessed directly',
            '10': 'A program accessed another program',
            '11': 'A file was created',
            '12': 'A registry entry was created or deleted',
            '13': 'A registry value was set',
            '14': 'A registry entry was renamed',
            '15': 'A file stream was created',
            '16': 'A Sysmon configuration was changed',
            '17': 'A communication pipe was created',
            '18': 'A communication pipe was connected',
            '19': 'A WMI event filter was detected',
            '20': 'A WMI event consumer was detected',
            '21': 'A WMI event binding was detected',
            '22': 'A DNS query was made',
            '23': 'A file was deleted',
            '24': 'A clipboard change was detected',
            '25': 'A program was tampered with',
            '26': 'A file deletion was logged',
            '27': 'An executable file was blocked',
            '28': 'A file shredding was blocked',
            '29': 'An executable file was detected',
        }
        
        # Check both dictionaries, preferring Sysmon if the event came from that channel
        if prefer_sysmon:
            if event_id in sysmon_events:
                return sysmon_events[event_id]
            elif event_id in windows_events:
                return windows_events[event_id]
        else:
            if event_id in windows_events:
                return windows_events[event_id]
            # Do NOT fall back to Sysmon descriptions for Windows channel events
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

        sysmon_counts = {}
        for event in (self.all_results.get('sysmon_events', []) if self.all_results else []):
            eid = event.get('event_id', '')
            sysmon_counts[eid] = sysmon_counts.get(eid, 0) + 1

        for event_id in self.available_event_ids:
            var = tk.BooleanVar(value=(event_id in self.selected_event_ids))
            check_vars[event_id] = var

            # Get description for this event, using Sysmon descriptions where appropriate
            description = self.get_event_description(event_id, prefer_sysmon=(event_id in sysmon_counts))

            # Annotate only if this ID actually came from the Sysmon channel
            if event_id in sysmon_counts:
                label_text = f"Event ID {event_id} (Sysmon)"
            else:
                label_text = f"Event ID {event_id}"

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
                    # Get description using correct channel
                    description = self.get_event_description(event_id, prefer_sysmon=(event_id in sysmon_counts))
                    
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
            from datetime import datetime
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


    def clear_filter(self):
        """Clear Event ID filter"""
        self.selected_event_ids = []
        self.update_filter_badge()
        self.apply_event_filter()
    
    def clear_time_filter(self):
        """Clear time filter and restore original results"""
        if not self.time_filter_active:
            return
        
        # Restore original results
        self.all_results = self.original_results
        self.malware_analysis = self.original_malware_analysis
        self.timeline_data = self.original_timeline_data
        
        # Update available event IDs
        self.available_event_ids = self.safe_sort_event_ids(self.original_results['counts'].keys())
        
        # Clear time filter state
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
            self.all_results = self.original_results
            self.malware_analysis = self.original_malware_analysis
            self.timeline_data = self.original_timeline_data
            self.available_event_ids = self.safe_sort_event_ids(self.original_results['counts'].keys())
        
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
        if self.time_filter_active or self.selected_event_ids:
            self.clear_filters_btn.config(state=tk.NORMAL)
        else:
            self.clear_filters_btn.config(state=tk.DISABLED)
    
    def update_filter_badge(self):
        """Update filter badge display"""
        if self.selected_event_ids:
            self.filter_badge.config(text=str(len(self.selected_event_ids)))
            self.filter_badge.pack(side=tk.LEFT, padx=(5, 0))
            self.filter_btn.config(text=f"🔍 Filter by Event ID ({len(self.selected_event_ids)})")
        else:
            self.filter_badge.pack_forget()
            self.filter_btn.config(text="🔍 Filter by Event ID")
    
    def generate_filtered_results(self, file_path, results, selected_ids):
        """Generate filtered results showing only selected Event IDs"""
        from collections import Counter
        import os
        from datetime import datetime
        
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
        
        sysmon_counts = {}
        for event in results.get('sysmon_events', []):
            eid = event.get('event_id', '')
            sysmon_counts[eid] = sysmon_counts.get(eid, 0) + 1

        for eid in self.safe_sort_event_ids(filtered_counts.keys()):
            count = filtered_counts[eid]
            if eid in sysmon_counts:
                label = f"Event ID {eid} (Sysmon): {count} occurrences\n"
            else:
                label = f"Event ID {eid}: {count} occurrences\n"
            output += label
        
        if not filtered_counts:
            output += "No events match the selected filter.\n"
        
        output += f"\n{'=' * 60}\n"
        output += f"Showing {filtered_total} of {results['total_events']} total events.\n"
        output += "Click 'Clear Filter' to see all results.\n"
        
        return output
    
    def generate_results(self, file_path, results):
        """Generate formatted results string"""
        import os
        from datetime import datetime
        
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
        sysmon_counts = {}
        for event in results.get('sysmon_events', []):
            eid = event.get('event_id', '')
            sysmon_counts[eid] = sysmon_counts.get(eid, 0) + 1

        for eid in self.safe_sort_event_ids(results['counts'].keys()):
            count = results['counts'][eid]
            if eid in sysmon_counts:
                label = f"Event ID {eid} (Sysmon): {count} occurrences\n"
            else:
                label = f"Event ID {eid}: {count} occurrences\n"
            output += label

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
            from collections import Counter
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
        from analysis import MalwareAnalyzer
        analyzer = MalwareAnalyzer()
        top_threats = analyzer.get_top_threats(malware_analysis, top_n=5)

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
            
            output += (
                f"\n{i}. [{risk_icon}] Event ID {threat['event_id']} - {threat['threat']}\n"
                f"   Category: {threat['category']}\n"
                f"   Impact: {impact}/4 | Confidence: {conf_display}\n"
                f"   Occurrences: {threat['count']}\n"
            )

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
        self.timeline_data = None
        self.available_event_ids = []
        self.selected_event_ids = []
        
        # Reset time filter state
        self.time_filter_active = False
        self.time_filter_start = None
        self.time_filter_end = None
        self.original_results = None
        self.original_malware_analysis = None
        self.original_timeline_data = None
        
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
            from datetime import datetime, timedelta
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=hours)
            apply_time_filter(start_time.isoformat(), end_time.isoformat())
            time_dialog.destroy()
        
        def apply_custom_range():
            """Apply custom date range filter"""
            try:
                from datetime import datetime
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
            
            from datetime import datetime
            
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
                    'file_path': self.original_results.get('file_path', ''),
                    'file_size': self.original_results.get('file_size', 0),
                    'file_type': self.original_results.get('file_type', 'Unknown'),
                    'last_modified': self.original_results.get('last_modified', 'Unknown'),
                    'total_lines': 0,
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
                    'os_build': self.original_results.get('os_build', 'Unknown')
                }
                
                # Filter Sysmon events
                for event in self.original_results.get('sysmon_events', []):
                    event_time_str = event['basic_info'].get('time_created', '')
                    if event_time_str:
                        try:
                            event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                            if start_dt <= event_dt <= end_dt:
                                filtered_results['sysmon_events'].append(event)
                        except:
                            continue
                
                # Filter Security events
                for event in self.original_results.get('security_events', []):
                    event_time_str = event['basic_info'].get('time_created', '')
                    if event_time_str:
                        try:
                            event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                            if start_dt <= event_dt <= end_dt:
                                filtered_results['security_events'].append(event)
                        except:
                            continue
                
                # Filter System events
                for event in self.original_results.get('system_events', []):
                    event_time_str = event['basic_info'].get('time_created', '')
                    if event_time_str:
                        try:
                            event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                            if start_dt <= event_dt <= end_dt:
                                filtered_results['system_events'].append(event)
                        except:
                            continue
                
                # Filter Defender events
                for event in self.original_results.get('defender_events', []):
                    event_time_str = event['basic_info'].get('time_created', '')
                    if event_time_str:
                        try:
                            event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                            if start_dt <= event_dt <= end_dt:
                                filtered_results['defender_events'].append(event)
                        except:
                            continue
                
                # Filter Other Windows events
                for event in self.original_results.get('other_windows_events', []):
                    event_time_str = event['basic_info'].get('time_created', '')
                    if event_time_str:
                        try:
                            event_dt = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                            if start_dt <= event_dt <= end_dt:
                                filtered_results['other_windows_events'].append(event)
                        except:
                            continue
                
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
                filtered_results['total_lines'] = filtered_results['total_events']
                
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
                    # Format timestamps for better readability
                    from datetime import datetime
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
                from analysis import analyze_malware, extract_timeline
                import xml.etree.ElementTree as ET
                
                # Rebuild timeline from filtered events
                raw_events = []
                all_events = (filtered_results['sysmon_events'] + 
                             filtered_results['security_events'] + 
                             filtered_results['system_events'] +
                             filtered_results['defender_events'])
                
                for event in all_events:
                    try:
                        # Get the XML element from the event (stored in 'root' field)
                        if 'root' in event and hasattr(event['root'], 'tag'):
                            raw_events.append(ET.tostring(event['root'], encoding='unicode'))
                    except:
                        continue
                
                filtered_timeline = extract_timeline(raw_events) if raw_events else None
                filtered_malware = analyze_malware(filtered_results, filtered_timeline)
                
                # Update displayed results
                self.all_results = filtered_results
                self.malware_analysis = filtered_malware
                self.timeline_data = filtered_timeline
                
                # Update available event IDs
                self.available_event_ids = self.safe_sort_event_ids(filtered_results['counts'].keys())
                
                # Re-display results — respect any active event ID filter
                display_path = self.selected_file if isinstance(self.selected_file, str) else f"{len(self.selected_file)} files from directory"
                
                from datetime import datetime
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

        # Character limit notice
        tk.Label(
            main_frame,
            text="Each field has a 500 character limit in the report.",
            font=("Arial", 9),
            bg="white",
            fg="#6b7280"
        ).pack(anchor='w', pady=(0, 15))

        # Field 1: Reported by / How it was reported
        tk.Label(
            main_frame,
            text="Reported by / How it was reported",
            font=("Arial", 10),
            bg="white",
            fg="#374151"
        ).pack(anchor='w', pady=(0, 5))
        
        reporter_text = tk.Text(main_frame, height=3, wrap=tk.WORD, font=("Arial", 10), relief=tk.SOLID, borderwidth=1)
        reporter_text.pack(fill=tk.X, pady=(0, 15))
        reporter_text.insert("1.0", "e.g., John Smith via email, Security Operations Center alert, etc.")
        reporter_text.config(fg='gray')
        
        # Field 2: What was observed
        tk.Label(
            main_frame,
            text="What was observed",
            font=("Arial", 10),
            bg="white",
            fg="#374151"
        ).pack(anchor='w', pady=(0, 5))
        
        observed_text = tk.Text(main_frame, height=3, wrap=tk.WORD, font=("Arial", 10), relief=tk.SOLID, borderwidth=1)
        observed_text.pack(fill=tk.X, pady=(0, 15))
        observed_text.insert("1.0", "e.g., Multiple failed login attempts, unusual network traffic, suspicious process execution, etc.")
        observed_text.config(fg='gray')
        
        # Field 3: Possible cause (if known)
        tk.Label(
            main_frame,
            text="Possible cause (if known)",
            font=("Arial", 10),
            bg="white",
            fg="#374151"
        ).pack(anchor='w', pady=(0, 5))
        
        cause_text = tk.Text(main_frame, height=3, wrap=tk.WORD, font=("Arial", 10), relief=tk.SOLID, borderwidth=1)
        cause_text.pack(fill=tk.X, pady=(0, 15))
        cause_text.insert("1.0", "e.g., Phishing attempt, credential compromise, malware infection, etc. (Leave blank if unknown)")
        cause_text.config(fg='gray')
        
        # Field 4: Impact to Business Operations (if known)
        tk.Label(
            main_frame,
            text="Impact to Business Operations (if known)",
            font=("Arial", 10),
            bg="white",
            fg="#374151"
        ).pack(anchor='w', pady=(0, 5))
        
        impact_text = tk.Text(main_frame, height=3, wrap=tk.WORD, font=("Arial", 10), relief=tk.SOLID, borderwidth=1)
        impact_text.pack(fill=tk.X, pady=(0, 15))
        impact_text.insert("1.0", "e.g., System downtime, data breach risk, productivity loss, etc. (Leave blank if unknown)")
        impact_text.config(fg='gray')
        
        # Placeholder text handlers
        def on_focus_in(text_widget, placeholder):
            if text_widget.get("1.0", "end-1c") == placeholder:
                text_widget.delete("1.0", tk.END)
                text_widget.config(fg='black')
        
        def on_focus_out(text_widget, placeholder):
            if text_widget.get("1.0", "end-1c").strip() == "":
                text_widget.insert("1.0", placeholder)
                text_widget.config(fg='gray')
        
        # Bind focus events
        placeholders = {
            reporter_text: "e.g., John Smith via email, Security Operations Center alert, etc.",
            observed_text: "e.g., Multiple failed login attempts, unusual network traffic, suspicious process execution, etc.",
            cause_text: "e.g., Phishing attempt, credential compromise, malware infection, etc. (Leave blank if unknown)",
            impact_text: "e.g., System downtime, data breach risk, productivity loss, etc. (Leave blank if unknown)"
        }
        
        for widget, placeholder in placeholders.items():
            widget.bind("<FocusIn>", lambda e, w=widget, p=placeholder: on_focus_in(w, p))
            widget.bind("<FocusOut>", lambda e, w=widget, p=placeholder: on_focus_out(w, p))
        
        # Button frame
        button_frame = tk.Frame(main_frame, bg="white")
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        def on_cancel():
            result['submitted'] = False
            context_dialog.destroy()
        
        def on_generate():
            # Get values (strip placeholders if still present)
            reporter = reporter_text.get("1.0", "end-1c").strip()
            if reporter == placeholders[reporter_text]:
                reporter = ""
            
            observed = observed_text.get("1.0", "end-1c").strip()
            if observed == placeholders[observed_text]:
                observed = ""
            
            cause = cause_text.get("1.0", "end-1c").strip()
            if cause == placeholders[cause_text]:
                cause = ""
            
            impact = impact_text.get("1.0", "end-1c").strip()
            if impact == placeholders[impact_text]:
                impact = ""
            
            result['submitted'] = True
            result['reporter'] = reporter
            result['observed'] = observed
            result['cause'] = cause
            result['impact'] = impact
            
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
        
        # Generate Report button
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
        privileged_users = set()
        regular_users = set()
        domains = set()
        logon_types_raw = set()
        
        # Track OS info from events
        os_info = set()
        
        # Track time range
        earliest_time = None
        latest_time = None
        
        # Track security-relevant event IDs
        security_relevant_events = set()
        
        # Collect from all event types
        all_events = []
        all_events.extend(self.all_results.get('sysmon_events', []))
        all_events.extend(self.all_results.get('security_events', []))
        all_events.extend(self.all_results.get('system_events', []))
        all_events.extend(self.all_results.get('defender_events', []))
        all_events.extend(self.all_results.get('windows_events', []))
        
        # Well-known built-in/system accounts to exclude from user lists
        SYSTEM_ACCOUNTS = {
            '-', 'system', 'local service', 'network service', 'anonymous logon',
            'window manager', 'dwm-1', 'dwm-2', 'dwm-3', 'umfd-0', 'umfd-1',
            'font driver host', ''
        }

        for event in all_events:
            # Track security-relevant event IDs
            event_id = event.get('event_id', '')
            if event_id in ['4624', '4625', '4648', '4672', '4688', '4720', '4732']:
                security_relevant_events.add(event_id)
            
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

            # Logon events (Security EIDs 4624, 4625, 4648)
            if event_id in ['4624', '4625', '4648', '4634', '4647', '4672']:
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
            if event_id in ['4732', '4728', '4756', '4720']:
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

                # Sysmon EID 3 = network connection (has DestinationIp)
                if event_id == '3':
                    dest_ip = event_data.get('DestinationIp', '')
                    if dest_ip and dest_ip not in ['-', '::1', '127.0.0.1', '0.0.0.0']:
                        ips.add(dest_ip)

            # OS version — parser stores it in all_results (v4.0 approach)
            if event_data.get('OSVersion'):
                os_info.add(event_data['OSVersion'])
            if event_data.get('ProductName'):
                os_info.add(event_data['ProductName'])
        
                # Clean up domains - remove junk values and hostnames
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
        
        # Convert logon types to human-readable, non-technical descriptions
        logon_type_descriptions = []
        logon_type_map = {
            '0': 'System',
            '2': 'Local (at keyboard)',
            '3': 'Network (file sharing)',
            '4': 'Scheduled task',
            '5': 'Windows service',
            '7': 'Screen unlock',
            '10': 'Remote Desktop',
            '11': 'Offline login'
        }
        
        # Categorize for simpler reporting
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
        
        log_sources = []
        if has_sysmon:
            log_sources.append('Sysmon')
        if has_security:
            log_sources.append('Security')
        if has_system:
            log_sources.append('System')
        
        return {
            'hostname': ', '.join(sorted(hostnames)) if hostnames else 'Unknown',
            'os_version': self.all_results.get('os_version') or 'Not detected in logs',
            'users_logged_in': users_display,
            'privileged_user_count': len(privileged_users),
            'regular_user_count': len(regular_users),
            'network_ips': ', '.join(sorted(ips)[:10]) if ips else 'No external network activity detected',
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
            from datetime import datetime
            
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

            # Generate the PDF with all analysis data
            pdf_path = create_test_pdf(
                filename=save_path,
                file_path=report_file_path,
                results=self.all_results,
                malware_analysis=self.malware_analysis,
                timeline_data=self.timeline_data,
                incident_context=incident_context,
                asset_scope=asset_scope  # ← NEW: Asset & Scope data
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
    app = TriageToolGUI(root)
    app.run()
