# gui.py - FIXED: Scroll bar error when filter dialog closes
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import os

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
        
        # Create GUI elements
        self.create_widgets()
        
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
        file_frame = tk.LabelFrame(main_frame, text="Select Log File", padx=10, pady=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # File path entry
        file_entry = tk.Entry(file_frame, textvariable=self.file_path, state='readonly', width=60)
        file_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        
        # Browse button
        browse_btn = tk.Button(
            file_frame, 
            text="Browse...", 
            command=self.browse_file,
            bg="#3b82f6",
            fg="white",
            padx=15,
            pady=5
        )
        browse_btn.pack(side=tk.LEFT)
        
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
        self.filter_btn.pack(side=tk.LEFT)
        
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
        
        # Clear filter button
        self.clear_filter_btn = tk.Button(
            button_frame,
            text="Clear Filter",
            command=self.clear_filter,
            padx=15,
            pady=5,
            state=tk.DISABLED
        )
        self.clear_filter_btn.pack(side=tk.LEFT, padx=(0, 10))
        
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
            
    def analyze_log(self):
        """Trigger log analysis"""
        if not self.selected_file:
            messagebox.showwarning("No File Selected", "Please select a log file first.")
            return
            
        if not os.path.exists(self.selected_file):
            messagebox.showerror("File Not Found", "The selected file does not exist.")
            return
        
        # Clear previous results and filters
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Analyzing log file...\n")
        self.results_text.update()
        
        # Import parser and run analysis
        try:
            from parser import parse_evtx, analyze_events
            
            # Parse the file
            events = parse_evtx(self.selected_file)
            
            if not events:
                self.results_text.insert(tk.END, "\nError: No events found or file could not be parsed.\n")
                self.results_text.config(state=tk.DISABLED)
                return
            
            # Analyze events
            self.all_results = analyze_events(events)
            
            # Run malware analysis
            from analysis import analyze_malware, extract_timeline
            self.malware_analysis = analyze_malware(self.all_results)
            
            # Extract timeline from raw XML events
            # Need to get raw XML strings from events
            raw_events = []
            for event in events:
                try:
                    import xml.etree.ElementTree as ET
                    raw_events.append(ET.tostring(event, encoding='unicode'))
                except:
                    continue
            
            self.timeline_data = extract_timeline(raw_events)
            
            # Extract available Event IDs and enable filter and report button
            self.available_event_ids = sorted(self.all_results['counts'].keys(), key=lambda x: int(x))
            self.selected_event_ids = []
            self.filter_btn.config(state=tk.NORMAL)
            self.report_btn.config(state=tk.NORMAL)
            self.clear_filter_btn.config(state=tk.DISABLED)
            self.update_filter_badge()
            
            # Generate and display results (including malware analysis and timeline)
            output = self.generate_results(self.selected_file, self.all_results)
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
    
    def get_event_description(self, event_id):
        """Get description for a given Event ID"""
        # Windows Security Event IDs
        windows_events = {
        '1': 'A system error occurred',
        '104': 'An event log was cleared',
        '1100': 'Event logging was shut down',
        '1101': 'Audit events were dropped',
        '1102': 'An audit log was cleared',
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
        '4719': 'Audit policy was changed',
        '4720': 'A user account was created',
        '4722': 'A user account was enabled',
        '4723': 'A password change was attempted',
        '4724': 'A password reset was attempted',
        '4725': 'A user account was disabled',
        '4726': 'A user account was deleted',
        '4732': 'A user was added to a group',
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
        '4768': 'A login ticket was requested',
        '4769': 'A service ticket was requested',
        '4771': 'A login pre-authentication failed',
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
        '7040': 'A service startup type was changed',
        '7045': 'A service was installed',
        }
        
        # Sysmon Event IDs
        sysmon_events = {
            '1': 'A program was started',
            '2': 'A file timestamp was changed',
            '3': 'A network connection was made',
            '4': 'A monitoring service changed state',
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
            '16': 'A service configuration was changed',
            '17': 'A communication pipe was created',
            '18': 'A communication pipe was connected',
            '19': 'A system management filter was detected',
            '20': 'A system management consumer was detected',
            '21': 'A system management binding was detected',
            '22': 'A DNS query was made',
            '23': 'A file was deleted',
            '24': 'A clipboard change was detected',
            '25': 'A program was tampered with',
            '26': 'A file deletion was logged',
            '27': 'An executable file was blocked',
            '28': 'A file shredding was blocked',
            '29': 'An executable file was detected',
        }
        
        # Check both dictionaries
        if event_id in windows_events:
            return windows_events[event_id]
        elif event_id in sysmon_events:
            return sysmon_events[event_id]
        else:
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
        
        for event_id in self.available_event_ids:
            var = tk.BooleanVar(value=(event_id in self.selected_event_ids))
            check_vars[event_id] = var
            
            # Get description for this event
            description = self.get_event_description(event_id)
            
            # Create a frame for each checkbox + description
            cb_frame = tk.Frame(scrollable_frame, bg="white")
            cb_frame.pack(anchor='w', padx=10, pady=5, fill=tk.X)
            
            # Checkbox with event ID
            cb = tk.Checkbutton(
                cb_frame,
                text=f"Event ID {event_id}",
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
                    # Get description for searching
                    description = self.get_event_description(event_id)
                    
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
        """Apply Event ID filter to results"""
        if not self.all_results:
            return
        
        if not self.selected_event_ids:
            output = self.generate_results(self.selected_file, self.all_results)
            # Add timeline and malware analysis sections when showing full results
            output += self.generate_timeline_summary(self.timeline_data)
            output += self.generate_malware_summary(self.malware_analysis)
            self.clear_filter_btn.config(state=tk.DISABLED)
        else:
            output = self.generate_filtered_results(self.selected_file, self.all_results, self.selected_event_ids)
            self.clear_filter_btn.config(state=tk.NORMAL)
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, output)
        self.results_text.config(state=tk.DISABLED)
    
    def clear_filter(self):
        """Clear Event ID filter"""
        self.selected_event_ids = []
        self.update_filter_badge()
        self.apply_event_filter()
    
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
        
        file_size = os.path.getsize(file_path) / 1024
        
        filtered_counts = {eid: count for eid, count in results['counts'].items() if eid in selected_ids}
        filtered_total = sum(filtered_counts.values())
        
        output = f"""Analysis Results for: {os.path.basename(file_path)}
{"=" * 60}
🔍 FILTERED VIEW - Showing {len(selected_ids)} Event ID(s)

File Information:
- File Name: {os.path.basename(file_path)}
- File Path: {file_path}
- File Size: {file_size:.2f} KB
- Analysis Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Filter Summary:
- Total Events in File: {results['total_events']}
- Events Matching Filter: {filtered_total}
- Event IDs Filtered: {', '.join(selected_ids)}

Filtered Event ID Breakdown:
{"=" * 60}
"""
        
        for eid in sorted(filtered_counts.keys(), key=lambda x: int(x)):
            output += f"Event ID {eid}: {filtered_counts[eid]} occurrences\n"
        
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
        
        file_size = os.path.getsize(file_path) / 1024
        
        output = f"""Analysis Results for: {os.path.basename(file_path)}
{"=" * 60}

File Information:
- File Name: {os.path.basename(file_path)}
- File Path: {file_path}
- File Size: {file_size:.2f} KB
- Analysis Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Event Summary:
- Total Events Parsed: {results['total_events']}
- Windows Events: {results['total_windows']}
- Sysmon Events: {results['total_sysmon']}
- Unique Event IDs Found: {len(results['counts'])}

Event ID Breakdown:
{"=" * 60}
"""
        
        for eid in sorted(results['counts'].keys(), key=lambda x: int(x)):
            output += f"Event ID {eid}: {results['counts'][eid]} occurrences\n"
        
        critical_windows_ids = {
            '4624': 'Successful Logon',
            '4625': 'Failed Logon Attempt',
            '4672': 'Special Privileges Assigned',
            '4688': 'Process Creation',
            '1102': 'Audit Log Cleared'
        }
        
        output += f"\n{'=' * 60}\nCritical Windows Events Found:\n{'=' * 60}\n"
        
        found_critical = False
        for eid, description in critical_windows_ids.items():
            if eid in results['counts']:
                output += f"⚠️ Event ID {eid} ({description}): {results['counts'][eid]} occurrences\n"
                found_critical = True
        
        if not found_critical:
            output += "No critical Windows security events detected in this log.\n"
        
        if results['total_sysmon'] > 0:
            common_sysmon_ids = {
                '1': 'Process Creation',
                '2': 'File Creation Time Changed',
                '3': 'Network Connection',
                '5': 'Process Terminated',
                '7': 'Image Loaded',
                '8': 'CreateRemoteThread',
                '10': 'Process Access',
                '11': 'File Created',
                '13': 'Registry Value Set'
            }
            
            output += f"\n{'=' * 60}\nSysmon Events Found:\n{'=' * 60}\n"
            
            for eid, description in common_sysmon_ids.items():
                if eid in results['counts']:
                    output += f"🔍 Sysmon Event ID {eid} ({description}): {results['counts'][eid]} occurrences\n"
        
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
        """Generate formatted malware analysis summary"""
        if not malware_analysis:
            return ""
        
        output = f"\n{'=' * 60}\nMALWARE THREAT ANALYSIS\n{'=' * 60}\n"
        output += f"Risk Level: {malware_analysis['risk_level']}\n"
        output += f"Highest CVSS Score: {malware_analysis['highest_cvss_score']}\n"
        output += f"Malware Indicators Found: {malware_analysis['total_malware_events']}\n"
        output += f"Total Event Occurrences: {malware_analysis['total_event_occurrences']}\n\n"
        
        # Show top threats
        output += "Top Malware Threats:\n"
        from analysis import MalwareAnalyzer
        analyzer = MalwareAnalyzer()
        top_threats = analyzer.get_top_threats(malware_analysis, top_n=5)
        
        for i, threat in enumerate(top_threats, 1):
            output += f"{i}. Event ID {threat['event_id']} - {threat['category']}\n"
            output += f"   {threat['threat']}\n"
            output += f"   Occurrences: {threat['count']} | CVSS Score: {threat['cvss_score']}\n\n"
        
        # Show category summary
        output += "Threat Categories Detected:\n"
        category_summary = analyzer.get_category_summary(malware_analysis)
        for category, stats in category_summary.items():
            output += f"- {category}: {stats['unique_events']} event type(s), Highest CVSS: {stats['highest_cvss_score']}\n"
        
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
        self.filter_btn.config(state=tk.DISABLED)
        self.report_btn.config(state=tk.DISABLED)
        self.clear_filter_btn.config(state=tk.DISABLED)
        self.update_filter_badge()
    
    def generate_pdf_report(self):
        """Generate a PDF report of the analysis results"""
        if not self.all_results or not self.selected_file:
            messagebox.showwarning("No Data", "Please analyze a log file first.")
            return
        
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
            
            # Generate the PDF with analysis data, malware analysis, and timeline
            pdf_path = create_test_pdf(
                filename=save_path,
                file_path=self.selected_file,
                results=self.all_results,
                malware_analysis=self.malware_analysis,
                timeline_data=self.timeline_data
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