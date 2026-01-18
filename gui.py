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
            
            # Extract available Event IDs and enable filter
            self.available_event_ids = sorted(self.all_results['counts'].keys(), key=lambda x: int(x))
            self.selected_event_ids = []
            self.filter_btn.config(state=tk.NORMAL)
            self.clear_filter_btn.config(state=tk.DISABLED)
            self.update_filter_badge()
            
            # Generate and display results
            output = self.generate_results(self.selected_file, self.all_results)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, output)
            self.results_text.config(state=tk.DISABLED)
            
        except Exception as e:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error during analysis:\n{str(e)}")
            self.results_text.config(state=tk.DISABLED)
            messagebox.showerror("Analysis Error", f"An error occurred:\n{str(e)}")
    
    def open_filter_dialog(self):
        """Open Event ID filter dialog"""
        if not self.available_event_ids:
            messagebox.showinfo("No Events", "No Event IDs available to filter.")
            return
        
        # Create filter dialog window
        filter_window = tk.Toplevel(self.root)
        filter_window.title("Filter by Event ID")
        filter_window.geometry("400x500")
        filter_window.resizable(False, False)
        
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
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=350)
            
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
            
            cb = tk.Checkbutton(
                scrollable_frame,
                text=f"Event ID {event_id}",
                variable=var,
                font=("Arial", 9),
                anchor='w',
                bg="white"
            )
            cb.pack(anchor='w', padx=10, pady=2, fill=tk.X)
            checkboxes[event_id] = cb
        
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
                
                for event_id, checkbox in checkboxes.items():
                    if search_term.lower() in event_id.lower():
                        checkbox.pack(anchor='w', padx=10, pady=2, fill=tk.X)
                    else:
                        checkbox.pack_forget()
                
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
        
        # Focus search entry
        search_entry.focus()
    
    def apply_event_filter(self):
        """Apply Event ID filter to results"""
        if not self.all_results:
            return
        
        if not self.selected_event_ids:
            output = self.generate_results(self.selected_file, self.all_results)
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
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "No results yet. Select a log file and click Analyze.")
        self.results_text.config(state=tk.DISABLED)
        
        self.all_results = None
        self.available_event_ids = []
        self.selected_event_ids = []
        self.filter_btn.config(state=tk.DISABLED)
        self.clear_filter_btn.config(state=tk.DISABLED)
        self.update_filter_badge()
    
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
