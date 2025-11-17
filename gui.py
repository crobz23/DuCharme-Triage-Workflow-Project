# gui.py
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from tkinter import ttk
import os

class TriageToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DuCharme Triage Assistant")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables
        self.file_path = tk.StringVar()
        self.selected_file = None
        
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
        
        # Analyze Button
        analyze_btn = tk.Button(
            main_frame,
            text="Analyze",
            command=self.analyze_log,
            bg="#1e40af",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=30,
            pady=10
        )
        analyze_btn.pack(pady=(0, 10))
        
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
        
        # Clear button
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
        
        # Clear previous results
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Analyzing log file...\n")
        self.results_text.update()
        
        # Import parser and run analysis
        try:
            from parser import parse_evtx, extract_event_ids
            from collections import Counter
            
            # Parse the file
            events = parse_evtx(self.selected_file)
            
            if not events:
                self.results_text.insert(tk.END, "\nError: No events found or file could not be parsed.\n")
                self.results_text.config(state=tk.DISABLED)
                return
            
            # Extract Event IDs
            event_ids = extract_event_ids(events)
            
            # Generate results
            results = self.generate_results(self.selected_file, events, event_ids)
            
            # Display results
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, results)
            self.results_text.config(state=tk.DISABLED)
            
        except Exception as e:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error during analysis:\n{str(e)}")
            self.results_text.config(state=tk.DISABLED)
            messagebox.showerror("Analysis Error", f"An error occurred:\n{str(e)}")
    
    def generate_results(self, file_path, events, event_ids):
        """Generate formatted results string"""
        from collections import Counter
        import os
        from datetime import datetime
        
        file_size = os.path.getsize(file_path) / 1024  # KB
        counts = Counter(event_ids)
        
        results = f"""Analysis Results for: {os.path.basename(file_path)}
{"=" * 60}

File Information:
- File Name: {os.path.basename(file_path)}
- File Path: {file_path}
- File Size: {file_size:.2f} KB
- Analysis Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Event Summary:
- Total Events Parsed: {len(events)}
- Unique Event IDs Found: {len(counts)}

Event ID Breakdown:
{"=" * 60}
"""
        
        # Add Event ID counts
        for eid, count in counts.most_common():
            results += f"Event ID {eid}: {count} occurrences\n"
        
        # Highlight critical Event IDs
        critical_ids = {
            '4624': 'Successful Logon',
            '4625': 'Failed Logon Attempt',
            '4672': 'Special Privileges Assigned',
            '4688': 'Process Creation',
            '1102': 'Audit Log Cleared'
        }
        
        results += f"\n{'=' * 60}\nCritical Events Found:\n{'=' * 60}\n"
        
        found_critical = False
        for eid, description in critical_ids.items():
            if eid in counts:
                results += f"⚠ Event ID {eid} ({description}): {counts[eid]} occurrences\n"
                found_critical = True
        
        if not found_critical:
            results += "No critical security events detected in this log.\n"
        
        results += f"\n{'=' * 60}\n"
        results += "Analysis Complete.\n"
        
        return results
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "No results yet. Select a log file and click Analyze.")
        self.results_text.config(state=tk.DISABLED)
    
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
