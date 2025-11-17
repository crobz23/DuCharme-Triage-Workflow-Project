import tkinter as tk
from gui import TriageToolGUI

def main():
    """Main entry point for the DuCharme Triage Assistant"""
    root = tk.Tk()
    app = TriageToolGUI(root)
    app.run()

if __name__ == "__main__":
    main()