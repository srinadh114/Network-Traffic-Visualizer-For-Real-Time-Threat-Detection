# main.py
import tkinter as tk
from visualizer import ApplicationController # Make sure visualizer.py contains ApplicationController and NetworkGUI

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app_controller = ApplicationController(root)
        root.mainloop()
    except ImportError as e:
        print(f"ImportError: {e}. Please ensure all required libraries and project files are correctly placed.")
        print("You might need to run: pip install scapy matplotlib")
    except Exception as e:
        print(f"An unexpected error occurred in main: {e}")
        import traceback
        traceback.print_exc()