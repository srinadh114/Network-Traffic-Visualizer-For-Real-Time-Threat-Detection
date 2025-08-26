# visualizer.py
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk  # ttk for potentially nicer styles
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from collections import defaultdict, deque
from scapy.all import sniff, Packet, TCP, UDP, ICMP, IP, ARP, Ether  # Keep these
from scapy.layers.inet6 import IPv6  # Use IPv6 for .nh check as ICMPv6Hdr import was problematic

import threading
import datetime
import csv
import time

# Import from your detector.py
from detector import analyze_packet  # Assuming detector.py is in the same directory

neon_colors = ['#39ff14', '#ff073a', '#00ffff', '#ff9ff3', '#feca57', '#5f27cd', '#10ac84', '#f368e0']


# --- Main Application Controller ---
class ApplicationController:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Visualizer & Threat Detector")
        self.root.geometry("1000x750")  # Adjusted size slightly
        self.root.configure(bg="black")

        self.current_user = None
        self.active_frame = None  # To keep track of the current page/frame

        # Store the NetworkGUI instance if it's active
        self.network_gui_instance = None

        self.show_login_page()

    def _clear_active_frame(self):
        if self.active_frame:
            # If NetworkGUI is active and sniffing, stop it
            if self.network_gui_instance and self.network_gui_instance.running:
                self.network_gui_instance.stop_sniffing()
            self.active_frame.destroy()
            self.active_frame = None
        self.network_gui_instance = None  # Clear instance when frame is cleared

    def show_login_page(self):
        self._clear_active_frame()
        self.active_frame = tk.Frame(self.root, bg="black")
        self.active_frame.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)

        tk.Label(self.active_frame, text="Network Security Visualizer", font=("Arial", 28, "bold"), bg="black",
                 fg="lime").pack(pady=(20, 10))
        tk.Label(self.active_frame, text="Login", font=("Arial", 20), bg="black", fg="white").pack(pady=(10, 20))

        form_frame = tk.Frame(self.active_frame, bg="black")
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Username:", font=("Arial", 12), bg="black", fg="white").grid(row=0, column=0, padx=5,
                                                                                                pady=10, sticky="w")
        self.username_entry = tk.Entry(form_frame, width=30, font=("Arial", 12))
        self.username_entry.grid(row=0, column=1, padx=5, pady=10)
        self.username_entry.insert(0, "admin")

        tk.Label(form_frame, text="Password:", font=("Arial", 12), bg="black", fg="white").grid(row=1, column=0, padx=5,
                                                                                                pady=10, sticky="w")
        self.password_entry = tk.Entry(form_frame, show="*", width=30, font=("Arial", 12))
        self.password_entry.grid(row=1, column=1, padx=5, pady=10)
        self.password_entry.insert(0, "password")  # Demo password

        tk.Button(self.active_frame, text="Login", command=self.handle_login, bg="#2ecc71", fg="black",
                  font=("Arial", 12, "bold"), width=15, height=1, relief=tk.RAISED).pack(pady=30)

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if username == "admin" and password == "password":  # Hardcoded for demo
            self.current_user = username
            self.show_home_page()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")
            self.password_entry.delete(0, tk.END)

    def show_home_page(self):
        self._clear_active_frame()
        self.active_frame = tk.Frame(self.root, bg="black")
        self.active_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        tk.Label(self.active_frame, text=f"Welcome, {self.current_user}!", font=("Arial", 20, "bold"), bg="black",
                 fg="lime").pack(pady=20)
        tk.Label(self.active_frame, text="Dashboard", font=("Arial", 16), bg="black", fg="white").pack(pady=(0, 30))

        btn_style = {"width": 30, "height": 2, "font": ("Arial", 12, "bold"), "relief": tk.RAISED, "borderwidth": 2,
                     "pady": 5}
        tk.Button(self.active_frame, text="Start Live Traffic Analysis", command=self.launch_visualizer_page,
                  bg="#3498db", fg="black", **btn_style).pack(pady=15)
        tk.Button(self.active_frame, text="Settings (Placeholder)", state=tk.DISABLED, bg="gray", **btn_style).pack(
            pady=15)
        tk.Button(self.active_frame, text="Logout", command=self.show_login_page, bg="#e74c3c", fg="black",
                  **btn_style).pack(pady=15)

    def launch_visualizer_page(self):
        self._clear_active_frame()
        self.active_frame = tk.Frame(self.root, bg="black")
        self.active_frame.pack(expand=True, fill=tk.BOTH)
        # Pass self (the ApplicationController instance) to NetworkGUI for navigation callbacks
        self.network_gui_instance = NetworkGUI(self.active_frame, self)


# --- NetworkGUI Class (Traffic Visualization Page) ---
class NetworkGUI:
    def __init__(self, master_frame, app_controller):
        self.master = master_frame
        self.app_controller = app_controller  # To call methods like app_controller.show_home_page()
        self.root_tk = master_frame.winfo_toplevel()  # Get the main Tk() root window for .after calls

        self.packets_for_export = []
        self.packet_counts_interval = defaultdict(int)
        self.total_packet_counts = defaultdict(int)
        self.protocols_to_track = ["TCP", "UDP", "ICMP", "Other"]
        self.protocol_history = defaultdict(lambda: deque(maxlen=60))  # 60 data points
        self.time_points = deque(maxlen=60)

        self.running = False
        self.paused = False
        self.start_time = 0
        self.sniff_thread = None

        self.protocol_colors = {
            "TCP": neon_colors[0], "UDP": neon_colors[1],
            "ICMP": neon_colors[2], "Other": neon_colors[3]
        }
        self._create_widgets()

    def _create_widgets(self):
        # Top frame for feeds and alerts
        top_feed_frame = tk.Frame(self.master, bg='black')
        top_feed_frame.pack(fill=tk.X, pady=(5, 0), padx=5)

        # Packet display
        self.packet_display_label = tk.Label(top_feed_frame, text="Live Packet Feed:", bg='black', fg='lime',
                                             font=("Arial", 10, "bold"), anchor="w")
        self.packet_display_label.pack(fill=tk.X)
        self.packet_display = scrolledtext.ScrolledText(top_feed_frame, height=7, bg='black', fg='lime',
                                                        font=("Courier", 9), relief=tk.SOLID, borderwidth=1)
        self.packet_display.pack(fill=tk.X, expand=True, pady=(0, 5))

        # Alerts display
        self.alerts_label = tk.Label(top_feed_frame, text="Real-Time Threat Alerts:", bg='black', fg='red',
                                     font=("Arial", 10, "bold"), anchor="w")
        self.alerts_label.pack(fill=tk.X)
        self.alerts_display = scrolledtext.ScrolledText(top_feed_frame, height=3, bg='black', fg='red',
                                                        font=("Courier", 9, "bold"), relief=tk.SOLID, borderwidth=1)
        self.alerts_display.pack(fill=tk.X, expand=True, pady=(0, 10))

        # Buttons frame
        self.button_frame = tk.Frame(self.master, bg='black')
        self.button_frame.pack(pady=5, fill=tk.X)

        btn_style = {"font": ("Arial", 10, "bold"), "relief": tk.RAISED, "borderwidth": 2, "padx": 10, "pady": 3}
        self.start_button = tk.Button(self.button_frame, text="Start", command=self.start_sniffing, bg="#2ecc71",
                                      fg="black", **btn_style)
        self.stop_button = tk.Button(self.button_frame, text="Stop", command=self.stop_sniffing, bg="#e74c3c",
                                     fg="black", **btn_style)
        self.pause_button = tk.Button(self.button_frame, text="Pause", command=self.toggle_pause, bg="#f39c12",
                                      fg="black", **btn_style)
        self.export_button = tk.Button(self.button_frame, text="Export CSV", command=self.export_csv, bg="#3498db",
                                       fg="black", **btn_style)
        self.back_button = tk.Button(self.button_frame, text="< Back to Home", command=self.go_back_to_home, bg="gray",
                                     fg="black", **btn_style)

        # Pack buttons with some spacing
        self.start_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.stop_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.pause_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.export_button.pack(side=tk.LEFT, padx=5, expand=True)
        self.back_button.pack(side=tk.LEFT, padx=5, expand=True)

        # Matplotlib plot
        self.figure = Figure(figsize=(5, 3), dpi=100, facecolor='black')  # Adjust figsize and dpi
        self.ax = self.figure.add_subplot(111)
        self.figure.subplots_adjust(left=0.1, right=0.95, top=0.9, bottom=0.15)  # Adjust subplot margins
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.master)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 0))  # Reduced bottom pady
        self.setup_plot_style()

    def go_back_to_home(self):
        if self.running:
            self.stop_sniffing()  # Important to stop background threads
        self.app_controller.show_home_page()  # Call back to the controller

    def setup_plot_style(self):
        self.ax.clear()
        self.ax.set_facecolor('black')
        self.ax.tick_params(axis='x', colors='white', labelsize=8)  # Smaller labelsize
        self.ax.tick_params(axis='y', colors='white', labelsize=8)
        for spine_pos in ['bottom', 'left', 'top', 'right']:
            self.ax.spines[spine_pos].set_color('white')
        self.ax.set_title("Live Protocol Distribution", color='white', fontsize=10)  # Smaller fontsize
        self.ax.set_xlabel("Time (s)", color='white', fontsize=9)
        self.ax.set_ylabel("Cumulative Count", color='white', fontsize=9)
        self.ax.grid(True, color='#444444', linestyle='--', linewidth=0.5)

    def start_sniffing(self):
        if self.running:
            messagebox.showinfo("Info", "Sniffing is already active.", parent=self.master)  # parent for messagebox
            return
        self.running = True
        self.paused = False
        self.pause_button.config(text="Pause", bg="#f39c12")

        self.packets_for_export = []
        self.packet_counts_interval = defaultdict(int)
        self.total_packet_counts = defaultdict(int)
        self.time_points.clear()
        for proto in self.protocols_to_track:
            self.protocol_history[proto].clear()
            self.protocol_history[proto].append(0)  # Initial 0 count

        self.packet_display.delete(1.0, tk.END)
        self.alerts_display.delete(1.0, tk.END)
        self.start_time = time.time()
        self.time_points.append(0)  # Initial t=0
        self.update_plot()

        self.sniff_thread = threading.Thread(target=self.sniff_packets_thread, daemon=True)
        self.sniff_thread.start()
        self.update_gui_loop()
        self.packet_display.insert(tk.END, "[INFO] Sniffing started...\n")

    def stop_sniffing(self):
        if not self.running:
            return
        self.running = False
        # Sniff thread should stop due to stop_filter or checks in process_packet
        # Wait a brief moment for thread to potentially exit if it's in a blocking call
        if self.sniff_thread and self.sniff_thread.is_alive():
            print("[DEBUG] Sniff thread still alive, trying to signal stop.")
            # Scapy's sniff might not be immediately interruptible this way if deep in C code.
            # The stop_filter is the primary mechanism.

        self.packet_display.insert(tk.END, "[INFO] Sniffing stopped.\n")
        self.packet_display.see(tk.END)

    def toggle_pause(self):
        if not self.running:
            messagebox.showinfo("Info", "Sniffing is not active.", parent=self.master)
            return
        self.paused = not self.paused
        state_msg = "[INFO] Sniffing paused.\n" if self.paused else "[INFO] Sniffing resumed.\n"
        btn_text = "Resume" if self.paused else "Pause"
        btn_bg = "#2ecc71" if self.paused else "#f39c12"
        self.pause_button.config(text=btn_text, bg=btn_bg)
        self.packet_display.insert(tk.END, state_msg)
        self.packet_display.see(tk.END)

    def sniff_packets_thread(self):
        try:
            sniff(prn=self.process_packet, store=False, stop_filter=lambda p: not self.running)
            print("[INFO] Sniff function exited.")
        except Exception as e:
            print(f"[ERROR] Error in sniff_packets_thread: {e}")
            # Potentially show error to user via GUI if appropriate
            # self.root_tk.after(0, lambda: messagebox.showerror("Sniffing Error", str(e), parent=self.master))

    def process_packet(self, packet: Packet):
        if not self.running or self.paused:
            return

        if len(self.packets_for_export) < 20000:  # Limit stored packets
            self.packets_for_export.append(packet)

        identified_protocol_for_graph = "Other"
        if packet.haslayer(TCP):
            identified_protocol_for_graph = "TCP"
        elif packet.haslayer(UDP):
            identified_protocol_for_graph = "UDP"
        elif packet.haslayer(ICMP) or \
                (packet.haslayer(IPv6) and packet[IPv6].nh == 58):  # ICMPv6 check
            identified_protocol_for_graph = "ICMP"
        self.packet_counts_interval[identified_protocol_for_graph] += 1

        try:  # Display packet summary
            now_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            src_ip_display, dst_ip_display = "N/A", "N/A"
            protocol_summary_part = packet.summary().split(' / ', 1)[-1]

            if IP in packet:
                src_ip_display, dst_ip_display = packet[IP].src, packet[IP].dst
                protocol_summary_part = packet.summary().split(' / ', 2)[
                    -1] if ' / ' in packet.summary() else packet.summary()
            elif IPv6 in packet:
                src_ip_display, dst_ip_display = packet[IPv6].src, packet[IPv6].dst
                protocol_summary_part = packet.summary().split(' / ', 2)[
                    -1] if ' / ' in packet.summary() else packet.summary()

            summary = f"[{now_str}] {src_ip_display} -> {dst_ip_display} | {protocol_summary_part}\n" if src_ip_display != "N/A" else f"[{now_str}] {packet.summary()}\n"

            # Schedule GUI update from the main thread
            self.root_tk.after(0, lambda s=summary: self._append_to_packet_display(s))

        except Exception as e:
            print(f"Error processing packet summary for display: {e} - Packet: {packet.summary()}")

        threat_message = analyze_packet(packet)  # From detector.py
        if threat_message:
            alert_now_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            full_alert_message = f"[{alert_now_str}] ALERT: {threat_message}\n"
            self.root_tk.after(0, lambda fam=full_alert_message: self._append_to_alerts_display(fam))

    def _append_to_packet_display(self, text):
        self.packet_display.insert(tk.END, text)
        if self.packet_display.yview()[1] > 0.9: self.packet_display.see(tk.END)

    def _append_to_alerts_display(self, text):
        original_fg = self.alerts_display.cget("fg")
        self.alerts_display.insert(tk.END, text)
        if self.alerts_display.yview()[1] > 0.9: self.alerts_display.see(tk.END)
        self.alerts_display.config(fg="yellow")
        self.root_tk.after(300, lambda: self.alerts_display.config(fg=original_fg))

    def update_gui_loop(self):
        if self.running and not self.paused:
            self.update_graph_data()  # This will call update_plot
        if self.running:
            self.root_tk.after(1000, self.update_gui_loop)

    def update_graph_data(self):
        if not self.running or self.paused: return

        current_relative_time = round(time.time() - self.start_time, 1)
        self.time_points.append(current_relative_time)

        for proto in self.protocols_to_track:
            self.total_packet_counts[proto] += self.packet_counts_interval.get(proto, 0)
            self.protocol_history[proto].append(self.total_packet_counts[proto])

        self.packet_counts_interval = defaultdict(int)
        self.root_tk.after(0, self.update_plot)  # Schedule plot update in main thread

    def update_plot(self):
        self.setup_plot_style()
        plotted_something = False
        for proto in self.protocols_to_track:
            counts = self.protocol_history.get(proto)
            if counts:
                min_len = min(len(self.time_points), len(counts))
                if min_len > 0:
                    time_data = list(self.time_points)[-min_len:]
                    count_data = list(counts)[-min_len:]
                    if any(c > 0 for c in count_data) or proto in ["TCP", "UDP", "ICMP"]:
                        self.ax.plot(time_data, count_data, label=proto,
                                     color=self.protocol_colors.get(proto, "#ffffff"), marker='o', markersize=2,
                                     linewidth=1)
                        plotted_something = True

        if plotted_something and self.ax.get_legend_handles_labels()[1]:
            legend = self.ax.legend(loc='upper left', fontsize=7, facecolor='#111111', labelcolor='white',
                                    framealpha=0.8)
            for text in legend.get_texts(): text.set_color('white')
        elif self.ax.get_legend() is not None:
            self.ax.get_legend().remove()

        self.canvas.draw()

    def export_csv(self):
        if not self.packets_for_export:
            messagebox.showwarning("No Data", "No packets captured to export.", parent=self.master)
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")],
                                                 title="Save Packet Data", parent=self.master)
        if not file_path: return

        try:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Source IP", "Dest IP", "Protocol", "Length", "Summary", "Alert"])
                for timestamp, pkt_data, alert_msg in self.generate_export_data():
                    writer.writerow([timestamp, pkt_data.get("src_ip", "N/A"), pkt_data.get("dst_ip", "N/A"),
                                     pkt_data.get("proto", "N/A"), pkt_data.get("len", "N/A"),
                                     pkt_data.get("summary", "N/A"), alert_msg if alert_msg else ""])
            messagebox.showinfo("Export Successful", f"Packet data exported to {file_path}", parent=self.master)
        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred: {e}", parent=self.master)

    def generate_export_data(self):
        for packet_obj in self.packets_for_export:
            timestamp_str = datetime.datetime.fromtimestamp(packet_obj.time).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            src_ip, dst_ip, proto_name, length_val = "N/A", "N/A", "N/A", "N/A"

            if IP in packet_obj:
                src_ip, dst_ip, length_val = packet_obj[IP].src, packet_obj[IP].dst, packet_obj[IP].len
            elif IPv6 in packet_obj:
                src_ip, dst_ip, length_val = packet_obj[IPv6].src, packet_obj[IPv6].dst, packet_obj[IPv6].plen

            if TCP in packet_obj:
                proto_name = "TCP"
            elif UDP in packet_obj:
                proto_name = "UDP"
            elif ICMP in packet_obj or (IPv6 in packet_obj and packet_obj[IPv6].nh == 58):
                proto_name = "ICMP"
            elif ARP in packet_obj:
                proto_name = "ARP"
            else:
                try:
                    proto_name = packet_obj.name
                except AttributeError:
                    proto_name = "Unknown"

            summary = packet_obj.summary()
            alert = analyze_packet(packet_obj)
            yield timestamp_str, {"src_ip": src_ip, "dst_ip": dst_ip, "proto": proto_name, "len": length_val,
                                  "summary": summary}, alert