import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, wrpcap, get_if_list
import threading
import subprocess
import os

# Global Variables
captured_packets = []
is_sniffing = False
pcap_file = "capture.pcap"

def start_sniffing():
    global is_sniffing, captured_packets
    interface = interface_var.get()
    packet_count = count_var.get()

    if not interface:
        messagebox.showerror("Error", "Please select a network interface.")
        return

    try:
        packet_count = int(packet_count)
    except ValueError:
        messagebox.showerror("Error", "Enter a valid number of packets.")
        return

    start_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)
    captured_packets = []
    is_sniffing = True
    log_box.delete(1.0, tk.END)
    log_box.insert(tk.END, f"[*] Started sniffing on {interface}...\n")

    def sniff_packets():
        global captured_packets
        captured_packets = sniff(iface=interface, count=packet_count,
                                 prn=lambda x: log_box.insert(tk.END, x.summary() + "\n"))
        wrpcap(pcap_file, captured_packets)
        log_box.insert(tk.END, f"[*] Capture complete and saved to {pcap_file}\n")
        start_btn.config(state=tk.NORMAL)
        open_btn.config(state=tk.NORMAL)

    t = threading.Thread(target=sniff_packets)
    t.daemon = True
    t.start()

def stop_sniffing():
    global is_sniffing
    if is_sniffing:
        is_sniffing = False
        log_box.insert(tk.END, "[*] Sniffing stopped.\n")
        start_btn.config(state=tk.NORMAL)

def open_wireshark():
    if not os.path.exists(pcap_file):
        messagebox.showerror("Error", f"{pcap_file} not found!")
        return
    subprocess.Popen(["wireshark", pcap_file])

# ------------------- GUI ------------------- #
root = tk.Tk()
root.title("GUI Packet Sniffer")
root.geometry("750x550")
root.config(bg="#0D1117")

style = ttk.Style()
style.configure("TLabel", foreground="white", background="#0D1117", font=("Consolas", 12))
style.configure("TButton", font=("Consolas", 12))
style.map("TButton", foreground=[('active', 'white')], background=[('active', '#112233')])

ttk.Label(root, text="Select Network Interface:").pack(pady=5)
interfaces = get_if_list()
interface_var = tk.StringVar()
interface_dropdown = ttk.Combobox(root, textvariable=interface_var, values=interfaces)
interface_dropdown.pack()

ttk.Label(root, text="Number of Packets to Capture:").pack(pady=5)
count_var = tk.StringVar(value="10")
ttk.Entry(root, textvariable=count_var).pack()

start_btn = ttk.Button(root, text="Start Sniffing", command=start_sniffing)
start_btn.pack(pady=10)

stop_btn = ttk.Button(root, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED)
stop_btn.pack(pady=5)

open_btn = ttk.Button(root, text="Open in Wireshark", command=open_wireshark, state=tk.DISABLED)
open_btn.pack(pady=5)

log_box = tk.Text(root, height=15, width=90, bg="#1E1E1E", fg="white", font=("Consolas", 10))
log_box.pack(pady=10)

root.mainloop()
