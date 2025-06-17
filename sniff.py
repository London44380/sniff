import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from scapy.all import sniff, IP, TCP, UDP, Raw
from threading import Thread
from collections import defaultdict
import time
import datetime
import sqlite3
import csv

# Created by London

# ========== CONFIGURATION ==========
WHITELIST = {"127.0.0.1"}  # Add your VPN IP here
params = {
    "L4_THRESHOLD": 100,
    "L7_THRESHOLD": 50
}

ip_packet_count_L4 = defaultdict(int)
ip_request_count_L7 = defaultdict(int)

# ========== DATABASE ==========
def init_db():
    conn = sqlite3.connect("ddos_logs.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            layer TEXT,
            message TEXT,
            source_ip TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_to_db(layer, message, source_ip):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect("ddos_logs.db")
    c = conn.cursor()
    c.execute("INSERT INTO logs (timestamp, layer, message, source_ip) VALUES (?, ?, ?, ?)",
              (timestamp, layer, message, source_ip))
    conn.commit()
    conn.close()

def export_logs():
    file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file:
        return
    conn = sqlite3.connect("ddos_logs.db")
    c = conn.cursor()
    c.execute("SELECT timestamp, layer, message, source_ip FROM logs")
    rows = c.fetchall()
    conn.close()

    with open(file, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Layer", "Message", "Source IP"])
        writer.writerows(rows)
    messagebox.showinfo("Export Complete", f"Logs saved to:\n{file}")

# ========== LOGGING ==========
def log_message(layer, message, source_ip):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
    full_message = f"{timestamp}{message}"
    logs_textbox.insert(tk.END, full_message + "\n")
    logs_textbox.see(tk.END)
    save_to_db(layer, message, source_ip)
    app.after(0, lambda: messagebox.showwarning(f"DDoS Alert - {layer}", message))

# ========== PACKET ANALYSIS ==========
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        if src_ip in WHITELIST:
            return

        if TCP in packet or UDP in packet:
            ip_packet_count_L4[src_ip] += 1
            if ip_packet_count_L4[src_ip] > params["L4_THRESHOLD"]:
                log_message("Layer 4", f"Possible DDoS attack from {src_ip}", src_ip)

        if TCP in packet and packet[TCP].dport == 80 and Raw in packet:
            if b"HTTP" in packet[Raw].load:
                ip_request_count_L7[src_ip] += 1
                if ip_request_count_L7[src_ip] > params["L7_THRESHOLD"]:
                    log_message("Layer 7", f"Excessive HTTP requests from {src_ip}", src_ip)

def reset_counters():
    while True:
        time.sleep(10)
        ip_packet_count_L4.clear()
        ip_request_count_L7.clear()

def start_sniffing():
    sniff(filter="ip", prn=packet_callback, store=0)

# ========== GUI ACTIONS ==========
def start_monitoring():
    try:
        params["L4_THRESHOLD"] = int(entry_l4.get())
        params["L7_THRESHOLD"] = int(entry_l7.get())
    except ValueError:
        messagebox.showerror("Error", "Please enter valid threshold values.")
        return

    btn_start.config(state='disabled')
    Thread(target=start_sniffing, daemon=True).start()
    Thread(target=reset_counters, daemon=True).start()
    label_status.config(text="Monitoring enabled", fg="#00ff00")

# ========== GUI SETUP (DARK THEME) ==========
init_db()

app = tk.Tk()
app.title("DDoS Detector • Sniff")
app.geometry("700x530")
app.configure(bg="#1e1e1e")
app.resizable(False, False)

# Theme colors
fg_color = "#ffffff"
bg_color = "#1e1e1e"
btn_color = "#2e2e2e"

tk.Label(app, text="Sniff Advanced DDoS Detection System", font=("Helvetica", 16, "bold"),
         fg=fg_color, bg=bg_color).pack(pady=10)

frame_controls = tk.Frame(app, bg=bg_color)
frame_controls.pack(pady=5)

tk.Label(frame_controls, text="L4 Threshold:", fg=fg_color, bg=bg_color).grid(row=0, column=0, padx=5)
entry_l4 = tk.Entry(frame_controls, width=6, bg=btn_color, fg=fg_color, insertbackground=fg_color)
entry_l4.insert(0, str(params["L4_THRESHOLD"]))
entry_l4.grid(row=0, column=1, padx=5)

tk.Label(frame_controls, text="L7 Threshold:", fg=fg_color, bg=bg_color).grid(row=0, column=2, padx=5)
entry_l7 = tk.Entry(frame_controls, width=6, bg=btn_color, fg=fg_color, insertbackground=fg_color)
entry_l7.insert(0, str(params["L7_THRESHOLD"]))
entry_l7.grid(row=0, column=3, padx=5)

btn_start = tk.Button(frame_controls, text="Start Monitoring", command=start_monitoring,
                      bg=btn_color, fg=fg_color, activebackground="#444", activeforeground=fg_color)
btn_start.grid(row=0, column=4, padx=10)

btn_export = tk.Button(frame_controls, text="Export Logs (CSV)", command=export_logs,
                       bg=btn_color, fg=fg_color, activebackground="#444", activeforeground=fg_color)
btn_export.grid(row=0, column=5, padx=10)

label_status = tk.Label(app, text="Monitoring not started", font=("Helvetica", 10),
                        fg="orange", bg=bg_color)
label_status.pack(pady=5)

logs_textbox = scrolledtext.ScrolledText(app, width=85, height=20, font=("Courier", 9),
                                         bg=bg_color, fg=fg_color, insertbackground=fg_color)
logs_textbox.pack(pady=10)

tk.Label(app, text="© 2025 - Created by London | lnk.bio/london443", font=("Helvetica", 8), fg="gray", bg=bg_color).pack(pady=5)

app.mainloop()
