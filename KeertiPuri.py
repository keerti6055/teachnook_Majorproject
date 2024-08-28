from scapy.all import sniff, IP, TCP, UDP
import matplotlib.pyplot as plt
from collections import defaultdict
from matplotlib.animation import FuncAnimation
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

traffic_data = defaultdict(int)
stop_sniffing = False
target_ip = ''
ips = []
counts = []
logfile = open("packet_log.txt", "a")

sniff_thread = threading.Thread(target=lambda: None)
sniff_thread.daemon = True

def packet_callback(packet):
    global stop_sniffing
    if stop_sniffing:
        return
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip == target_ip:
                traffic_data[src_ip] += 1
                log_message = f"{src_ip} -> {packet[IP].dst} | "
                if packet.haslayer(TCP):
                    log_message += f"TCP | Port: {packet[TCP].dport}"
                elif packet.haslayer(UDP):
                    log_message += f"UDP | Port: {packet[UDP].dport}"
                else:
                    log_message += f"Other | {packet[IP].dst}"
                logfile.write(log_message + "\n")
                update_text_area(log_message)
    except Exception as e:
        print(f"Error processing packet: {e}")

def update_plot(frame):
    ips.clear()
    counts.clear()
    ips.extend(traffic_data.keys())
    counts.extend(traffic_data.values())
    ax.clear()
    ax.bar(ips, counts, color='blue')
    ax.set_title(f"Live Network Traffic Patterns for {target_ip}")
    ax.set_xlabel("Source IP Address")
    ax.set_ylabel("Number of Packets")
    ax.tick_params(axis='x', rotation=45)

def start_capture():
    global sniff_thread, stop_sniffing, target_ip
    target_ip = target_ip_entry.get()
    if not target_ip:
        messagebox.showerror("Input Error", "Please enter a target IP address.")
        return
    stop_sniffing = False
    if not sniff_thread.is_alive():
        sniff_thread = threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'filter': f"ip src {target_ip}", 'store': 0})
        sniff_thread.daemon = True
        sniff_thread.start()
        status_var.set("Status: Capturing...")

def stop_capture():
    global stop_sniffing
    stop_sniffing = True
    status_var.set("Status: Stopped")

def update_text_area(text):
    log_text_area.insert(tk.END, text + "\n")
    log_text_area.yview(tk.END)

def on_closing():
    global stop_sniffing
    stop_sniffing = True
    logfile.close()
    root.destroy()

fig, ax = plt.subplots(figsize=(10, 6))

root = tk.Tk()
root.title("Network Traffic Monitor")

notebook = ttk.Notebook(root)
notebook.pack(pady=10, padx=10, expand=True)

capture_tab = ttk.Frame(notebook)
notebook.add(capture_tab, text="Packet Capture")

tk.Label(capture_tab, text="Enter Target IP Address:").pack(pady=5)
target_ip_entry = tk.Entry(capture_tab, width=40)
target_ip_entry.pack(pady=5)

status_var = tk.StringVar()
status_var.set("Status: Not Capturing")
status_label = tk.Label(capture_tab, textvariable=status_var)
status_label.pack(pady=5)

start_button = tk.Button(capture_tab, text="Start Capture", command=start_capture)
start_button.pack(pady=5)

stop_button = tk.Button(capture_tab, text="Stop Capture", command=stop_capture)
stop_button.pack(pady=5)

log_text_area = scrolledtext.ScrolledText(capture_tab, width=80, height=20)
log_text_area.pack(pady=5)

graph_tab = ttk.Frame(notebook)
notebook.add(graph_tab, text="Graph")

canvas = FigureCanvasTkAgg(fig, master=graph_tab)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def update_plot_canvas():
    update_plot(None)
    canvas.draw()
    root.after(1000, update_plot_canvas)

update_plot_canvas()

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
