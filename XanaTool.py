# A code created by ViperFSFA
# Do NOT sell or modify this code, Unethical use is Prohibited!!
# Hacktheplanet

import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS, ICMP, send
import threading
from datetime import datetime
import binascii
import socket
import re
import sys
import traceback

root = tk.Tk()
root.title("XanaTool BY ViperFSFA - Community edition")
root.geometry("1400x900")  
root.configure(bg="#0d0d0d")
root.resizable(True, True)

style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook", background="#0d0d0d", borderwidth=0, tabmargins=0)
style.configure("TNotebook.Tab", 
                background="#1a1a1a", 
                foreground="#ff2d2d", 
                padding=[30, 15], 
                font=("Orbitron", 16, "bold"), 
                bordercolor="#ff2d2d", 
                relief="flat")
style.map("TNotebook.Tab", 
          background=[("selected", "#ff2d2d"), ("active", "#2a2a2a")], 
          foreground=[("selected", "#00ffff"), ("active", "#ff6666")], 
          expand=[("selected", [0, 0, 0, 2])])
style.configure("TButton", 
                background="#ff2d2d", 
                foreground="#ffffff", 
                font=("Orbitron", 13, "bold"), 
                borderwidth=0, 
                padding=10, 
                relief="flat")
style.map("TButton", 
          background=[("active", "#00ffff")],  
          foreground=[("active", "#0d0d0d")])
style.configure("TLabel", 
                background="#0d0d0d", 
                foreground="#ff2d2d", 
                font=("Orbitron", 14))

notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

tab1 = tk.Frame(notebook, bg="#0d0d0d")
notebook.add(tab1, text="Packet Sniffer")

packet_frame = tk.Frame(tab1, bg="#0d0d0d", relief="flat", borderwidth=3, highlightbackground="#00ffff")
packet_frame.pack(fill="both", expand=True, padx=20, pady=20)

packet_list = tk.Listbox(packet_frame, 
                         bg="#1a1a1a", 
                         fg="#e6e6e6", 
                         font=("JetBrains Mono", 13), 
                         selectbackground="#ff2d2d", 
                         selectforeground="#00ffff", 
                         highlightthickness=3, 
                         highlightcolor="#ff6666", 
                         borderwidth=0, 
                         height=30)
packet_list.pack(fill="both", expand=True, side=tk.LEFT)

scrollbar = tk.Scrollbar(packet_frame, orient="vertical", command=packet_list.yview, bg="#1a1a1a", troughcolor="#0d0d0d", highlightcolor="#ff2d2d")
scrollbar.pack(side=tk.RIGHT, fill="y")
packet_list.config(yscrollcommand=scrollbar.set)

def auto_scroll_packet_list():
    packet_list.yview_moveto(1.0)
    packet_frame.config(highlightcolor="#00ffff" if packet_frame.cget("highlightcolor") == "#ff6666" else "#ff6666") 
    root.after(50, auto_scroll_packet_list)

auto_scroll_packet_list()

packets = []
displayed_packets = []
packet_stats = {"total": 0, "ip": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "sensitive": 0}
stats_label = ttk.Label(tab1, text="Total: 0 | IP: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | DNS: 0 | Sensitive: 0", font=("Orbitron", 13))
stats_label.pack(pady=10)

def log_action(action):
    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    action_log.insert(tk.END, f"[{timestamp}] {action}\n")
    action_log.yview_moveto(1.0)

def highlight_packet(event):
    packet_list.selection_clear(0, tk.END)
    idx = packet_list.nearest(event.y)
    packet_list.selection_set(idx)
    packet_list.activate(idx)

packet_list.bind("<Motion>", highlight_packet)
packet_list.bind("<Button-3>", lambda e: popup_menu(e))

popup = tk.Menu(root, tearoff=0, bg="#1a1a1a", fg="#00ffff", font=("Orbitron", 11), borderwidth=3, activebackground="#ff2d2d")
popup.add_command(label="Send to Decoder", command=lambda: send_to_decoder(None))
popup.add_command(label="Quick Inspect", command=lambda: quick_peek())
popup.add_command(label="Filter Packet", command=lambda: filter_packet())
popup.add_command(label="Clear Filter", command=lambda: clear_filter())

def popup_menu(event):
    idx = packet_list.nearest(event.y)
    packet_list.selection_set(idx)
    packet_list.activate(idx)
    popup.post(event.x_root, event.y_root)

def send_to_decoder(event):
    idx = packet_list.index(tk.ACTIVE)
    if idx >= 0 and idx < len(packets):
        packet = packets[idx]
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        decoder_list.insert(tk.END, f"[{timestamp}] {packet.summary()}")
        log_action(f"Sent packet #{idx} to decoder: {packet.summary()[:50]}...")

def quick_peek():
    idx = packet_list.index(tk.ACTIVE)
    if idx >= 0 and idx < len(packets):
        packet = packets[idx]
        peek = f"Time: {packet.time} | Src: {packet[IP].src if IP in packet else 'N/A'} | Dst: {packet[IP].dst if IP in packet else 'N/A'}"
        if TCP in packet or UDP in packet:
            peek += f" | Payload: {len(packet[Raw]) if Raw in packet else 0} bytes"
        messagebox.showinfo("Quick Peek", peek, parent=root)
        log_action(f"Quick Inspected packet #{idx}: {packet.summary()[:50]}...")

def filter_packet():
    idx = packet_list.index(tk.ACTIVE)
    if idx >= 0 and idx < len(packets):
        packet = packets[idx]
        filter_type = None
        if TCP in packet:
            filter_type = TCP
        elif UDP in packet:
            filter_type = UDP
        elif ICMP in packet:
            filter_type = ICMP
        elif DNS in packet:
            filter_type = DNS
        elif IP in packet:
            filter_type = IP
        if filter_type:
            packet_list.delete(0, tk.END)
            global displayed_packets
            displayed_packets = [p for p in packets if filter_type in p]
            for i, p in enumerate(displayed_packets):
                timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                summary = f"[{timestamp}] {p.summary()}"
                packet_list.insert(tk.END, summary)
                if is_sensitive(p):
                    packet_list.itemconfig(i, {'fg': '#ffff00'})
            log_action(f"Filtered packets to type: {filter_type.__name__} ({len(displayed_packets)} shown)")

def clear_filter():
    packet_list.delete(0, tk.END)
    global displayed_packets
    displayed_packets = packets.copy()
    for i, p in enumerate(displayed_packets):
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        summary = f"[{timestamp}] {p.summary()}"
        packet_list.insert(tk.END, summary)
        if is_sensitive(p):
            packet_list.itemconfig(i, {'fg': '#ffff00'})
    log_action(f"Cleared filter - showing all {len(displayed_packets)} packets")

def is_sensitive(packet):
    if Raw in packet:
        raw = bytes(packet[Raw]).decode('utf-8', errors='ignore').lower()
        return any(x in raw for x in ["password", "user", "login", "key", "token", "credit", "ssn"])
    return False

tab2 = tk.Frame(notebook, bg="#0d0d0d")
notebook.add(tab2, text="Decoder")

decoder_frame = tk.Frame(tab2, bg="#0d0d0d", relief="flat", borderwidth=3, highlightbackground="#00ffff")
decoder_frame.pack(fill="both", expand=True, padx=20, pady=20)

decoder_list = tk.Listbox(decoder_frame, 
                          bg="#1a1a1a", 
                          fg="#e6e6e6", 
                          font=("JetBrains Mono", 13), 
                          selectbackground="#ff2d2d", 
                          selectforeground="#00ffff", 
                          highlightthickness=3, 
                          highlightcolor="#ff6666", 
                          borderwidth=0, 
                          height=15)
decoder_list.pack(fill="both", expand=True, side=tk.LEFT)

decoder_scroll = tk.Scrollbar(decoder_frame, orient="vertical", command=decoder_list.yview, bg="#1a1a1a", troughcolor="#0d0d0d")
decoder_scroll.pack(side=tk.RIGHT, fill="y")
decoder_list.config(yscrollcommand=decoder_scroll.set)

decode_output = tk.Text(tab2, 
                        bg="#1a1a1a", 
                        fg="#e6e6e6", 
                        font=("JetBrains Mono", 13), 
                        height=12, 
                        borderwidth=0, 
                        highlightthickness=3, 
                        highlightcolor="#ff2d2d", 
                        insertbackground="#00ffff")
decode_output.pack(fill="x", padx=20, pady=5)

button_frame = tk.Frame(tab2, bg="#0d0d0d")
button_frame.pack(pady=10)

def decode_packet():
    idx = decoder_list.curselection()
    if idx and idx[0] < len(packets):
        packet = packets[idx[0]]
        decode_output.delete(1.0, tk.END)
        sensitive_info = ">> Full Packet Extracting <<\n\n"
        sensitive_info += f"[Time] {datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]}\n"
        if IP in packet:
            sensitive_info += f"[IP] Src: {packet[IP].src} ({socket.getfqdn(packet[IP].src)})\n"
            sensitive_info += f"[IP] Dst: {packet[IP].dst} ({socket.getfqdn(packet[IP].dst)})\n"
            sensitive_info += f"[IP] Version: {packet[IP].version} | TTL: {packet[IP].ttl} | TOS: {packet[IP].tos} | Len: {packet[IP].len}\n"
        if TCP in packet:
            sensitive_info += f"[TCP] Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}\n"
            sensitive_info += f"[TCP] Seq: {packet[TCP].seq} | Ack: {packet[TCP].ack}\n"
            sensitive_info += f"[TCP] Flags: {packet[TCP].flags} | Window: {packet[TCP].window}\n"
            if Raw in packet:
                raw = bytes(packet[Raw])
                sensitive_info += f"[RAW] Payload (hex): {binascii.hexlify(raw).decode()}\n"
                sensitive_info += f"[RAW] Payload (ASCII): {re.sub(r'[^\x20-\x7e]', '.', raw.decode('utf-8', errors='replace'))}\n"
        elif UDP in packet:
            sensitive_info += f"[UDP] Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}\n"
            sensitive_info += f"[UDP] Len: {packet[UDP].len}\n"
            if Raw in packet:
                raw = bytes(packet[Raw])
                sensitive_info += f"[RAW] Payload (hex): {binascii.hexlify(raw).decode()}\n"
                sensitive_info += f"[RAW] Payload (ASCII): {re.sub(r'[^\x20-\x7e]', '.', raw.decode('utf-8', errors='replace'))}\n"
        elif ICMP in packet:
            sensitive_info += f"[ICMP] Type: {packet[ICMP].type} | Code: {packet[ICMP].code}\n"
            if Raw in packet:
                raw = bytes(packet[Raw])
                sensitive_info += f"[RAW] Payload (hex): {binascii.hexlify(raw).decode()}\n"
                sensitive_info += f"[RAW] Payload (ASCII): {re.sub(r'[^\x20-\x7e]', '.', raw.decode('utf-8', errors='replace'))}\n"
        if DNS in packet:
            sensitive_info += f"[DNS] ID: {packet[DNS].id} | Query: {packet[DNS].qname.decode() if packet[DNS].qname else 'N/A'}\n"
            if packet[DNS].an:
                sensitive_info += f"[DNS] Answer: {packet[DNS].an.rdata}\n"
        if Raw in packet:
            raw_str = raw.decode('utf-8', errors='ignore').lower()
            if any(x in raw_str for x in ["password", "user", "login", "key", "token", "credit", "ssn"]):
                sensitive_info += f"\n[!] ALERT: Sensitive Data Detected: {raw_str[:200]}\n"
                packet_stats["sensitive"] += 1
        decode_output.insert(tk.END, sensitive_info)
        log_action(f"Decoded packet #{idx[0]}: {packet.summary()[:50]}...")
        update_stats()

def save_packet():
    idx = decoder_list.curselection()
    if idx and idx[0] < len(packets):
        packet = packets[idx[0]]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"packet_{timestamp}_{idx[0]}.pcap"
        with open(filename, "wb") as f:
            from scapy.utils import wrpcap
            wrpcap(f, packet)
        decode_output.insert(tk.END, f"\n[>] Packet archived: {filename}\n")
        log_action(f"Saved packet #{idx[0]} to {filename}")

decode_button = ttk.Button(button_frame, text="Decode", command=decode_packet)
decode_button.pack(side=tk.LEFT, padx=10)
save_button = ttk.Button(button_frame, text="Save Packet", command=save_packet)
save_button.pack(side=tk.LEFT, padx=10)

tab3 = tk.Frame(notebook, bg="#0d0d0d")
notebook.add(tab3, text="Action Log")

action_log = tk.Text(tab3, 
                     bg="#1a1a1a", 
                     fg="#ff2d2d", 
                     font=("JetBrains Mono", 13), 
                     height=25, 
                     borderwidth=0, 
                     highlightthickness=3, 
                     highlightcolor="#00ffff", 
                     insertbackground="#00ffff")
action_log.pack(fill="both", expand=True, padx=20, pady=20)
action_log.insert(tk.END, ">> Action Log <<\n\n> Running... #Hacktheplanet\n")

def auto_scroll_action_log():
    action_log.yview_moveto(1.0)
    root.after(50, auto_scroll_action_log)

auto_scroll_action_log()

tab4 = tk.Frame(notebook, bg="#0d0d0d")
notebook.add(tab4, text="Custom Payload")

forge_frame = tk.Frame(tab4, bg="#0d0d0d", relief="flat", borderwidth=3, highlightbackground="#00ffff")
forge_frame.pack(fill="both", expand=True, padx=20, pady=20)

tk.Label(forge_frame, text="Source IP:", bg="#0d0d0d", fg="#ff2d2d", font=("Orbitron", 12)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
src_ip_entry = tk.Entry(forge_frame, bg="#1a1a1a", fg="#00ffff", font=("JetBrains Mono", 12), insertbackground="#ff2d2d")
src_ip_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Label(forge_frame, text="Dest IP:", bg="#0d0d0d", fg="#ff2d2d", font=("Orbitron", 12)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
dst_ip_entry = tk.Entry(forge_frame, bg="#1a1a1a", fg="#00ffff", font=("JetBrains Mono", 12), insertbackground="#ff2d2d")
dst_ip_entry.grid(row=1, column=1, padx=5, pady=5)

tk.Label(forge_frame, text="Source Port:", bg="#0d0d0d", fg="#ff2d2d", font=("Orbitron", 12)).grid(row=2, column=0, padx=5, pady=5, sticky="e")
src_port_entry = tk.Entry(forge_frame, bg="#1a1a1a", fg="#00ffff", font=("JetBrains Mono", 12), insertbackground="#ff2d2d")
src_port_entry.grid(row=2, column=1, padx=5, pady=5)

tk.Label(forge_frame, text="Dest Port:", bg="#0d0d0d", fg="#ff2d2d", font=("Orbitron", 12)).grid(row=3, column=0, padx=5, pady=5, sticky="e")
dst_port_entry = tk.Entry(forge_frame, bg="#1a1a1a", fg="#00ffff", font=("JetBrains Mono", 12), insertbackground="#ff2d2d")
dst_port_entry.grid(row=3, column=1, padx=5, pady=5)

tk.Label(forge_frame, text="Payload:", bg="#0d0d0d", fg="#ff2d2d", font=("Orbitron", 12)).grid(row=4, column=0, padx=5, pady=5, sticky="ne")
payload_entry = tk.Text(forge_frame, bg="#1a1a1a", fg="#e6e6e6", font=("JetBrains Mono", 12), height=5, width=40, insertbackground="#ff2d2d")
payload_entry.grid(row=4, column=1, padx=5, pady=5)

forge_button_frame = tk.Frame(forge_frame, bg="#0d0d0d")
forge_button_frame.grid(row=5, column=0, columnspan=2, pady=10)

def inject_payload():
    try:
        src_ip = src_ip_entry.get()
        dst_ip = dst_ip_entry.get()
        src_port = int(src_port_entry.get())
        dst_port = int(dst_port_entry.get())
        payload = payload_entry.get("1.0", tk.END).strip().encode()
        
        packet = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="PA")/Raw(load=payload)
        send(packet, verbose=0)
        log_action(f"Injected TCP payload: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Payload: {payload[:50]}...")
        messagebox.showinfo("Payload Forge", "Payload injected successfully!", parent=root)
    except ValueError:
        log_action("Injection failed: Invalid port numbers")
        messagebox.showerror("Payload Forge", "Ports must be integers!", parent=root)
    except Exception as e:
        log_action(f"Injection failed: {str(e)}")
        messagebox.showerror("Payload Forge", f"Error: {str(e)}", parent=root)

inject_button = ttk.Button(forge_button_frame, text="Inject Payload", command=inject_payload)
inject_button.pack()

def sniff_packets():
    def packet_handler(packet):
        try:
            packet_stats["total"] += 1
            packets.append(packet)
            displayed_packets.append(packet)
            timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            summary = f"[{timestamp}] {packet.summary()}"
            idx = packet_list.size()
            packet_list.insert(tk.END, summary)
            if is_sensitive(packet):
                packet_list.itemconfig(idx, {'fg': '#ffff00'})
                packet_stats["sensitive"] += 1
            if IP in packet:
                packet_stats["ip"] += 1
            if TCP in packet:
                packet_stats["tcp"] += 1
            elif UDP in packet:
                packet_stats["udp"] += 1
            elif ICMP in packet:
                packet_stats["icmp"] += 1
            if DNS in packet:
                packet_stats["dns"] += 1
            update_stats()
        except Exception as e:
            log_action(f"Packet processing error: {str(e)}")
            log_action(f"Trace: {traceback.format_exc()}")

    while True:
        try:
            log_action("Starting packet capture on interface 'Wi-Fi'")
            sniff(iface="Wi-Fi", prn=packet_handler, store=0, filter=None, timeout=None, count=0)
            log_action("Sniff stopped unexpectedly - restarting...")
        except PermissionError:
            log_action("Permission denied - run as admin/root!")
            break
        except Exception as e:
            log_action(f"Sniffing crashed: {str(e)}")
            log_action(f"Trace: {traceback.format_exc()}")
            log_action("Retrying in 1 second...")
            import time
            time.sleep(1)

def update_stats():
    stats_label.config(text=f"Total: {packet_stats['total']} | IP: {packet_stats['ip']} | TCP: {packet_stats['tcp']} | "
                           f"UDP: {packet_stats['udp']} | ICMP: {packet_stats['icmp']} | DNS: {packet_stats['dns']} | "
                           f"Sensitive: {packet_stats['sensitive']}")

sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
sniff_thread.start()

root.mainloop()