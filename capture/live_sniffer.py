import os
import csv
import platform
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, get_if_list, conf
from capture.handshake import analyze_handshake

CSV_FILE  = "captures/traffic.csv"
INTERFACE = "wlp0s20f0u1"
FIELDS    = ["timestamp", "src_ip", "dst_ip", "protocol",
             "src_port", "dst_port", "flags", "length"]

def setup():
    os.makedirs("captures", exist_ok=True)
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=FIELDS).writeheader()

def build_record(packet):
    ip = packet[IP]
    record = {
        "timestamp": datetime.now().isoformat(),
        "src_ip":    ip.src,
        "dst_ip":    ip.dst,
        "protocol":  ip.proto,
        "length":    len(packet),
        "src_port":  None,
        "dst_port":  None,
        "flags":     None,
    }
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        record["src_port"] = tcp.sport
        record["dst_port"] = tcp.dport
        record["flags"]    = str(tcp.flags)
        analyze_handshake(ip, tcp)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        record["src_port"] = udp.sport
        record["dst_port"] = udp.dport
    return record

def save_record(record):
    with open(CSV_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore").writerow(record)

def process_packet(packet):
    if not packet.haslayer(IP):
        return
    record = build_record(packet)
    save_record(record)

def start():
    setup()
    print(f"[*] Live capture started on {INTERFACE}")
    sniff(iface=INTERFACE, prn=process_packet, store=False)
