import sys
import os
import csv
import platform
from datetime import datetime
from scapy.all import sniff, rdpcap, IP, TCP, UDP, PcapWriter, get_if_list, conf
from capture.handshake import analyze_handshake

CSV_FILE  = "captures/traffic.csv"
PCAP_FILE = "captures/raw.pcap"
FIELDS    = ["timestamp", "src_ip", "dst_ip", "protocol",
             "src_port", "dst_port", "flags", "length"]

def setup_output_files():
    os.makedirs("captures", exist_ok=True)
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=FIELDS).writeheader()

def get_interface():
    ifaces = [i for i in get_if_list() if i != "lo"]
    return ifaces[0] if ifaces else conf.iface

def check_permissions():
    if platform.system() == "Windows":
        try:
            from scapy.arch.windows import get_windows_if_list
        except Exception:
            print("[!] On Windows, install Npcap from https://npcap.com")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("[!] Live sniffing requires root. Run with: sudo python3 -m capture.sniffer")
            print("    Or replay a pcap: python3 -m capture.sniffer path/to/file.pcap")
            sys.exit(1)

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

def save_record(record, pcap_writer, packet):
    with open(CSV_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore").writerow(record)
    pcap_writer.write(packet)


def process_packet(pcap_writer):
    def handler(packet):
        if not packet.haslayer(IP):
            return
        record = build_record(packet)
        save_record(record, pcap_writer, packet)
    return handler

def run_live():
    check_permissions()
    iface      = get_interface()
    pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)
    print(f"[*] Sniffing on '{iface}' — Ctrl+C to stop")
    sniff(iface=iface, prn=process_packet(pcap_writer), store=False)

def run_from_pcap(path):
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)
    pcap_writer = PcapWriter(PCAP_FILE, append=True, sync=True)
    packets     = rdpcap(path)
    print(f"[*] Replaying {len(packets)} packets from {path}")
    for pkt in packets:
        process_packet(pcap_writer)(pkt)
    print(f"[*] Done. Output saved to {CSV_FILE}")

if __name__ == "__main__":
    setup_output_files()
    if len(sys.argv) == 2:
        run_from_pcap(sys.argv[1])
    else:
        run_live()


