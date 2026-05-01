from collections import defaultdict
from datetime import datetime

connection_table = defaultdict(lambda: {"state": None, "syn_time": None})

def analyze_handshake(ip, tcp):
    key = (ip.src, ip.dst, tcp.dport)
    conn = connection_table[key]
    flags = str(tcp.flags)

    if "S" in flags and "A" not in flags:
        conn.update({"state": "SYN", "syn_time": datetime.now()})

    elif "S" in flags and "A" in flags:
        if conn["state"] == "SYN":
            conn["state"] == "SYN-ACK"

    elif "A" in flags and "S" not in flags:
        if conn["state"] == "SYN-ACK":
            print(f"[+] Handshake complete :) {key}")
            connection_table.pop(key)
        elif conn["state"] == "SYN":
            print(f"[!] Possible SYN flood: {key}")
