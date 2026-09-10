import os
import pandas as pd
import time
from preprocessing.encryptor import encrypt_file
from preprocessing.align_features import align

RAW_INPUT     = "captures/traffic.csv"
CLEAN_OUTPUT  = "captures/processed.csv"
ALIGNED_OUTPUT = "captures/aligned.csv"
ENCRYPTED     = "captures/processed.enc"
TRACKER_FILE  = "captures/.last_processed_row"

FIELDS = ["timestamp", "src_ip", "dst_ip", "protocol",
          "src_port", "dst_port", "flags", "length"]

def get_last_processed_row():
    if os.path.exists(TRACKER_FILE):
        with open(TRACKER_FILE, "r") as f:
            return int(f.read().strip())
    return 0

def save_last_processed_row(row):
    with open(TRACKER_FILE, "w") as f:
        f.write(str(row))

def process_new_rows():
    if not os.path.exists(RAW_INPUT):
        return

    last_row = get_last_processed_row()
    df       = pd.read_csv(RAW_INPUT)

    if len(df) <= last_row:
        return

    new_rows = df.iloc[last_row:].copy()
    print(f"[*] Processing {len(new_rows)} new rows")

    new_rows = new_rows.dropna(subset=["src_ip", "dst_ip", "protocol"])
    new_rows = new_rows[new_rows["protocol"].isin([6, 17])]

    new_rows["flags"]    = new_rows["flags"].fillna("none")
    new_rows["has_syn"]  = new_rows["flags"].str.contains("S").astype(int)
    new_rows["has_ack"]  = new_rows["flags"].str.contains("A").astype(int)
    new_rows["has_fin"]  = new_rows["flags"].str.contains("F").astype(int)
    new_rows["has_rst"]  = new_rows["flags"].str.contains("R").astype(int)
    new_rows["is_tcp"]   = (new_rows["protocol"] == 6).astype(int)
    new_rows["is_udp"]   = (new_rows["protocol"] == 17).astype(int)
    new_rows["src_port"] = new_rows["src_port"].fillna(0).astype(int)
    new_rows["dst_port"] = new_rows["dst_port"].fillna(0).astype(int)
    new_rows["length"]   = new_rows["length"].fillna(0).astype(int)

    cleaned = new_rows.drop(columns=["timestamp", "src_ip", "dst_ip", "protocol", "flags"], errors="ignore")
    aligned = align(cleaned)

    if os.path.exists(ALIGNED_OUTPUT):
        existing = pd.read_csv(ALIGNED_OUTPUT)
        combined = pd.concat([existing, aligned], ignore_index=True)
    else:
        combined = aligned

    combined.to_csv(ALIGNED_OUTPUT, index=False)
    combined.to_csv(CLEAN_OUTPUT, index=False)
    encrypt_file(CLEAN_OUTPUT, ENCRYPTED)

    save_last_processed_row(len(df))
    print(f"[+] Aligned data updated: {len(combined)} total rows")

def start():
    print("[*] Live preprocessor started")
    while True:
        try:
            process_new_rows()
        except Exception as e:
            print(f"[preprocessor error] {e}")
        time.sleep(30)
