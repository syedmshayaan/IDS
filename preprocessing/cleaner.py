import os
import pandas as pd
from preprocessing.encryptor import encrypt_file

RAW_INPUT    = "captures/traffic.csv"
CLEAN_OUTPUT = "captures/processed.csv"
ENCRYPTED    = "captures/processed.enc"

def load_raw(path):
    df = pd.read_csv(path)
    print(f"[*] Loaded {len(df)} rows from {path}")
    return df

def drop_noise(df):
    df = df.dropna(subset=["src_ip", "dst_ip", "protocol"])
    df = df[df["protocol"].isin([6, 17])]
    df = df[~df["src_ip"].str.startswith("224.")]
    df = df[~df["src_ip"].str.startswith("255.")]
    return df

def extract_features(df):
    df["flags"]       = df["flags"].fillna("none")
    df["has_syn"]     = df["flags"].str.contains("S").astype(int)
    df["has_ack"]     = df["flags"].str.contains("A").astype(int)
    df["has_fin"]     = df["flags"].str.contains("F").astype(int)
    df["has_rst"]     = df["flags"].str.contains("R").astype(int)
    df["is_tcp"]      = (df["protocol"] == 6).astype(int)
    df["is_udp"]      = (df["protocol"] == 17).astype(int)
    df["src_port"]    = df["src_port"].fillna(0).astype(int)
    df["dst_port"]    = df["dst_port"].fillna(0).astype(int)
    df["length"]      = df["length"].fillna(0).astype(int)
    return df

def drop_unused_columns(df):
    return df.drop(columns=["timestamp", "src_ip", "dst_ip", "protocol", "flags"])

def clean(input_path=RAW_INPUT, output_path=CLEAN_OUTPUT):
    df = load_raw(input_path)
    df = drop_noise(df)
    df = extract_features(df)
    df = drop_unused_columns(df)
    os.makedirs("captures", exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[+] Cleaned data saved: {output_path} ({len(df)} rows)")
    encrypt_file(output_path, ENCRYPTED)
    return df

if __name__ == "__main__":
    clean()
