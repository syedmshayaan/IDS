import pandas as pd

CLEAN_INPUT   = "captures/processed.csv"
ALIGNED_OUTPUT = "captures/aligned.csv"

CICIDS_COLUMNS = [
    "dst_port", "protocol", "flow_duration", "tot_fwd_pkts",
    "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean",
    "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std",
    "fwd_iat_mean", "bwd_iat_mean", "fwd_psh_flags", "bwd_psh_flags",
    "fwd_urg_flags", "bwd_urg_flags", "fin_flag_cnt", "syn_flag_cnt",
    "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt",
    "down_up_ratio", "pkt_size_avg", "init_fwd_win_byts",
    "init_bwd_win_byts", "active_mean", "idle_mean"
]

COLUMN_MAP = {
    "length":   "pkt_size_avg",
    "dst_port": "dst_port",
    "has_syn":  "syn_flag_cnt",
    "has_ack":  "ack_flag_cnt",
    "has_fin":  "fin_flag_cnt",
    "has_rst":  "rst_flag_cnt",
    "is_tcp":   "protocol",
}

def align(df):
    for src_col, dst_col in COLUMN_MAP.items():
        if src_col in df.columns:
            df[dst_col] = df[src_col]

    for col in CICIDS_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    return df[CICIDS_COLUMNS]

if __name__ == "__main__":
    df      = pd.read_csv(CLEAN_INPUT)
    aligned = align(df)
    aligned.to_csv(ALIGNED_OUTPUT, index=False)
    print(f"[+] Aligned data saved: {ALIGNED_OUTPUT} ({len(aligned)} rows)")
