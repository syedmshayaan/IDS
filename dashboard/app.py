import os
import pandas as pd
import joblib
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, render_template
from dashboard.database import init_db, insert_packet, get_recent_packets, get_recent_alerts, get_recent_sandbox_jobs, get_stats
from dashboard.alerts import process_prediction

app = Flask(__name__)

def safe_int(val):
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return 0
def run_pipeline():
    last_processed = 0
    while True:
        try:
            if not os.path.exists("captures/traffic.csv"):
                time.sleep(5)
                continue

            traffic = pd.read_csv("captures/traffic.csv")
            
            pred_labels = []
            if os.path.exists("captures/predictions.csv"):
                preds = pd.read_csv("captures/predictions.csv")
                pred_labels = preds["prediction"].tolist()

            new_traffic = traffic.iloc[last_processed:]
            if len(new_traffic) == 0:
                time.sleep(5)
                continue

            for i, (_, row) in enumerate(new_traffic.iterrows()):
                abs_idx    = last_processed + i
                prediction = pred_labels[abs_idx] if abs_idx < len(pred_labels) else "BENIGN"
                packet = {
                    "timestamp":  str(row.get("timestamp", datetime.now().isoformat())),
                    "src_ip":     str(row.get("src_ip", "") or ""),
                    "dst_ip":     str(row.get("dst_ip", "") or ""),
                    "src_port":   safe_int(row.get("src_port", 0)),
                    "dst_port":   safe_int(row.get("dst_port", 0)),
                    "protocol":   safe_int(row.get("protocol", 0)),
                    "length":     safe_int(row.get("length", 0)),
                    "flags":      str(row.get("flags", "") or ""),
                    "prediction": prediction,
                }
                insert_packet(packet)
                process_prediction(packet, prediction)

            last_processed = len(traffic)

        except Exception as e:
            import traceback
            print(f"[pipeline error] {e}")
            traceback.print_exc()

        time.sleep(10)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    return jsonify(get_stats())

@app.route("/api/packets")
def packets():
    return jsonify(get_recent_packets())

@app.route("/api/alerts")
def alerts():
    return jsonify(get_recent_alerts())

@app.route("/api/sandbox")
def sandbox():
    return jsonify(get_recent_sandbox_jobs())

if __name__ == "__main__":
    init_db()
    thread = threading.Thread(target=run_pipeline, daemon=True)
    thread.start()
    app.run(debug=False, port=5000)
