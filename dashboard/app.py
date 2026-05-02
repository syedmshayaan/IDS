import pandas as pd
import joblib
import threading
import time
from datetime import datetime
from flask import Flask, jsonify, render_template
from dashboard.database import init_db, insert_packet, get_recent_packets, get_recent_alerts, get_recent_sandbox_jobs, get_stats
from dashboard.alerts import process_prediction
from preprocessing.encryptor import decrypt_file

app = Flask(__name__)

MODEL_PATH   = "ml/models/random_forest.pkl"
ENCODER_PATH = "ml/models/label_encoder.pkl"
ENCRYPTED    = "captures/processed.enc"
DECRYPTED    = "captures/temp_decrypted.csv"

model   = joblib.load(MODEL_PATH)
encoder = joblib.load(ENCODER_PATH)

def run_pipeline():
    while True:
        try:
            decrypt_file(ENCRYPTED, DECRYPTED)
            df = pd.read_csv(DECRYPTED)
            df = df.replace([float('inf'), float('-inf')], pd.NA).fillna(0)

            trained_features = model.feature_names_in_
            for col in trained_features:
                if col not in df.columns:
                    df[col] = 0
            df = df[trained_features]

            preds  = model.predict(df)
            labels = encoder.inverse_transform(preds)

            raw = pd.read_csv("captures/traffic.csv")
            for i, (_, row) in enumerate(raw.iterrows()):
                prediction = labels[i] if i < len(labels) else "Unknown"
                packet = {
                    "timestamp":  row.get("timestamp", datetime.now().isoformat()),
                    "src_ip":     row.get("src_ip", ""),
                    "dst_ip":     row.get("dst_ip", ""),
                    "src_port":   int(row.get("src_port", 0) or 0),
                    "dst_port":   int(row.get("dst_port", 0) or 0),
                    "protocol":   int(row.get("protocol", 0) or 0),
                    "length":     int(row.get("length", 0) or 0),
                    "flags":      str(row.get("flags", "")),
                    "prediction": prediction,
                }
                insert_packet(packet)
                process_prediction(packet, prediction)

        except Exception as e:
            print(f"[pipeline error] {e}")

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
