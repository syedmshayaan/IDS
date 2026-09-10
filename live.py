import threading
import time
import os
from capture.live_sniffer import start as start_sniffer
from preprocessing.live_cleaner import start as start_cleaner
from ml.live_predict import start as start_predictor
from dashboard.app import app, init_db, run_pipeline

def main():
    print("""
    ╔══════════════════════════════════════════╗
    ║     AI-BASED IDS — LIVE CAPTURE MODE    ║
    ╚══════════════════════════════════════════╝
    """)

    os.makedirs("captures", exist_ok=True)

    init_db()

    threads = [
        threading.Thread(target=start_sniffer,  daemon=True, name="Sniffer"),
        threading.Thread(target=start_cleaner,  daemon=True, name="Preprocessor"),
        threading.Thread(target=start_predictor, daemon=True, name="Predictor"),
        threading.Thread(target=run_pipeline,   daemon=True, name="Pipeline"),
    ]

    for t in threads:
        print(f"[*] Starting {t.name}...")
        t.start()
        time.sleep(2)

    print("[*] Dashboard running at http://localhost:5000")
    app.run(debug=False, port=5000)

if __name__ == "__main__":
    main()
