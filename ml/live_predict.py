import os
import pandas as pd
import joblib
import time

MODEL_PATH    = "ml/models/random_forest.pkl"
ENCODER_PATH  = "ml/models/label_encoder.pkl"
ALIGNED_INPUT = "captures/aligned.csv"
PREDICTIONS   = "captures/predictions.csv"
TRACKER_FILE  = "captures/.last_predicted_row"

def get_last_predicted_row():
    if os.path.exists(TRACKER_FILE):
        with open(TRACKER_FILE, "r") as f:
            return int(f.read().strip())
    return 0

def save_last_predicted_row(row):
    with open(TRACKER_FILE, "w") as f:
        f.write(str(row))

def predict_new_rows():
    if not os.path.exists(ALIGNED_INPUT):
        return

    model = joblib.load(MODEL_PATH)
    le    = joblib.load(ENCODER_PATH)

    df       = pd.read_csv(ALIGNED_INPUT)
    last_row = get_last_predicted_row()

    if len(df) <= last_row:
        return

    new_rows = df.iloc[last_row:].copy()
    print(f"[*] Predicting {len(new_rows)} new rows")

    new_rows = new_rows.apply(pd.to_numeric, errors="coerce").fillna(0)
    new_rows = new_rows.replace(float("inf"), 0).replace(float("-inf"), 0)

    trained = model.feature_names_in_
    for col in trained:
        if col not in new_rows.columns:
            new_rows[col] = 0
    new_rows = new_rows[trained]

    preds  = model.predict(new_rows)
    labels = le.inverse_transform(preds)
    new_rows["prediction"] = labels

    if os.path.exists(PREDICTIONS):
        existing = pd.read_csv(PREDICTIONS)
        combined = pd.concat([existing, new_rows[["prediction"]]], ignore_index=True)
    else:
        combined = new_rows[["prediction"]]

    combined.to_csv(PREDICTIONS, index=False)
    save_last_predicted_row(len(df))

    suspicious = new_rows[new_rows["prediction"] != "BENIGN"]
    print(f"[+] {len(suspicious)} threats detected in this batch")

def start():
    print("[*] Live predictor started")
    while True:
        try:
            predict_new_rows()
        except Exception as e:
            print(f"[predictor error] {e}")
        time.sleep(30)
