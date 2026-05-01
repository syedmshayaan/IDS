import pandas as pd
import joblib

MODEL_PATH   = "ml/models/random_forest.pkl"
ENCODER_PATH = "ml/models/label_encoder.pkl"
INPUT_PATH   = "captures/aligned.csv"

def predict(input_path=INPUT_PATH):
    model = joblib.load(MODEL_PATH)
    le    = joblib.load(ENCODER_PATH)
    df    = pd.read_csv(input_path)
    df    = df.replace([float('inf'), float('-inf')], pd.NA).fillna(0)

    trained_features = model.feature_names_in_
    for col in trained_features:
        if col not in df.columns:
            df[col] = 0
    df = df[trained_features]

    preds        = model.predict(df)
    labels       = le.inverse_transform(preds)
    df["prediction"] = labels

    suspicious = df[df["prediction"] != "BENIGN"]
    print(f"[*] Total packets analysed: {len(df)}")
    print(f"[!] Suspicious packets found: {len(suspicious)}")
    print(suspicious[["prediction"]].value_counts())

    df.to_csv("captures/predictions.csv", index=False)
    print("[+] Predictions saved to captures/predictions.csv")
    return df
