import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from ml.train import load_data, prepare

DATA_PATH = "data/Friday.csv"
LABEL_COL = "Label"

def evaluate(model_path, X_test, y_test, le):
    model = joblib.load(model_path)
    preds = model.predict(X_test)
    acc   = accuracy_score(y_test, preds)
    print(f"\n--- {model_path} ---")
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, preds, target_names=le.classes_))

def run():
    df               = load_data(DATA_PATH, LABEL_COL)
    X, y, le         = prepare(df, LABEL_COL)
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    evaluate("ml/models/random_forest.pkl", X_test, y_test, le)
    evaluate("ml/models/decision_tree.pkl", X_test, y_test, le)

if __name__ == "__main__":
    run()
