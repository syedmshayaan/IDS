import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATA_PATH = "data/Friday.csv"
LABEL_COL = "Attack Type"

def load_data(path, label_col):
    df = pd.read_csv(path, nrows=100000)
    df.columns = df.columns.str.strip()
    df = df.replace([float('inf'), float('-inf')], pd.NA)
    df = df.dropna()
    return df

def prepare(df, label_col):
    le = LabelEncoder()
    df[label_col] = le.fit_transform(df[label_col])
    X = df.drop(columns=[label_col])
    y = df[label_col]
    return X, y, le

def train(X_train, y_train):
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    joblib.dump(rf, "ml/models/random_forest.pkl")
    print("[+] Random Forest saved")

    dt = DecisionTreeClassifier(random_state=42)
    dt.fit(X_train, y_train)
    joblib.dump(dt, "ml/models/decision_tree.pkl")
    print("[+] Decision Tree saved")

def run():
    print("[*] Loading data...")
    df = load_data(DATA_PATH, LABEL_COL)
    print(f"[*] Dataset shape: {df.shape}")
    X, y, le = prepare(df, LABEL_COL)
    joblib.dump(le, "ml/models/label_encoder.pkl")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"[*] Training on {len(X_train)} rows...")
    train(X_train, y_train)
    print("[*] Training complete")

if __name__ == "__main__":
    run()
