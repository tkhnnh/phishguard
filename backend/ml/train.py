"""Offline training script for the phishing-URL model.

Run once (or when retraining):
    cd backend
    python -m ml.train

Reads the PhiUSIIL dataset, computes OUR features from the raw URL column
(ignoring the dataset's precomputed features), trains a LightGBM classifier,
evaluates it, and saves the model to app/ml_model.txt for the server to load.
"""
import sys
from pathlib import Path

import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Make `app` importable when run as `python -m ml.train` from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ml_features import extract_features, FEATURE_NAMES  # noqa: E402

DATA_PATH = Path(__file__).parent / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = Path(__file__).resolve().parents[1] / "app" / "ml_model.txt"


def main() -> None:
    print(f"Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, usecols=["URL", "label"])
    print(f"  {len(df):,} rows")

    # Dataset label: 1 = legitimate, 0 = phishing.
    # We want the model to predict PHISHING, so make phishing the positive class.
    y = (df["label"] == 0).astype(int)

    print("Extracting features from raw URLs ...")
    X = pd.DataFrame(
        [extract_features(u) for u in df["URL"].astype(str)],
        columns=FEATURE_NAMES,
    )

    # Stratified split so both classes are represented in train and test.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training LightGBM ...")
    model = lgb.LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=48,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
    )
    model.fit(X_train, y_train)

    # Evaluate on the held-out test set.
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\n=== Evaluation (held-out 20%) ===")
    print(f"  accuracy : {accuracy_score(y_test, pred):.4f}")
    print(f"  precision: {precision_score(y_test, pred):.4f}")
    print(f"  recall   : {recall_score(y_test, pred):.4f}")
    print(f"  f1       : {f1_score(y_test, pred):.4f}")
    print(f"  roc_auc  : {roc_auc_score(y_test, proba):.4f}")

    # Feature importances (sanity check).
    print("\n=== Top features ===")
    importances = sorted(
        zip(FEATURE_NAMES, model.booster_.feature_importance()),
        key=lambda t: t[1], reverse=True,
    )
    for name, imp in importances:
        print(f"  {name:20s} {imp}")

    # Save the native LightGBM booster (small, no sklearn/joblib needed to load).
    model.booster_.save_model(str(MODEL_PATH))
    print(f"\nSaved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
