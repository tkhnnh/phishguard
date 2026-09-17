"""Train the email-text phishing classifier (TF-IDF + Logistic Regression).

Run:  cd backend && python -m ml.train_email

Lightweight and CPU-friendly (no transformers) so it deploys on a small host.
Reads the phishing-email dataset (Email Text / Email Type), trains a pipeline,
evaluates it, and saves it to app/ml_email_model.joblib for the server to load.
"""
import sys
from pathlib import Path

import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

DATA_PATH = Path(__file__).parent / "data" / "phishing_email.csv"
MODEL_PATH = Path(__file__).resolve().parents[1] / "app" / "ml_email_model.joblib"


def main() -> None:
    print(f"Loading {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, usecols=["Email Text", "Email Type"]).dropna()
    df = df[df["Email Text"].str.strip().astype(bool)]  # drop empty text
    y = (df["Email Type"] == "Phishing Email").astype(int)
    X = df["Email Text"].astype(str)
    print(f"  {len(df):,} emails  (phishing={y.sum():,})")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=20000, ngram_range=(1, 2),
            stop_words="english", min_df=2, sublinear_tf=True,
        )),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=4.0)),
    ])

    print("Training ...")
    pipe.fit(X_train, y_train)

    proba = pipe.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\n=== Held-out evaluation ===")
    print(f"  accuracy : {accuracy_score(y_test, pred):.4f}")
    print(f"  precision: {precision_score(y_test, pred):.4f}")
    print(f"  recall   : {recall_score(y_test, pred):.4f}")
    print(f"  f1       : {f1_score(y_test, pred):.4f}")
    print(f"  roc_auc  : {roc_auc_score(y_test, proba):.4f}")

    print("\n=== Sanity check ===")
    samples = {
        "Hi, are we still on for lunch tomorrow at noon? Let me know.": "legit",
        "Your meeting notes from today's standup are attached. Thanks!": "legit",
        "URGENT: Your account has been suspended. Verify your password now at http://bit.ly/x to avoid closure.": "PHISH",
        "Dear customer, we detected unusual activity. Confirm your banking details immediately to restore access.": "PHISH",
    }
    for text, want in samples.items():
        p = float(pipe.predict_proba([text])[0, 1])
        print(f"  {p:.3f}  ({want:5s})  {text[:60]}")

    joblib.dump(pipe, MODEL_PATH)
    size_mb = MODEL_PATH.stat().st_size / 1e6
    print(f"\nSaved model to {MODEL_PATH}  ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
