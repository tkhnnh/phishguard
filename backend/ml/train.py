"""Offline training for the phishing-URL model (v2, with augmentation).

Run:  cd backend && python -m ml.train

The PhiUSIIL dataset's LEGITIMATE URLs are almost all bare homepages
(https://www.domain.com, no path), while phishing URLs have paths/queries.
A model trained naively learns the useless shortcut "has a path => phishing"
and flags every real email link.

Fix: augment the legitimate class with realistic variants — strip `www`, add
common paths, add query strings — so path/`www` presence becomes uninformative
and the model must rely on real domain signals (entropy, TLD, length, hyphens).
"""
import random
import sys
from pathlib import Path

import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ml_features import extract_features, FEATURE_NAMES  # noqa: E402

DATA_PATH = Path(__file__).parent / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = Path(__file__).resolve().parents[1] / "app" / "ml_model.txt"

random.seed(42)

# Realistic benign path/query fragments to graft onto legit homepages.
_PATHS = [
    "", "", "",  # keep some bare (weight toward some no-path)
    "/", "/about", "/contact", "/products", "/products/12345", "/blog",
    "/blog/2024/how-to-guide", "/news/article-title-here", "/login", "/account",
    "/account/settings", "/help/faq", "/search", "/category/electronics",
    "/user/profile", "/download", "/pricing", "/careers/job-1024", "/support",
    "/2024/09/17/story-name", "/watch", "/track/abc123def", "/feed", "/home",
    "/checkout", "/cart", "/terms", "/privacy", "/api/v1/items/88",
]
_QUERIES = [
    "", "", "", "", "?ref=nav", "?utm_source=newsletter&utm_medium=email",
    "?id=1024", "?q=shoes&page=2", "?lang=en", "?source=gmail&ust=17280000",
]


def _augment_legit(url: str) -> str:
    """Produce one realistic legit variant of a bare homepage URL."""
    u = url.strip()
    scheme, rest = ("https://", u.split("://", 1)[1]) if "://" in u else ("http://", u)
    host = rest.split("/", 1)[0]
    # Sometimes drop the leading www so "www => legit" isn't learnable.
    if host.startswith("www.") and random.random() < 0.5:
        host = host[4:]
    return f"{scheme}{host}{random.choice(_PATHS)}{random.choice(_QUERIES)}"


def main() -> None:
    print(f"Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH, usecols=["URL", "label"])
    # label: 1 = legit, 0 = phishing. Target: 1 = phishing.
    legit = df[df["label"] == 1]["URL"].astype(str).tolist()
    phish = df[df["label"] == 0]["URL"].astype(str).tolist()
    print(f"  legit={len(legit):,}  phish={len(phish):,}")

    print("Augmenting legitimate URLs with realistic paths/queries ...")
    urls, labels = [], []
    for u in legit:
        urls.append(u); labels.append(0)              # original bare homepage
        urls.append(_augment_legit(u)); labels.append(0)   # + one realistic variant
    for u in phish:
        urls.append(u); labels.append(1)
    print(f"  total training URLs: {len(urls):,}")

    print("Extracting features ...")
    X = pd.DataFrame([extract_features(u) for u in urls], columns=FEATURE_NAMES)
    y = pd.Series(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training LightGBM ...")
    model = lgb.LGBMClassifier(
        n_estimators=400, learning_rate=0.05, num_leaves=64,
        subsample=0.9, colsample_bytree=0.9, random_state=42,
    )
    model.fit(X_train, y_train)

    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    print("\n=== Held-out evaluation ===")
    print(f"  accuracy : {accuracy_score(y_test, pred):.4f}")
    print(f"  precision: {precision_score(y_test, pred):.4f}")
    print(f"  recall   : {recall_score(y_test, pred):.4f}")
    print(f"  f1       : {f1_score(y_test, pred):.4f}")
    print(f"  roc_auc  : {roc_auc_score(y_test, proba):.4f}")

    # The real test: URLs that broke the old model. Legit ones must score LOW.
    print("\n=== Sanity check (real-world URLs) ===")
    checks = {
        "https://www.google.com": "legit",
        "https://github.com": "legit",
        "https://www.nytimes.com/2024/09/17/story-name": "legit",
        "https://open.spotify.com/track/abc123": "legit",
        "https://www.linkedin.com/feed": "legit",
        "https://www.google.com/url?q=https://carsales.com.au&source=gmail": "legit",
        "https://mail.beehiiv.com/ss/c/u001.abc/xyz": "legit(tracking)",
        "http://paypa1-secure-login.gq/verify?id=1": "PHISH",
        "http://secure-account-verify.x7f9q2zk8bv.tk/login": "PHISH",
        "http://192.168.1.1/wp-admin/paypal/login.php": "PHISH",
    }
    import numpy as np
    for u, want in checks.items():
        p = float(model.predict_proba([extract_features(u)])[0, 1])
        print(f"  {p:.3f}  ({want:16s})  {u[:60]}")

    model.booster_.save_model(str(MODEL_PATH))
    print(f"\nSaved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
