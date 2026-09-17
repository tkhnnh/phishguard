"""Serve the email-text phishing classifier as a detection signal.

Loads the TF-IDF + LogisticRegression pipeline once at import. If the model is
missing or fails to load, the signal is disabled and returns [].
"""
from pathlib import Path

import joblib

from app.schemas import EmailIn, Signal

MODEL_PATH = Path(__file__).parent / "ml_email_model.joblib"

_HIGH = 0.90
_MEDIUM = 0.70
_MIN_CHARS = 40  # too little text => unreliable, skip

try:
    _model = joblib.load(MODEL_PATH)
except Exception:  # noqa: BLE001 - any load failure disables the signal
    _model = None


def check_ml_email(email: EmailIn) -> list[Signal]:
    if _model is None:
        return []
    text = f"{email.subject}\n{email.body_text}".strip()
    if len(text) < _MIN_CHARS:
        return []

    prob = float(_model.predict_proba([text])[0, 1])
    if prob < _MEDIUM:
        return []

    severity = "high" if prob >= _HIGH else "medium"
    weight = 40 if prob >= _HIGH else 20
    return [Signal(
        code="ml_email",
        message=f"Message text reads as phishing ({int(prob * 100)}% by language model)",
        weight=weight,
        severity=severity,
    )]
