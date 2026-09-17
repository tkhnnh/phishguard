"""Serve the trained phishing-URL model as a detection signal.

Loads the LightGBM booster once at import. If the model file is missing or
fails to load, the model is disabled and check_ml_url returns [] — the app
still runs on the other signals.
"""
from pathlib import Path

import lightgbm as lgb

from app.schemas import EmailIn, Signal
from app.heuristics import registered_domain
from app.ml_features import extract_features

MODEL_PATH = Path(__file__).parent / "ml_model.txt"

# Probability thresholds for turning a model score into a signal.
_HIGH = 0.85
_MEDIUM = 0.60
_MAX_URLS = 15

try:
    _model = lgb.Booster(model_file=str(MODEL_PATH))
except Exception:  # noqa: BLE001 - any load failure disables ML gracefully
    _model = None


def _predict(url: str) -> float:
    """Phishing probability for one URL (0..1)."""
    features = [extract_features(url)]
    return float(_model.predict(features)[0])


def check_ml_url(email: EmailIn) -> list[Signal]:
    if _model is None or not email.urls:
        return []

    signals = []
    flagged = set()
    for url in email.urls[:_MAX_URLS]:
        domain = registered_domain(url)
        if domain in flagged:
            continue
        prob = _predict(url)
        if prob < _MEDIUM:
            continue
        flagged.add(domain)
        severity = "high" if prob >= _HIGH else "medium"
        weight = 45 if prob >= _HIGH else 25
        signals.append(Signal(
            code="ml_url",
            message=f"Machine-learning model rates '{domain}' {int(prob * 100)}% likely phishing",
            weight=weight,
            severity=severity,
        ))
    return signals
