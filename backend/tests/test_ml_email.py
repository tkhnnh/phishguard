from app.ml_email import check_ml_email
from tests.test_heuristics import make_email


def test_ml_email_fires_on_phishing_text():
    body = ("URGENT: Your account has been suspended due to unusual activity. "
            "Verify your password and banking details immediately at the link "
            "below to restore access or your account will be permanently closed.")
    signals = check_ml_email(make_email(subject="Account suspended", body_text=body))
    assert len(signals) == 1
    assert signals[0].code == "ml_email"


def test_ml_email_silent_on_normal_text():
    body = "Hi team, here are the notes from today's standup meeting. See you tomorrow at the usual time."
    assert check_ml_email(make_email(subject="Standup notes", body_text=body)) == []


def test_ml_email_silent_on_too_short_text():
    assert check_ml_email(make_email(subject="hi", body_text="ok")) == []
