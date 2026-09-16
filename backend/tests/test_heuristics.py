from app.schemas import EmailIn
from app.heuristics import (check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to, check_url_entropy)

def make_email(**kwargs) -> EmailIn:
    """Helper: build an EmailIn with sensible defaults, override per test."""
    defaults = {"sender": "a@example.com", "subject": "", "body_text": "", "urls": []}
    defaults.update(kwargs)
    return EmailIn(**defaults)

def test_urgency_fires_on_phrase():
    # Arrange
    email = make_email(body_text="Please verify your account within 24 hours.")
    # Act
    signals = check_urgency(email)
    # Assert
    assert len(signals) == 2                       # two phrases matched
    assert all(s.code == "urgency" for s in signals)

def test_urgency_silent_on_clean_email():
    email = make_email(body_text="Lunch tomorrow at noon?")
    assert check_urgency(email) == []
    
def test_domain_mismatch_fires_sender_domain_dif_link_domain():
    email = make_email(sender="a@paypal.com",urls = ["mail.paypa1.com"])
    
    signals = check_domain_mismatch(email)
    
    assert len(signals) == 1
    assert all(s.code == "domain_mismatch" for s in signals)
    
def test_domain_mismatch_on_clear_email():
    email = make_email(sender="A@paypal.com", urls = ["mail.paypal.com"])
    assert check_domain_mismatch(email) == []
    
def test_domain_mismatch_skips_known_esp():
    email = make_email(sender="hi@withsandra.dev", urls = ["https://mail.beehiiv.com/x"])
    assert check_domain_mismatch(email) == []
    
    
def test_lookalike_fires_on_wrong_domain():
    email = make_email(urls = ["paypa1.com"])
    signals = check_lookalike(email)
    
    assert len(signals) == 1
    assert all(s.code == "lookalike" for s in signals)
    
def test_lookalike_on_clear_email():
    email = make_email(urls = ["paypal.com"])
    assert check_lookalike(email) == []
    

def test_ip_url_fires_on_IP():
    email = make_email(urls = ["http://185.220.101.5/login"])
    
    signals = check_ip_url(email)
    
    assert len(signals) == 1
    assert all(s.code == "ip_url" for s in signals)
    
def test_ip_url_on_clean_email():
    email = make_email(urls = ["http://paypal.com"])
    assert check_ip_url(email) == []
    
def test_reply_fires_on_domain_dif_sender():
    email = make_email(sender="1@paypal.com", reply_to = "abc@youtube.com")
    signals = check_reply_to(email)
    
    assert len(signals) == 1
    assert all(s.code == "reply_to_mismatch" for s in signals)

def test_reply_on_clean_email():
    email = make_email(sender="abc@gmail.com", reply_to="abc@gmail.com")
    assert check_reply_to(email) == []
    
def test_reply_silent_when_no_reply_to():
    email = make_email(sender="abc@gmail.com")
    assert check_reply_to(email) == []
    
def test_url_entropy_fires_on_improper_domain():
    email = make_email(urls = ["x7f9q2zk8bv.com"])
    signals = check_url_entropy(email)
    assert len(signals) == 1
    assert all(s.code == "high_entropy" for s in signals)
    
def test_url_entropy_on_proper_domain():
    email = make_email(urls = ["paypal.com"])
    assert check_url_entropy(email) == []