from app.ml_features import extract_features, FEATURE_NAMES
from app.ml_url import check_ml_url
from tests.test_heuristics import make_email


# --- Feature extractor -------------------------------------------------------
def test_extract_features_length_matches_names():
    feats = extract_features("http://paypa1.com/login")
    assert len(feats) == len(FEATURE_NAMES)


def test_extract_features_detects_ip_and_at():
    feats = extract_features("http://185.220.101.5/x@evil")
    d = dict(zip(FEATURE_NAMES, feats))
    assert d["has_ip"] == 1.0
    assert d["has_at"] == 1.0


def test_extract_features_https_flag():
    feats = extract_features("https://example.com")
    d = dict(zip(FEATURE_NAMES, feats))
    assert d["has_https"] == 1.0


def test_extract_features_handles_empty():
    # Must not raise on junk input.
    assert len(extract_features("")) == len(FEATURE_NAMES)


# --- ML signal ---------------------------------------------------------------
def test_ml_url_silent_when_no_urls():
    assert check_ml_url(make_email(urls=[])) == []


def test_ml_url_silent_on_reputable_domain():
    # A well-known legit site should not be flagged by the model.
    assert check_ml_url(make_email(urls=["https://www.google.com"])) == []


def test_ml_url_fires_on_phishy_url():
    # A random-looking, hyphen/entropy-heavy credential URL should score high.
    url = "http://secure-account-verify-login-update.x7f9q2zk8bv1p.tk/confirm?id=99213"
    signals = check_ml_url(make_email(urls=[url]))
    assert len(signals) == 1
    assert signals[0].code == "ml_url"
