"""URL feature extraction for the ML model.

This module is imported by BOTH the offline training script and the running
server, so the features computed at train time and predict time are guaranteed
identical. Every feature is derived from the URL string alone — no network.
"""
import re
from urllib.parse import urlparse
import tldextract
from app.heuristics import shannon_entropy

# Fixed order. The model learns feature-by-position, so never reorder this.
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "num_dots", "num_hyphens",
    "num_digits", "digit_ratio", "num_subdomains", "has_ip", "has_at",
    "num_special", "non_alnum_ratio", "hostname_entropy", "has_https",
    "num_query_params",
]

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_SPECIAL_RE = re.compile(r"[?=&%_~@\-]")


def extract_features(url: str) -> list[float]:
    """Turn a URL into a fixed-order list of numeric features (len == FEATURE_NAMES)."""
    url = (url or "").strip()
    if "://" not in url:
        url = "http://" + url  # ensure urlparse finds scheme/host

    parsed = urlparse(url)
    hostname = (parsed.netloc or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    ext = tldextract.extract(url)

    url_len = len(url)
    digits = sum(c.isdigit() for c in url)
    non_alnum = sum(not c.isalnum() for c in url)
    num_subdomains = len(ext.subdomain.split(".")) if ext.subdomain else 0

    features = [
        url_len,                                            # url_length
        len(hostname),                                      # hostname_length
        len(path),                                          # path_length
        url.count("."),                                     # num_dots
        url.count("-"),                                     # num_hyphens
        digits,                                             # num_digits
        digits / url_len if url_len else 0.0,               # digit_ratio
        num_subdomains,                                     # num_subdomains
        1.0 if _IP_RE.match(hostname) else 0.0,             # has_ip
        1.0 if "@" in url else 0.0,                         # has_at
        len(_SPECIAL_RE.findall(url)),                      # num_special
        non_alnum / url_len if url_len else 0.0,            # non_alnum_ratio
        shannon_entropy(hostname),                          # hostname_entropy
        1.0 if parsed.scheme == "https" else 0.0,           # has_https
        query.count("&") + (1 if query else 0),             # num_query_params
    ]
    return [float(x) for x in features]
