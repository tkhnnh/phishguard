import httpx
from urllib.parse import urlparse
from app.schemas import (EmailIn, Signal)
from app.heuristics import registered_domain

OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text/"

# Major shared platforms: phishing is sometimes hosted on a subdomain of these
# (e.g. sites.google.com/phish), but the registered domain must NEVER be treated
# as fully malicious, or we'd flag every legit google.com/amazonaws.com link.
NEVER_BLOCKLIST = {
    "google.com", "googleapis.com", "gstatic.com",
    "microsoft.com", "apple.com", "amazonaws.com",
    "cloudflare.com", "github.io", "githubusercontent.com",
    "sharepoint.com", "windows.net", "web.app", "firebaseapp.com",
}

# Populated at startup, read on every request. Holds HOSTNAMES (e.g.
# "sites.google.com"), not registered domains — so one bad subdomain doesn't
# poison an entire shared platform.
BLOCKLIST_HOSTS: set[str] = set()


def host_of(url: str) -> str:
    """Return the lowercase hostname of a URL (adds a scheme if missing)."""
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).netloc.lower()


async def load_feeds() -> None:
    """Download the feeds and fill BLOCKLIST_HOSTS. Called once at startup."""
    hosts = set()
    async with httpx.AsyncClient(timeout=15.0) as client:
        for feed_url in (OPENPHISH_FEED, URLHAUS_FEED):
            try:
                resp = await client.get(feed_url)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue          # skip blanks and comment lines
                    host = host_of(line)
                    if host:
                        hosts.add(host)
            except (httpx.HTTPError, httpx.TimeoutException):
                continue                  # one feed down shouldn't break the other
    # Replace contents (so a later refresh swaps cleanly)
    BLOCKLIST_HOSTS.clear()
    BLOCKLIST_HOSTS.update(hosts)


def check_blocklist(email: EmailIn) -> list[Signal]:
    """Sync rule: fast local set lookup by hostname, no network."""
    signals = []
    flagged = set()
    for url in email.urls:
        host = host_of(url)
        # Skip major shared platforms — the whole registered domain is not bad.
        if registered_domain(url) in NEVER_BLOCKLIST:
            continue
        if host in BLOCKLIST_HOSTS and host not in flagged:
            flagged.add(host)
            signals.append(Signal(
                code="blocklist", weight=50, severity="high",
                message=f"Link host '{host}' is on a known phishing/malware blocklist",
            ))
    return signals
