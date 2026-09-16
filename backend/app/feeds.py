import httpx
from app.schemas import (EmailIn, Signal)
from app.heuristics import registered_domain

OPENPHISH_FEED = "https://openphish.com/feed.txt"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text/"

# Populated at startup, read on every request. Lives for the server's lifetime.
BLOCKLIST_DOMAINS: set[str] = set()


async def load_feeds() -> None:
    """Download the feeds and fill BLOCKLIST_DOMAINS. Called once at startup."""
    domains = set()
    async with httpx.AsyncClient(timeout=15.0) as client:
        for feed_url in (OPENPHISH_FEED, URLHAUS_FEED):
            try:
                resp = await client.get(feed_url)
                resp.raise_for_status()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue          # skip blanks and comment lines
                    
                    domains.add(registered_domain(line))
                    
            except (httpx.HTTPError, httpx.TimeoutException):
                continue                  # one feed down shouldn't break the other
    # Replace contents (so a later refresh swaps cleanly)
    BLOCKLIST_DOMAINS.clear()
    BLOCKLIST_DOMAINS.update(domains)


def check_blocklist(email: EmailIn) -> list[Signal]:
    """Sync rule: fast local set lookup, no network."""
    signals = []
    flagged = set()
    for url in email.urls:
        domain = registered_domain(url)
        if domain in BLOCKLIST_DOMAINS and domain not in flagged:
            flagged.add(domain)
            signals.append(Signal(code="blocklist", weight=50, severity="high",
                message=f"Domain '{domain}' is on a known phishing/malware blocklist"))
    return signals