import asyncio
import httpx
from app.schemas import (EmailIn, Signal)
from app.config import settings
from datetime import (datetime, timezone)
from app.heuristics import registered_domain, sender_domain_of, KNOWN_ESP_DOMAINS

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

RDAP_URL = "https://rdap.org/domain/"

async def check_safe_browsing(email: EmailIn) -> list[Signal]:
    if not email.urls:
        return []
    if not settings.safe_browsing_api_key:
        return []
    
    
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in email.urls],
        },
    }
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                SAFE_BROWSING_URL,
                params={"key": settings.safe_browsing_api_key},
                json=body,
            )
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, httpx.TimeoutException):
        return []

    signals = []
    if not data:
        return []

    matches = data.get("matches")
    if not matches:
        return []
    for match in matches:
        threat_type = match["threatType"]
        threat = match["threat"]["url"]
        
        signals.append(Signal(
                        code="safe_browsing",
                        message=f"Flagged by Google Safe Browsing as {threat_type}: {threat}",
                        weight=50,
                        severity="high",
                    ))
    
    return signals
        
# Cap how many URLs we hit the network for, so a newsletter with 50 links
# doesn't trigger 50 slow lookups. Analyze the first N unique ones.
MAX_URLS = 15


async def _domain_age_signal(client: httpx.AsyncClient, domain: str) -> Signal | None:
    """Look up one domain's age via RDAP. Returns a Signal or None. Never raises."""
    try:
        resp = await client.get(RDAP_URL + domain)
        resp.raise_for_status()
        for event in resp.json().get("events", []):
            if event.get("eventAction") == "registration":
                dt = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
                if age_days < 30:
                    return Signal(
                        code="new_domain",
                        message=f"Domain '{domain}' registered {age_days} days ago",
                        weight=30, severity="high",
                    )
    except (httpx.HTTPError, httpx.TimeoutException, ValueError, KeyError):
        pass
    return None


async def check_domain_age(email: EmailIn) -> list[Signal]:
    # Unique domains, capped.
    domains = []
    seen = set()
    for url in email.urls:
        domain = registered_domain(url)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
        if len(domains) >= MAX_URLS:
            break
    if not domains:
        return []
    # One shared client; all RDAP lookups run concurrently.
    async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
        results = await asyncio.gather(*(_domain_age_signal(client, d) for d in domains))
    return [s for s in results if s is not None]


async def _redirect_final_domain(client: httpx.AsyncClient, url: str) -> tuple[str, str] | None:
    """Return (orig_domain, final_domain) after following redirects, or None."""
    try:
        resp = await client.head(url, follow_redirects=True)
        return registered_domain(url), registered_domain(str(resp.url))
    except (httpx.HTTPError, httpx.TimeoutException):
        return None


async def check_redirects(email: EmailIn) -> list[Signal]:
    urls = list(dict.fromkeys(email.urls))[:MAX_URLS]  # unique, order-preserving, capped
    if not urls:
        return []

    sender_domain = sender_domain_of(email.sender)

    async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
        results = await asyncio.gather(*(_redirect_final_domain(client, u) for u in urls))

    signals = []
    flagged = set()
    for pair in results:
        if pair is None:
            continue
        orig, final = pair
        # Not a cross-domain redirect.
        if orig == final:
            continue
        # Benign: a tracking link that redirects back to the sender's own site.
        if final == sender_domain:
            continue
        # Benign: the link starts on a known email/click-tracking platform.
        if orig in KNOWN_ESP_DOMAINS:
            continue
        # Dedup by destination so many tracking links don't repeat.
        if (orig, final) in flagged:
            continue
        flagged.add((orig, final))
        signals.append(Signal(
            code="redirect",
            message=f"Link redirects from '{orig}' to '{final}'",
            weight=25, severity="medium",
        ))
    return signals

