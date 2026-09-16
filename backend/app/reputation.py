import httpx
from app.schemas import (EmailIn, Signal)
from app.config import settings
from datetime import (datetime, timezone)
from app.heuristics import registered_domain

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
        
async def check_domain_age(email: EmailIn) -> list[Signal]:
    signals = []
    seen = set()
    for url in email.urls:
        domain = registered_domain(url)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                resp = await client.get(RDAP_URL + domain)
            resp.raise_for_status()
            data = resp.json()
            events = data.get("events", [])
            if not events:
                continue
            for event in events:
                if event.get("eventAction") == "registration":
                    event_date = event.get("eventDate")
                    reformat_event_date = datetime.fromisoformat(event_date.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - reformat_event_date).days
                    if age_days < 30:
                        signals.append(Signal(code="new_domain",
                    message=f"Domain '{domain}' registered {age_days} days ago",
                    weight=30, severity="high",))
                    
        except (httpx.HTTPError, httpx.TimeoutException, ValueError, KeyError):
            continue
    return signals

async def check_redirects(email: EmailIn) -> list[Signal]:
    signals = []
    seen = set()
    for url in email.urls:
        if url in seen:
            continue
        seen.add(url)
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
                resp = await client.head(url, follow_redirects=True)
            final_url = str(resp.url)
            orig = registered_domain(url)
            final = registered_domain(final_url)
            if orig != final:
                    signals.append(Signal(code="redirect",
                    message=f"Link redirects from '{orig}' to '{final}'",
                    weight=25, severity="medium"))
           
        except (httpx.HTTPError, httpx.TimeoutException):
            continue
    return signals

