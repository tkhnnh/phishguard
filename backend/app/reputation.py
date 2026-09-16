import httpx
from app.schemas import EmailIn, Signal
from app.config import settings

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

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
        
