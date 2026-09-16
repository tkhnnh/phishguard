import httpx
import respx
from app.schemas import EmailIn
from app.reputation import (check_safe_browsing, check_domain_age,SAFE_BROWSING_URL, RDAP_URL, check_redirects)
from app.config import settings
from datetime import (datetime, timezone,timedelta)
from tests.test_heuristics import make_email



async def test_safe_browsing_skips_when_no_urls():
    assert await check_safe_browsing(make_email(urls=[])) == []


async def test_safe_browsing_skips_when_no_key(monkeypatch):
    monkeypatch.setattr(settings, "safe_browsing_api_key", "")
    assert await check_safe_browsing(make_email(urls=["http://x.com"])) == []


@respx.mock
async def test_safe_browsing_flags_a_match(monkeypatch):
    monkeypatch.setattr(settings, "safe_browsing_api_key", "test-key")
    respx.post(SAFE_BROWSING_URL).mock(return_value=httpx.Response(200, json={
        "matches": [
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "http://bad.com"}}
        ]
    }))
    signals = await check_safe_browsing(make_email(urls=["http://bad.com"]))
    assert len(signals) == 1
    assert signals[0].code == "safe_browsing"


@respx.mock
async def test_safe_browsing_clean_response(monkeypatch):
    monkeypatch.setattr(settings, "safe_browsing_api_key", "test-key")
    respx.post(SAFE_BROWSING_URL).mock(return_value=httpx.Response(200, json={}))
    assert await check_safe_browsing(make_email(urls=["http://good.com"])) == []


@respx.mock
async def test_safe_browsing_degrades_on_error(monkeypatch):
    monkeypatch.setattr(settings, "safe_browsing_api_key", "test-key")
    respx.post(SAFE_BROWSING_URL).mock(return_value=httpx.Response(500))
    assert await check_safe_browsing(make_email(urls=["http://x.com"])) == []

@respx.mock    
async def test_domain_age_fires_on_a_young_domain():
    recent = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    respx.get(RDAP_URL + "newphish.com").mock(
        return_value=httpx.Response(200, json={
            "events": [
                {"eventAction": "registration", "eventDate": recent},
                {"eventAction": "last changed",  "eventDate": recent},
            ]
        })
    )
    
    signals = await check_domain_age(make_email(urls=["https://newphish.com/login"]))
    
    assert len(signals) ==1
    assert signals[0].code == "new_domain"
    

async def test_domain_age_no_urls():
    assert await check_domain_age(make_email(urls=[])) == []

@respx.mock  
async def test_domain_age_old_domain():
    respx.get(RDAP_URL + "oldphish.com").mock(
        return_value=httpx.Response(200, json={
            "events": [
                {"eventAction": "registration", "eventDate": "1999-03-27T05:00:00Z" },
                {"eventAction": "last changed",  "eventDate": "1999-03-27T05:00:00Z"},
            ]
        })
    )
    
    assert  await check_domain_age(make_email(urls= ["oldphish.com"])) == []
    
@respx.mock
async def test_domain_age_degrades_on_error():
    respx.get(RDAP_URL + "error.com").mock(
        return_value=httpx.Response(500)
    )
    assert await check_domain_age(make_email(urls = ["error.com"])) == []
    
@respx.mock
async def test_domain_degrades_registration_event_missing():
    respx.get(RDAP_URL+ "registrationeventmissing.com").mock(
        return_value= httpx.Response(200, json = {
            "events": []
        })
    )
    assert await check_domain_age(make_email(urls = ["registrationeventmissing.com"])) == []
    
    
@respx.mock
async def test_redirects_fires_on_URL_redirects():
    respx.head("http://bit.ly/x").mock(
        return_value=httpx.Response(301, headers={"Location": "http://evil.com/login"})
    )
    respx.head("http://evil.com/login").mock(return_value=httpx.Response(200))
    
    signals = await check_redirects(make_email(urls=["http://bit.ly/x"]))
    assert len(signals) == 1
    assert all(s.code == "redirect" for s in signals)
    
@respx.mock
async def test_redirects_silent():
    respx.head("http://normal.com").mock(
        return_value=httpx.Response(200)
    )
    assert await check_redirects(make_email(urls=["http://normal.com"])) == []
    
@respx.mock
async def test_redirects_degrades_on_error():
    respx.head("http://abnormal.com").mock(
        side_effect=httpx.ConnectError("boom")
    )
    assert await check_redirects(make_email(urls=["http://abnormal.com"])) == []