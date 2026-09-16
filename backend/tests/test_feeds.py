from app import feeds
from app.heuristics import registered_domain
from app.feeds import check_blocklist, load_feeds
from tests.test_heuristics import make_email
import httpx
import respx
import pytest

@pytest.fixture(autouse=True)
def clear_blocklist():
    feeds.BLOCKLIST_DOMAINS.clear()
    yield
    feeds.BLOCKLIST_DOMAINS.clear()



def test_blocklist_fires_on_blocked_domain():
    feeds.BLOCKLIST_DOMAINS.add("badphish.com")
    signals = check_blocklist(make_email(urls = ["badphish.com"]))
    assert len(signals) == 1
    assert all(s.code == "blocklist" for s in signals)
    
def test_blocklist_on_clean_domaiN():
    assert check_blocklist(make_email(urls = ["helloworld.com"])) == []
    
    
@respx.mock
async def test_load_feeds_populates_domains_from_both_feeds():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://evil.com/login\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(200, text="http://malware.net/x\n"))
    await feeds.load_feeds()
    assert "evil.com" in feeds.BLOCKLIST_DOMAINS
    assert "malware.net" in feeds.BLOCKLIST_DOMAINS
    
    
@respx.mock
async def test_load_feeds_reduces_URLs_to_registered_domains():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://sub.badphish.com/a\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(200, text="http://sub.badphish.com/b\n"))
    await feeds.load_feeds()
    assert "badphish.com" in feeds.BLOCKLIST_DOMAINS
    
@respx.mock
async def test_load_feeds_degrades_when_one_feed_fails():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://sub.badphish.com/a\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(500, text="http://sub.badphish.com/b\n"))
    await feeds.load_feeds()
    assert "badphish.com" in feeds.BLOCKLIST_DOMAINS

@respx.mock
async def test_load_feeds_replaces_old_contents_on_reload():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://fresh.com/x\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(200, text=""))
    feeds.BLOCKLIST_DOMAINS.add("stale.com")
    await feeds.load_feeds()
    assert "stale.com" not in feeds.BLOCKLIST_DOMAINS
    
  
    
