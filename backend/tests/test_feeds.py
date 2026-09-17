from app import feeds
from app.feeds import check_blocklist
from tests.test_heuristics import make_email
import httpx
import respx
import pytest


@pytest.fixture(autouse=True)
def clear_blocklist():
    feeds.BLOCKLIST_HOSTS.clear()
    yield
    feeds.BLOCKLIST_HOSTS.clear()


def test_blocklist_fires_on_blocked_host():
    feeds.BLOCKLIST_HOSTS.add("badphish.com")
    signals = check_blocklist(make_email(urls=["badphish.com"]))
    assert len(signals) == 1
    assert all(s.code == "blocklist" for s in signals)


def test_blocklist_on_clean_host():
    assert check_blocklist(make_email(urls=["helloworld.com"])) == []


def test_blocklist_skips_shared_platform():
    # A phishing page on sites.google.com must NOT cause legit google.com links
    # to be flagged — the registered domain is on NEVER_BLOCKLIST.
    feeds.BLOCKLIST_HOSTS.add("sites.google.com")
    assert check_blocklist(make_email(urls=["https://www.google.com/maps"])) == []


@respx.mock
async def test_load_feeds_populates_hosts_from_both_feeds():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://evil.com/login\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(200, text="http://malware.net/x\n"))
    await feeds.load_feeds()
    assert "evil.com" in feeds.BLOCKLIST_HOSTS
    assert "malware.net" in feeds.BLOCKLIST_HOSTS


@respx.mock
async def test_load_feeds_stores_full_hostname():
    # Hostname, not registered domain: sub.badphish.com stays as-is so we don't
    # over-block the whole registered domain.
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://sub.badphish.com/a\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(200, text=""))
    await feeds.load_feeds()
    assert "sub.badphish.com" in feeds.BLOCKLIST_HOSTS


@respx.mock
async def test_load_feeds_degrades_when_one_feed_fails():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://openphish-host.com/a\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(500))
    await feeds.load_feeds()
    assert "openphish-host.com" in feeds.BLOCKLIST_HOSTS


@respx.mock
async def test_load_feeds_replaces_old_contents_on_reload():
    respx.get(feeds.OPENPHISH_FEED).mock(return_value=httpx.Response(200, text="http://fresh.com/x\n"))
    respx.get(feeds.URLHAUS_FEED).mock(return_value=httpx.Response(200, text=""))
    feeds.BLOCKLIST_HOSTS.add("stale.com")
    await feeds.load_feeds()
    assert "stale.com" not in feeds.BLOCKLIST_HOSTS
