from app.schemas import (EmailIn, Signal)
import tldextract
import difflib
import re
import math
from collections import Counter

URGENCY_PHRASES = [
    "verify your account",
    "account suspended",
    "within 24 hours",
    "act now",
    "confirm your password",
]

PROTECTED_BRANDS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com",
]

IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")

# Email service providers / newsletter platforms: links legitimately point here
# even when the sender is a different domain, so don't flag these as mismatches.
KNOWN_ESP_DOMAINS = {
    "beehiiv.com",
    "beehiivstatus.com",
    "list-manage.com",     # Mailchimp
    "mcusercontent.com",   # Mailchimp
    "sendgrid.net",
    "mailgun.org",
    "rs6.net",             # Constant Contact
    "substack.com",
    "cmail19.com",         # Campaign Monitor (varies: cmailNN.com)
    "hubspotlinks.com",
    "klaviyomail.com",
    "sparkpostmail.com",
}

def check_urgency(email: EmailIn) -> list[Signal]:
    signals = []
    text = (email.subject + " " + email.body_text).lower()
    for phrase in URGENCY_PHRASES:
        if phrase in text:
            signals.append(Signal(code="urgency",message=f"Urgent-action language: '{phrase}'",weight=20, severity="medium",))
    
    return signals   

def registered_domain(value: str) -> str:
    ext = tldextract.extract(value)
    return f"{ext.domain}.{ext.suffix}".lower()

def sender_domain_of(header: str) -> str | None:
    if not header or "@" not in header:
        return None
    address = header.split('@')[1].strip('>')
    dom = registered_domain(address)
    return dom if "." in dom else None

def check_domain_mismatch(email: EmailIn) -> list[Signal]:
    signals = []
    
    if not email.urls:
        return []
    
    if '@' not in email.sender:
        return []
    
    sender_domain = sender_domain_of(email.sender)
    
    if not sender_domain or "." not in sender_domain:
        return []
    
    flagged = set() 
    for url in email.urls:
        link_domain = registered_domain(url)
        if link_domain in KNOWN_ESP_DOMAINS:
            continue
        if link_domain != sender_domain and link_domain not in flagged:
            flagged.add(link_domain)
            signals.append(Signal(
                    code="domain_mismatch",
                    message=f"Link domain '{link_domain}' differs from sender '{sender_domain}'",
                    weight=35,
                    severity="high",))
    
    return signals

def check_lookalike(email: EmailIn) -> list[Signal]:
    signals = []
    flagged = set()
    for url in email.urls:
        domain = registered_domain(url)
        match = difflib.get_close_matches(domain, PROTECTED_BRANDS, n=1, cutoff=0.8)
        if match and match[0] != domain and match[0] not in flagged:
            flagged.add(match[0])
            signals.append(Signal(
                code="lookalike",
                message=f"Domain '{domain}' looks like '{match[0]}'",
                weight=40,
                severity="high",
            ))
        
        
        if "xn--" in domain and domain not in flagged:
            flagged.add(domain)
            signals.append(Signal(
            code="homograph",
            message=f"Domain '{domain}' uses punycode (possible homograph attack)",
            weight=35,
            severity="high",
        ))
            
    return signals

def check_ip_url(email: EmailIn)-> list[Signal]:
    signals = []
    flagged = set()
    for url in email.urls:
        match = IP_URL_PATTERN.search(url)
        if match:
            ip = match.group()
            if ip not in flagged:
                flagged.add(ip)
                signals.append(Signal(code="ip_url", message=f"Link uses a raw IP address instead of a domain: {url}", weight=30, severity="high",))
    
    return signals


def check_reply_to(email:EmailIn) -> list[Signal]:
    signals = []
    from_domain = sender_domain_of(email.sender)
    reply_domain = sender_domain_of(email.reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        signals.append(Signal(
            code="reply_to_mismatch",
            message=f"Reply-To domain '{reply_domain}' differs from sender '{from_domain}'",
            weight=25,
            severity="medium",
        ))
        
    return signals


# Entropy = the average number of bits needed to describe the next character of the string
def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (c/length) * math.log2(c/ length)
        for c in counts.values()
    )
    
def check_url_entropy(email: EmailIn) -> list[Signal]:
    signals = []
    flagged = set()
    for url in email.urls:
        domain = registered_domain(url)
        entropy = shannon_entropy(domain)
        if entropy > 3.5 and domain not in flagged:
            flagged.add(entropy)
            signals.append(Signal(code="high_entropy", message=f"Link domain '{domain}' looks random (entropy {entropy:.2f})", weight=15,severity="low",))    
    return signals