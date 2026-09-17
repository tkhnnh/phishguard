from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware 
from app.schemas import (EmailIn, AnalyzeResponse)
from app.heuristics import (check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to, check_url_entropy)
from app.scoring import score_signal
from app.reputation import (check_safe_browsing, check_domain_age, check_redirects)
from app.feeds import (check_blocklist, load_feeds)
from contextlib import asynccontextmanager
import asyncio

@asynccontextmanager
async def lifespan(app: FastAPI):
    await load_feeds()
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # dev only — tighten before production
    allow_methods=["POST"],
    allow_headers=["*"],
)

RULES = [check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to, check_url_entropy, check_blocklist]

@app.post("/analyze", response_model = AnalyzeResponse)
async def analyze(payload: EmailIn):
    
    signals = []
    for rule in RULES: 
        signals += rule(payload)
    # Run the three network-bound checks concurrently instead of one after
    # another, so response time is the slowest one, not their sum.
    sb, age, redirects = await asyncio.gather(
        check_safe_browsing(payload),
        check_domain_age(payload),
        check_redirects(payload),
    )
    signals += sb + age + redirects
    return score_signal(signals)