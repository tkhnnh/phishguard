from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware 
from app.schemas import EmailIn, AnalyzeResponse
from app.heuristics import (check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to, check_url_entropy)
from app.scoring import score_signal
from app.reputation import (check_safe_browsing, check_domain_age)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # dev only — tighten before production
    allow_methods=["POST"],
    allow_headers=["*"],
)

RULES = [check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to, check_url_entropy]

@app.post("/analyze", response_model = AnalyzeResponse)
async def analyze(payload: EmailIn):
    
    signals = []
    for rule in RULES: 
        signals += rule(payload)
    signals += await check_safe_browsing(payload)
    signals += await check_domain_age(payload)
    return score_signal(signals)