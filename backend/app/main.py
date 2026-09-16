from fastapi import FastAPI
from app.schemas import EmailIn, AnalyzeResponse
from app.heuristics import (check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to)
from app.scoring import score_signal


app = FastAPI()
RULES = [check_urgency, check_domain_mismatch, check_lookalike, check_ip_url, check_reply_to]

@app.post("/analyze", response_model = AnalyzeResponse)
async def analyze(payload: EmailIn):
    
    signals = []
    for rule in RULES: 
        signals += rule(payload)
    
    return score_signal(signals)