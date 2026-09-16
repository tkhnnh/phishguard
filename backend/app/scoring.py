from app.schemas import (Signal, AnalyzeResponse)

def score_signal(signals: list[Signal]) -> AnalyzeResponse:
    total = sum(s.weight for s in signals)
    score = min(total, 100)
    verdict = "Safe" if score < 30 else "Suspicious" if score < 70 else "Dangerous"
    return AnalyzeResponse(score=score , verdict=verdict,signals=signals)