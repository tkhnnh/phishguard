from app.schemas import Signal, AnalyzeResponse
from app.scoring import score_signal

def sig(weight):
    """Helper: to build a signature with cusomizable weight"""
    return Signal(code="test", message="x", weight=weight, severity="low")

def test_scoring_with_empty_list():
    result = score_signal([])
    assert result.score ==0
    assert result.verdict == "Safe"
    assert result.signals == []
    
def test_below_threshold():
    result = score_signal([sig(20)])
    assert result.score == 20
    assert result.verdict == "Safe"
    
def test_boundary_at_30():
    result = score_signal([sig(30)])
    assert result.score == 30
    assert result.verdict == "Suspicious"
    
def test_boundary_at_mid_range():
    result = score_signal([sig(40)])
    assert result.verdict == "Suspicious"
    
def test_boundary_at_70():
    result = score_signal([sig(70)])
    assert result.score == 70
    assert result.verdict == "Dangerous"
    
def test_cap_at_100():
    result = score_signal([sig(50),sig(50),sig(50)])
    assert result.score == 100
    assert result.verdict == "Dangerous"
    
def test_signals_pass_through():
    result = score_signal([sig(4), sig(10)])
    assert len(result.signals) == 2