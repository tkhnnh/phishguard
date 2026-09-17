"""Combine signals into a single risk score + verdict.

A naive sum double-counts *correlated* evidence: three reputation sources
(Safe Browsing + blocklist + ML) firing on the same bad link are really one
piece of evidence, not three, yet a sum stacks them and inflates the score —
the main driver of false positives.

Fix: group signals by the KIND of evidence they represent and combine each
group with diminishing returns (the strongest signal counts fully; additional
signals in the same group add only half their weight). Independent groups then
sum, because different kinds of evidence genuinely reinforce each other.

Signals whose code isn't in any group are summed normally (backward compatible).
"""
from app.schemas import Signal, AnalyzeResponse

# Signal codes grouped by the kind of evidence they represent.
SIGNAL_GROUPS = {
    "reputation": {"safe_browsing", "blocklist", "ml_url"},
    "impersonation": {"domain_mismatch", "lookalike", "homograph", "reply_to_mismatch"},
    "content": {"urgency", "ml_email"},
    "technical": {"ip_url", "high_entropy", "redirect", "new_domain"},
}
_CODE_TO_GROUP = {code: g for g, codes in SIGNAL_GROUPS.items() for code in codes}

# Extra signals in the same group beyond the strongest count at this fraction.
_DIMINISH = 0.5


def _group_contribution(weights: list[int]) -> float:
    """Strongest weight counts fully; the rest at a diminished rate."""
    if not weights:
        return 0.0
    ordered = sorted(weights, reverse=True)
    return ordered[0] + _DIMINISH * sum(ordered[1:])


def score_signal(signals: list[Signal]) -> AnalyzeResponse:
    grouped: dict[str, list[int]] = {}
    ungrouped_total = 0
    for s in signals:
        group = _CODE_TO_GROUP.get(s.code)
        if group is None:
            ungrouped_total += s.weight
        else:
            grouped.setdefault(group, []).append(s.weight)

    total = ungrouped_total + sum(_group_contribution(w) for w in grouped.values())
    score = int(min(round(total), 100))

    verdict = "Safe" if score < 30 else "Suspicious" if score < 70 else "Dangerous"
    return AnalyzeResponse(score=score, verdict=verdict, signals=signals)
