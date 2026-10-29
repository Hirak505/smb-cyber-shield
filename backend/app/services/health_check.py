"""Health-check scoring service – pure function, no I/O.

score(answers, questions) -> score, band, per_area_breakdown, top5_actions
"""
from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict


@dataclass
class AreaBreakdown:
    area: str
    score: float
    max_score: float


@dataclass
class TopAction:
    recommendation_id: str
    title: str
    effort: str
    weight: float


_EFFORT_ORDER = {"low": 0, "med": 1, "high": 2}

_BAND_LABELS = [
    (70, 100, "Lower risk"),
    (40, 69, "Medium risk"),
    (0, 39, "High risk"),
]


def compute_score(
    answers: dict[str, str],   # {question_id: "yes"|"no"|"unsure"}
    questions: list,            # list of KBQuestion
    recommendations: list,      # list of KBRecommendation
) -> tuple[int, str, list[AreaBreakdown], list[TopAction]]:
    """
    Compute health-check score.

    Rules:
    - 'yes'    = full weight (safe)
    - 'no'     = 0 (unsafe)
    - 'unsure' = 0 (counts as unsafe, per PRD)

    Score = (earned_weight / total_weight) * 100, rounded to int.
    """
    if not questions:
        return 0, "High risk", [], []

    total_weight = sum(q.weight for q in questions)
    if total_weight == 0:
        return 0, "High risk", [], []

    earned_weight = 0
    area_earned: dict[str, float] = defaultdict(float)
    area_total: dict[str, float] = defaultdict(float)
    failed_recs: dict[str, float] = defaultdict(float)  # rec_id -> weight deficit

    for q in questions:
        area_total[q.area] += q.weight
        answer = answers.get(q.id, "unsure")
        if answer == "yes":
            earned_weight += q.weight
            area_earned[q.area] += q.weight
        else:
            # Track which recommendations need attention (weight = urgency)
            failed_recs[q.recommendation_id] += q.weight

    score = round((earned_weight / total_weight) * 100)

    band = "High risk"
    for lo, hi, label in _BAND_LABELS:
        if lo <= score <= hi:
            band = label
            break

    breakdown = [
        AreaBreakdown(
            area=area,
            score=area_earned.get(area, 0),
            max_score=total,
        )
        for area, total in sorted(area_total.items())
    ]

    # Top 5 by (weight_deficit DESC, effort ASC)
    rec_map = {r.id: r for r in recommendations}
    sorted_recs = sorted(
        failed_recs.items(),
        key=lambda x: (-x[1], _EFFORT_ORDER.get(rec_map.get(x[0], _FakeRec()).effort, 99)),
    )[:5]

    top_actions = []
    for rec_id, deficit in sorted_recs:
        rec = rec_map.get(rec_id)
        if rec:
            top_actions.append(
                TopAction(
                    recommendation_id=rec.id,
                    title=rec.title,
                    effort=rec.effort,
                    weight=deficit,
                )
            )

    return score, band, breakdown, top_actions


class _FakeRec:
    """Fallback object when recommendation not found in KB."""
    effort = "high"
