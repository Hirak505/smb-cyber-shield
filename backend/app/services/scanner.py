"""Scanner service: wraps rules engine, stores scan, returns response."""
from __future__ import annotations

import hashlib
import json
import logging

from sqlalchemy.orm import Session

from app.models.models import Scan, ScanType
from app.rules.scanner import Context, ParsedMessage, RuleHit, score_message
from app.schemas.schemas import (
    EvidenceSpan,
    RuleHitOut,
    ScanMessageResponse,
    ScanLinkResponse,
)
from app.services.kb_loader import kb

log = logging.getLogger(__name__)

_STATIC_NEXT_STEPS = {
    "Likely phishing": [
        "Do not click any links or open attachments in the message.",
        "Report the message to your email provider as phishing.",
        "Warn colleagues if relevant.",
        "If you already clicked a link, follow the phishing-click playbook.",
    ],
    "Suspicious": [
        "Verify through a second channel before taking any action.",
        "Do not enter credentials or payment details.",
        "Check the sender domain carefully.",
    ],
    "Likely safe": [
        "No immediate action required.",
        "Continue to exercise normal caution.",
    ],
}


def _hash_input(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _snippet(text: str, max_len: int = 200) -> str:
    """Return first max_len chars – never stores full body."""
    return text[:max_len] if len(text) > max_len else text


def _rule_hit_to_out(hit: RuleHit) -> RuleHitOut:
    return RuleHitOut(
        rule_id=hit.rule_id,
        weight=hit.weight,
        description=hit.description,
        evidence=[
            EvidenceSpan(start=s.start, end=s.end, rule_id=s.rule_id, text=s.text)
            for s in hit.evidence
        ],
    )


def scan_message(
    text: str,
    sender: str | None,
    urls: list[str] | None,
    db: Session,
    business_id: str | None = None,
) -> ScanMessageResponse:
    msg = ParsedMessage(text=text, sender=sender, urls=urls)
    ctx = Context()

    risk_score, verdict, hits = score_message(msg, ctx)

    # Build response
    rules_out = [_rule_hit_to_out(h) for h in hits]
    all_spans = [span for h in hits for span in h.evidence]
    all_spans_out = [
        EvidenceSpan(start=s.start, end=s.end, rule_id=s.rule_id, text=s.text)
        for s in all_spans
    ]

    # Static explanation (LLM is optional / post-MVP)
    if hits:
        reasons = "; ".join(h.description for h in hits[:3])
        explanation = f"This message triggered {len(hits)} detection rule(s): {reasons}."
    else:
        explanation = "No suspicious patterns were detected."

    next_steps = _STATIC_NEXT_STEPS.get(verdict, [])

    # Persist scan – store hash + snippet only (privacy)
    try:
        rules_json = json.dumps([{"rule_id": h.rule_id, "weight": h.weight} for h in hits])
        scan = Scan(
            business_id=business_id,
            type=ScanType.message,
            input_hash=_hash_input(text),
            verdict=verdict,
            risk_score=risk_score,
            triggered_rules_json=rules_json,
            explanation=explanation,
            evidence_snippet=_snippet(text),
        )
        db.add(scan)
        db.commit()
    except Exception as exc:
        log.warning("Failed to persist scan: %s", exc)
        db.rollback()

    return ScanMessageResponse(
        verdict=verdict,
        risk_score=risk_score,
        rules=rules_out,
        explanation=explanation,
        next_steps=next_steps,
        evidence_spans=all_spans_out,
    )


def scan_link(
    url: str,
    db: Session,
    business_id: str | None = None,
) -> ScanLinkResponse:
    """Run link-specific rules only (R04, R05)."""
    from app.rules.scanner import rule_r04, rule_r05, Context, ParsedMessage

    msg = ParsedMessage(text=url, urls=[url])
    ctx = Context()

    hits: list[RuleHit] = []
    for rule_fn in [rule_r04, rule_r05]:
        h = rule_fn(msg, ctx)
        if h:
            hits.append(h)

    risk_score = min(100, sum(h.weight for h in hits))
    if risk_score >= 60:
        verdict = "Likely phishing"
    elif risk_score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Likely safe"

    try:
        scan = Scan(
            business_id=business_id,
            type=ScanType.link,
            input_hash=_hash_input(url),
            verdict=verdict,
            risk_score=risk_score,
        )
        db.add(scan)
        db.commit()
    except Exception as exc:
        log.warning("Failed to persist link scan: %s", exc)
        db.rollback()

    return ScanLinkResponse(
        verdict=verdict,
        risk_score=risk_score,
        rules=[_rule_hit_to_out(h) for h in hits],
    )
