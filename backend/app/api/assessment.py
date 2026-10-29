"""Assessment router.

GET  /assessment/questions
POST /assessment
GET  /assessment/latest
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Assessment, AssessmentAnswer
from app.schemas.schemas import (
    AreaBreakdown,
    AssessmentRequest,
    AssessmentResponse,
    ErrorResponse,
    TopAction,
)
from app.services.auth import AuthError, get_current_user
from app.services.health_check import compute_score
from app.services.kb_loader import kb

log = logging.getLogger(__name__)
router = APIRouter(prefix="/assessment", tags=["assessment"])


def _get_user(request: Request, db: Session):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "MISSING_TOKEN", "message": "Authorization required."}},
        )
    try:
        return get_current_user(token, db)
    except AuthError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc


@router.get("/questions")
def get_questions() -> list[dict]:
    questions = kb.all_questions()
    return [
        {
            "id": q.id,
            "area": q.area,
            "text": q.text,
            "weight": q.weight,
            "why_it_matters": q.why_it_matters,
        }
        for q in questions
    ]


@router.post(
    "",
    response_model=AssessmentResponse,
    status_code=201,
    responses={401: {"model": ErrorResponse}},
)
def submit_assessment(
    req: AssessmentRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> AssessmentResponse:
    user = _get_user(request, db)
    if not user.business_id:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "NO_BUSINESS", "message": "User has no associated business."}},
        )

    questions = kb.all_questions()
    recommendations = kb.all_recommendations()
    answers_map = {a.question_id: a.answer for a in req.answers}

    score, band, breakdown, top_actions = compute_score(answers_map, questions, recommendations)

    assessment = Assessment(
        business_id=user.business_id,
        score=score,
        band=band,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(assessment)
    db.flush()

    for ans in req.answers:
        db.add(
            AssessmentAnswer(
                assessment_id=assessment.id,
                question_id=ans.question_id,
                answer=ans.answer,
            )
        )
    db.commit()
    db.refresh(assessment)

    return AssessmentResponse(
        id=assessment.id,
        score=score,
        band=band,
        breakdown=[
            AreaBreakdown(area=b.area, score=b.score, max_score=b.max_score)
            for b in breakdown
        ],
        top_actions=[
            TopAction(
                recommendation_id=t.recommendation_id,
                title=t.title,
                effort=t.effort,
                weight=t.weight,
            )
            for t in top_actions
        ],
    )


@router.get(
    "/latest",
    responses={401: {"model": ErrorResponse}},
)
def latest_assessment(
    request: Request,
    db: Session = Depends(get_db),
) -> dict:
    user = _get_user(request, db)
    if not user.business_id:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "No assessment found."}},
        )

    assessment = (
        db.query(Assessment)
        .filter(Assessment.business_id == user.business_id)
        .order_by(Assessment.completed_at.desc())
        .first()
    )
    if not assessment:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "No assessment found."}},
        )

    return {
        "id": assessment.id,
        "score": assessment.score,
        "band": assessment.band,
        "completed_at": assessment.completed_at,
    }
