"""Actions router: GET /actions, PATCH /actions/{id}."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import ActionItem, ActionStatus
from app.schemas.schemas import ActionItemOut, ActionPatchRequest, ErrorResponse
from app.services.auth import AuthError, get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/actions", tags=["actions"])


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


@router.get("", response_model=list[ActionItemOut])
def list_actions(
    request: Request,
    db: Session = Depends(get_db),
) -> list[ActionItemOut]:
    user = _get_user(request, db)
    if not user.business_id:
        return []
    items = (
        db.query(ActionItem)
        .filter(ActionItem.business_id == user.business_id)
        .all()
    )
    return [ActionItemOut.model_validate(i) for i in items]


@router.patch(
    "/{action_id}",
    response_model=ActionItemOut,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def patch_action(
    action_id: str,
    body: ActionPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> ActionItemOut:
    user = _get_user(request, db)
    item = (
        db.query(ActionItem)
        .filter(
            ActionItem.id == action_id,
            ActionItem.business_id == user.business_id,
        )
        .first()
    )
    if not item:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "NOT_FOUND", "message": "Action item not found."}},
        )
    item.status = body.status
    if body.due_date is not None:
        item.due_date = body.due_date
    db.commit()
    db.refresh(item)
    return ActionItemOut.model_validate(item)
