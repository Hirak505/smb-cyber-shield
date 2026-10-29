"""Playbook + Incident router.

GET  /playbooks
GET  /playbooks/{id}
POST /incidents
PATCH /incidents/{id}/steps/{step_id}
GET  /incidents/{id}/export
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.schemas import (
    ErrorResponse,
    IncidentCreateRequest,
    IncidentExport,
    IncidentOut,
    IncidentStepPatch,
    PlaybookOut,
    UserOut,
)
from app.services.auth import AuthError, get_current_user
from app.services.playbooks import PlaybookError, create_incident, complete_step
from app.services.playbooks import export_incident, get_incident, list_playbooks, get_playbook

log = logging.getLogger(__name__)
router = APIRouter(tags=["playbooks"])


def _get_user(request: Request, db: Session) -> UserOut:
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


@router.get("/playbooks", response_model=list[PlaybookOut])
def get_playbooks() -> list[PlaybookOut]:
    return list_playbooks()


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut)
def get_playbook_by_id(playbook_id: str) -> PlaybookOut:
    try:
        return get_playbook(playbook_id)
    except PlaybookError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc


@router.post(
    "/incidents",
    response_model=IncidentOut,
    status_code=201,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def create_incident_endpoint(
    req: IncidentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> IncidentOut:
    user = _get_user(request, db)
    if not user.business_id:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "NO_BUSINESS", "message": "User has no associated business."}},
        )
    try:
        return create_incident(req.playbook_id, user.business_id, db)
    except PlaybookError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc


@router.patch(
    "/incidents/{incident_id}/steps/{step_id}",
    response_model=IncidentOut,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def patch_incident_step(
    incident_id: str,
    step_id: str,
    body: IncidentStepPatch,
    request: Request,
    db: Session = Depends(get_db),
) -> IncidentOut:
    user = _get_user(request, db)
    if not user.business_id:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "NO_BUSINESS", "message": "User has no associated business."}},
        )
    try:
        return complete_step(
            incident_id=incident_id,
            step_id=step_id,
            done=body.done,
            note=body.note,
            business_id=user.business_id,
            db=db,
        )
    except PlaybookError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc


@router.get(
    "/incidents/{incident_id}/export",
    response_model=IncidentExport,
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def export_incident_endpoint(
    incident_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> IncidentExport:
    user = _get_user(request, db)
    if not user.business_id:
        raise HTTPException(
            status_code=400,
            detail={"error": {"code": "NO_BUSINESS", "message": "User has no associated business."}},
        )
    try:
        return export_incident(incident_id, user.business_id, db)
    except PlaybookError as exc:
        raise HTTPException(
            status_code=exc.status,
            detail={"error": {"code": exc.code, "message": exc.message}},
        ) from exc
