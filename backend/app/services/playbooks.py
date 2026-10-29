"""Playbook (incident) service – wraps kb_loader + DB operations."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.models import Incident, IncidentStatus, IncidentStep
from app.schemas.schemas import (
    IncidentExport,
    IncidentOut,
    IncidentStepOut,
    PlaybookOut,
    PlaybookStepOut,
)
from app.services.kb_loader import KBPlaybook, kb

log = logging.getLogger(__name__)


class PlaybookError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        self.code = code
        self.message = message
        self.status = status
        super().__init__(message)


def _playbook_to_out(pb: KBPlaybook) -> PlaybookOut:
    return PlaybookOut(
        id=pb.id,
        title=pb.title,
        status=pb.status,
        steps=[
            PlaybookStepOut(
                id=s.id,
                action=s.action,
                time_target=s.time_target,
                who=s.who,
                kb_ref=s.kb_ref,
            )
            for s in pb.steps
        ],
    )


def _incident_to_out(incident: Incident) -> IncidentOut:
    return IncidentOut(
        id=incident.id,
        playbook_id=incident.playbook_id,
        status=incident.status,
        started_at=incident.started_at,
        closed_at=incident.closed_at,
        steps=[
            IncidentStepOut(
                id=s.id,
                step_id=s.step_id,
                done_at=s.done_at,
                note=s.note,
            )
            for s in incident.steps
        ],
    )


# ---------------------------------------------------------------------------
# Playbook read operations
# ---------------------------------------------------------------------------

def list_playbooks() -> list[PlaybookOut]:
    return [_playbook_to_out(pb) for pb in kb.all_playbooks()]


def get_playbook(playbook_id: str) -> PlaybookOut:
    pb = kb.get_playbook(playbook_id)
    if not pb:
        raise PlaybookError("NOT_FOUND", f"Playbook '{playbook_id}' not found.", 404)
    return _playbook_to_out(pb)


# ---------------------------------------------------------------------------
# Incident CRUD
# ---------------------------------------------------------------------------

def create_incident(
    playbook_id: str,
    business_id: str,
    db: Session,
) -> IncidentOut:
    pb = kb.get_playbook(playbook_id)
    if not pb:
        raise PlaybookError("NOT_FOUND", f"Playbook '{playbook_id}' not found.", 404)

    incident = Incident(
        business_id=business_id,
        playbook_id=playbook_id,
        status=IncidentStatus.open,
    )
    db.add(incident)
    db.flush()

    # Pre-create step rows (all uncompleted)
    for step in pb.steps:
        db.add(IncidentStep(incident_id=incident.id, step_id=step.id))

    db.commit()
    db.refresh(incident)
    return _incident_to_out(incident)


def get_incident(incident_id: str, business_id: str, db: Session) -> IncidentOut:
    incident = _fetch_incident(incident_id, business_id, db)
    return _incident_to_out(incident)


def complete_step(
    incident_id: str,
    step_id: str,
    done: bool,
    note: str | None,
    business_id: str,
    db: Session,
) -> IncidentOut:
    incident = _fetch_incident(incident_id, business_id, db)

    step = next(
        (s for s in incident.steps if s.step_id == step_id), None
    )
    if step is None:
        raise PlaybookError("NOT_FOUND", f"Step '{step_id}' not in incident.", 404)

    step.done_at = datetime.now(timezone.utc) if done else None
    step.note = note

    # Auto-close if all steps done
    if all(s.done_at is not None for s in incident.steps):
        incident.status = IncidentStatus.closed
        incident.closed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(incident)
    return _incident_to_out(incident)


def export_incident(incident_id: str, business_id: str, db: Session) -> IncidentExport:
    incident = _fetch_incident(incident_id, business_id, db)
    pb_out = get_playbook(incident.playbook_id)
    return IncidentExport(
        incident=_incident_to_out(incident),
        playbook=pb_out,
        exported_at=datetime.now(timezone.utc),
    )


def _fetch_incident(incident_id: str, business_id: str, db: Session) -> Incident:
    incident = (
        db.query(Incident)
        .filter(
            Incident.id == incident_id,
            Incident.business_id == business_id,
        )
        .first()
    )
    if not incident:
        raise PlaybookError("NOT_FOUND", "Incident not found.", 404)
    return incident
