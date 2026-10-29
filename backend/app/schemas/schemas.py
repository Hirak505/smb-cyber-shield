"""Pydantic v2 schemas for request/response validation."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    business_name: str = Field(min_length=1, max_length=255)
    role: str = Field(default="owner", pattern="^(owner|employee)$")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not _EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter.")
        return v


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not _EMAIL_REGEX.match(v):
            raise ValueError("Invalid email format")
        return v.lower()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    business_id: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class HealthOut(BaseModel):
    status: str
    version: str = "0.1.0"
    env: str


# ---------------------------------------------------------------------------
# Scan – message
# ---------------------------------------------------------------------------

class EvidenceSpan(BaseModel):
    start: int
    end: int
    rule_id: str
    text: str


class RuleHitOut(BaseModel):
    rule_id: str
    weight: int
    description: str
    evidence: list[EvidenceSpan] = Field(default_factory=list)


class ScanMessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_480)
    sender: str | None = Field(default=None, max_length=255)
    urls: list[str] | None = Field(default=None, max_length=20)


class ScanMessageResponse(BaseModel):
    verdict: str          # "Likely safe" | "Suspicious" | "Likely phishing"
    risk_score: int
    rules: list[RuleHitOut]
    explanation: str
    next_steps: list[str]
    evidence_spans: list[EvidenceSpan] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scan – link
# ---------------------------------------------------------------------------

class ScanLinkRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class ScanLinkResponse(BaseModel):
    verdict: str
    risk_score: int
    rules: list[RuleHitOut]


# ---------------------------------------------------------------------------
# Scan – domain
# ---------------------------------------------------------------------------

class ScanDomainRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=255)


class ScanDomainResponse(BaseModel):
    domain: str
    spf: str | None
    dkim: str | None
    dmarc: str | None
    findings: list[str]


# ---------------------------------------------------------------------------
# Scan – password
# ---------------------------------------------------------------------------

class ScanPasswordRequest(BaseModel):
    sha1_prefix: str = Field(min_length=5, max_length=5, pattern="^[0-9A-Fa-f]{5}$")


class ScanPasswordResponse(BaseModel):
    suffixes: list[str]    # client does the comparison locally


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

class AnswerIn(BaseModel):
    question_id: str
    answer: str = Field(pattern="^(yes|no|unsure)$")


class AssessmentRequest(BaseModel):
    answers: list[AnswerIn] = Field(min_length=1, max_length=25)


class AreaBreakdown(BaseModel):
    area: str
    score: float
    max_score: float


class TopAction(BaseModel):
    recommendation_id: str
    title: str
    effort: str
    weight: float


class AssessmentResponse(BaseModel):
    id: str
    score: int
    band: str
    breakdown: list[AreaBreakdown]
    top_actions: list[TopAction]


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

class ActionItemOut(BaseModel):
    id: str
    recommendation_id: str
    status: str
    due_date: str | None

    model_config = {"from_attributes": True}


class ActionPatchRequest(BaseModel):
    status: str = Field(pattern="^(todo|doing|done)$")
    due_date: str | None = None


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------

class PlaybookStepOut(BaseModel):
    id: str
    action: str
    time_target: str
    who: str
    kb_ref: str


class PlaybookOut(BaseModel):
    id: str
    title: str
    status: str
    steps: list[PlaybookStepOut]


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

class IncidentCreateRequest(BaseModel):
    playbook_id: str = Field(min_length=1, max_length=50)


class IncidentStepPatch(BaseModel):
    done: bool = True
    note: str | None = Field(default=None, max_length=500)


class IncidentStepOut(BaseModel):
    id: str
    step_id: str
    done_at: datetime | None
    note: str | None

    model_config = {"from_attributes": True}


class IncidentOut(BaseModel):
    id: str
    playbook_id: str
    status: str
    started_at: datetime
    closed_at: datetime | None
    steps: list[IncidentStepOut]

    model_config = {"from_attributes": True}


class IncidentExport(BaseModel):
    incident: IncidentOut
    playbook: PlaybookOut
    exported_at: datetime


# ---------------------------------------------------------------------------
# Lessons
# ---------------------------------------------------------------------------

class LessonOut(BaseModel):
    id: str
    title: str
    body_md: str

    model_config = {"from_attributes": True}


class QuizAnswerIn(BaseModel):
    answers: list[int] = Field(min_length=1, max_length=10)


class QuizResultOut(BaseModel):
    score: int
    total: int


# ---------------------------------------------------------------------------
# Common error envelope
# ---------------------------------------------------------------------------

class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
