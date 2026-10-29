"""SQLAlchemy ORM models matching the DATA_MODEL.md specification."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class UserRole(str, enum.Enum):
    owner = "owner"
    employee = "employee"
    advisor = "advisor"


class SizeBand(str, enum.Enum):
    micro = "micro"     # 1-5
    small = "small"     # 6-25


class AnswerChoice(str, enum.Enum):
    yes = "yes"
    no = "no"
    unsure = "unsure"


class ActionStatus(str, enum.Enum):
    todo = "todo"
    doing = "doing"
    done = "done"


class EffortLevel(str, enum.Enum):
    low = "low"
    med = "med"
    high = "high"


class ScanType(str, enum.Enum):
    message = "message"
    link = "link"
    domain = "domain"
    password = "password"


class IncidentStatus(str, enum.Enum):
    open = "open"
    closed = "closed"


# ---------------------------------------------------------------------------
# Business
# ---------------------------------------------------------------------------

class Business(Base):
    __tablename__ = "businesses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    size_band: Mapped[str | None] = mapped_column(
        Enum(SizeBand), nullable=True
    )
    industry: Mapped[str | None] = mapped_column(String(100), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    users: Mapped[list["User"]] = relationship("User", back_populates="business")
    assessments: Mapped[list["Assessment"]] = relationship(
        "Assessment", back_populates="business"
    )
    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="business")
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident", back_populates="business"
    )
    action_items: Mapped[list["ActionItem"]] = relationship(
        "ActionItem", back_populates="business"
    )


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum(UserRole), nullable=False, default=UserRole.owner
    )
    business_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("businesses.id"), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now
    )

    business: Mapped["Business | None"] = relationship(
        "Business", back_populates="users"
    )
    quiz_results: Mapped[list["QuizResult"]] = relationship(
        "QuizResult", back_populates="user"
    )


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

class Assessment(Base):
    __tablename__ = "assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    business_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("businesses.id"), nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    band: Mapped[str | None] = mapped_column(String(50), nullable=True)

    business: Mapped["Business"] = relationship("Business", back_populates="assessments")
    answers: Mapped[list["AssessmentAnswer"]] = relationship(
        "AssessmentAnswer", back_populates="assessment"
    )


class AssessmentAnswer(Base):
    __tablename__ = "assessment_answers"
    __table_args__ = (
        UniqueConstraint("assessment_id", "question_id", name="uq_answer_per_question"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    assessment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assessments.id"), nullable=False
    )
    question_id: Mapped[str] = mapped_column(String(20), nullable=False)
    answer: Mapped[str] = mapped_column(Enum(AnswerChoice), nullable=False)

    assessment: Mapped["Assessment"] = relationship(
        "Assessment", back_populates="answers"
    )


# ---------------------------------------------------------------------------
# ActionItem
# ---------------------------------------------------------------------------

class ActionItem(Base):
    __tablename__ = "action_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    business_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("businesses.id"), nullable=False
    )
    recommendation_id: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(ActionStatus), nullable=False, default=ActionStatus.todo
    )
    due_date: Mapped[str | None] = mapped_column(String(20), nullable=True)

    business: Mapped["Business"] = relationship(
        "Business", back_populates="action_items"
    )


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    business_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("businesses.id"), nullable=True
    )
    type: Mapped[str] = mapped_column(Enum(ScanType), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    triggered_rules_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_snippet: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    business: Mapped["Business | None"] = relationship(
        "Business", back_populates="scans"
    )


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    business_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("businesses.id"), nullable=False
    )
    playbook_id: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(IncidentStatus), nullable=False, default=IncidentStatus.open
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    business: Mapped["Business"] = relationship("Business", back_populates="incidents")
    steps: Mapped[list["IncidentStep"]] = relationship(
        "IncidentStep", back_populates="incident"
    )


class IncidentStep(Base):
    __tablename__ = "incident_steps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id"), nullable=False
    )
    step_id: Mapped[str] = mapped_column(String(20), nullable=False)
    done_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="steps")


# ---------------------------------------------------------------------------
# Lesson / Quiz
# ---------------------------------------------------------------------------

class Lesson(Base):
    __tablename__ = "lessons"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    body_md: Mapped[str] = mapped_column(Text, nullable=False)

    quiz_results: Mapped[list["QuizResult"]] = relationship(
        "QuizResult", back_populates="lesson"
    )


class QuizResult(Base):
    __tablename__ = "quiz_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    lesson_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("lessons.id"), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="quiz_results")
    lesson: Mapped["Lesson"] = relationship("Lesson", back_populates="quiz_results")
