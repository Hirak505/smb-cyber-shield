"""Knowledge Base and Rules Pydantic schemas.

Author: Person 3 - AI & Knowledge Engineer
Ticket: T03
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RecommendationEntry(BaseModel):
    """Knowledge base recommendation entry."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique recommendation ID, e.g. KB-ACC-001")
    title: str = Field(..., description="Short plain-language title")
    area: str = Field(..., description="Security domain area")
    effort: Literal["low", "med", "high"] = Field(..., description="Implementation effort level")
    status: Literal["draft", "approved"] = Field(..., description="Review status")
    source_org: str = Field(..., description="Source organization or TODO")
    source_url: str = Field(..., description="Canonical source URL or TODO")
    last_reviewed: str | None = Field(default=None, description="Date of last review")
    steps: list[str] = Field(default_factory=list, description="Concrete sequential actions")


class QuestionEntry(BaseModel):
    """Health check assessment question."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique question ID, e.g. Q01")
    area: str = Field(..., description="Security domain area")
    text: str = Field(..., description="Question prompt shown to user")
    weight: int = Field(..., ge=1, le=10, description="Weight used in health check scoring")
    recommendation_id: str = Field(..., description="Referenced KB recommendation ID")
    why_it_matters: str = Field(..., description="Explanation of why this security item matters")
    status: Literal["draft", "approved"] = Field(..., description="Review status")


class PlaybookStep(BaseModel):
    """Individual step inside an incident response playbook."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Step ID within playbook, e.g. S1")
    action: str = Field(..., description="Specific action to perform")
    time_target: str = Field(..., description="Target completion timeframe, e.g. 5 min, ASAP")
    who: str = Field(..., description="Responsible role, e.g. Employee, Owner, IT helper")
    kb_ref: str = Field(..., description="Referenced KB recommendation ID")


class PlaybookEntry(BaseModel):
    """Incident response playbook."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique playbook ID, e.g. PB-PHISH-CLICK")
    title: str = Field(..., description="Plain-language incident title")
    status: Literal["draft", "approved"] = Field(..., description="Review status")
    steps: list[PlaybookStep] = Field(default_factory=list, description="Ordered response steps")


class RuleConfig(BaseModel):
    """Detection rule metadata and KB mappings."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Rule ID, e.g. R01")
    weight: int = Field(..., ge=1, le=100, description="Risk weight")
    description: str = Field(..., description="Plain-language description")
    kb: list[str] = Field(default_factory=list, description="Allowed KB recommendation IDs")


class RulesConfig(BaseModel):
    """Detection engine rules file schema."""

    model_config = ConfigDict(extra="forbid")

    bands: dict[str, list[int]] = Field(..., description="Risk bands mapping to [min, max]")
    rules: list[RuleConfig] = Field(default_factory=list, description="Configured detection rules")
