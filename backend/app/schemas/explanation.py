"""Pydantic schemas for LLM-generated scan explanations.

Ticket: T13
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ReasonExplanation(BaseModel):
    """Plain-language explanation for a triggered detection rule."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(..., min_length=1, description="Rule ID that was triggered, e.g. R02")
    plain_text: str = Field(..., min_length=1, description="Explanation of the triggered rule")


class NextStepExplanation(BaseModel):
    """Recommended recovery action citing a Knowledge Base recommendation ID."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, description="Recommended action")
    kb_ref: str = Field(..., min_length=1, description="Referenced KB recommendation ID, e.g. KB-EML-001")


class ScanExplanation(BaseModel):
    """Structured explanation produced by LLMClient with deterministic fallback."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., min_length=1, description="Plain-language explanation summary")
    reasons: list[ReasonExplanation] = Field(..., description="Explanations for triggered rules")
    next_steps: list[NextStepExplanation] = Field(..., description="Recommended actions referencing valid KB entries")
    is_fallback: bool = Field(default=False, description="Whether deterministic fallback was used")


Explanation = ScanExplanation
