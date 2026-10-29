"""Knowledge-base loader: loads and validates kb/*.yaml at startup.

Policy (KNOWLEDGE_BASE.md):
- All advice shown to users comes from these files.
- Only status: approved entries may be shown in production (draft shown in dev).
- Lookup by id.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError

log = logging.getLogger(__name__)

_KB_DIR = Path(__file__).parent.parent / "kb"


# ---------------------------------------------------------------------------
# Pydantic models for KB entries
# ---------------------------------------------------------------------------

class KBRecommendation(BaseModel):
    id: str
    title: str
    area: str
    effort: str
    status: str = "draft"
    source_org: str = "TODO"
    source_url: str = "TODO"
    last_reviewed: str | None = None
    steps: list[str] = Field(default_factory=list)


class KBQuestion(BaseModel):
    id: str
    area: str
    text: str
    weight: int
    recommendation_id: str
    why_it_matters: str = "TODO"
    status: str = "draft"


class PlaybookStep(BaseModel):
    id: str
    action: str
    time_target: str
    who: str
    kb_ref: str


class KBPlaybook(BaseModel):
    id: str
    title: str
    status: str = "draft"
    steps: list[PlaybookStep] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

class KnowledgeBase:
    def __init__(self) -> None:
        self._recommendations: dict[str, KBRecommendation] = {}
        self._questions: dict[str, KBQuestion] = {}
        self._playbooks: dict[str, KBPlaybook] = {}

    def load(self, prod_mode: bool = False) -> None:
        self._recommendations = self._load_file(
            "recommendations.yaml", KBRecommendation, prod_mode
        )
        self._questions = self._load_file(
            "questions.yaml", KBQuestion, prod_mode
        )
        self._playbooks = self._load_file(
            "playbooks.yaml", KBPlaybook, prod_mode
        )
        log.info(
            "KB loaded: %d recommendations, %d questions, %d playbooks",
            len(self._recommendations),
            len(self._questions),
            len(self._playbooks),
        )

    def _load_file(
        self,
        filename: str,
        model: type,
        prod_mode: bool,
    ) -> dict[str, Any]:
        path = _KB_DIR / filename
        if not path.exists():
            log.error("KB file missing: %s", path)
            return {}

        with path.open(encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or []

        result: dict[str, Any] = {}
        for item in raw:
            try:
                obj = model(**item)
            except ValidationError as exc:
                msg = f"KB validation error in {filename}: {exc}"
                if prod_mode:
                    raise RuntimeError(msg) from exc
                log.warning(msg)
                continue

            if obj.id in result:
                msg = f"Duplicate KB id '{obj.id}' in {filename}"
                if prod_mode:
                    raise RuntimeError(msg)
                log.warning(msg)
                continue

            # In prod, skip draft entries
            if prod_mode and getattr(obj, "status", "draft") == "draft":
                continue

            result[obj.id] = obj

        return result

    # Accessors ---------------------------------------------------------------

    def get_recommendation(self, kb_id: str) -> KBRecommendation | None:
        return self._recommendations.get(kb_id)

    def all_recommendations(self) -> list[KBRecommendation]:
        return list(self._recommendations.values())

    def get_question(self, q_id: str) -> KBQuestion | None:
        return self._questions.get(q_id)

    def all_questions(self) -> list[KBQuestion]:
        return list(self._questions.values())

    def get_playbook(self, pb_id: str) -> KBPlaybook | None:
        return self._playbooks.get(pb_id)

    def all_playbooks(self) -> list[KBPlaybook]:
        return list(self._playbooks.values())


# Module-level singleton
kb = KnowledgeBase()
