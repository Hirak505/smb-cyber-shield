"""Knowledge Base Loader and Registry Service.

Author: Person 3 – AI & Knowledge Engineer
Ticket: T03
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from backend.app.schemas.kb import (
    PlaybookEntry,
    QuestionEntry,
    RecommendationEntry,
    RuleConfig,
    RulesConfig,
)

logger = logging.getLogger(__name__)

# Default locations relative to backend/app/services
DEFAULT_KB_DIR = Path(__file__).resolve().parent.parent / "kb"
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"


class KBError(Exception):
    """Base exception for Knowledge Base operations."""


class KBFileNotFoundError(KBError):
    """Raised when a KB file cannot be found."""


class KBValidationError(KBError):
    """Raised when KB content fails schema validation or integrity checks."""


class KBDuplicateIdError(KBValidationError):
    """Raised when duplicate IDs are found within a KB file."""


class KBCrossReferenceError(KBValidationError):
    """Raised when a cross-reference between KB entities or rules cannot be resolved."""


def _read_yaml_file(file_path: Path) -> Any:
    """Read and parse a YAML file safely.

    Raises:
        KBFileNotFoundError: If the file does not exist.
        KBValidationError: If the YAML syntax is invalid.
    """
    if not file_path.exists():
        raise KBFileNotFoundError(f"KB file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise KBValidationError(f"Invalid YAML syntax in {file_path}: {e}") from e


def load_recommendations(
    file_path: Path | str, allow_drafts: bool = True
) -> dict[str, RecommendationEntry]:
    """Load and validate recommendations.yaml.

    Args:
        file_path: Path to recommendations.yaml.
        allow_drafts: If False, exclude entries with status == 'draft'.

    Returns:
        Mapping of recommendation ID to RecommendationEntry.

    Raises:
        KBFileNotFoundError: If the file does not exist.
        KBValidationError: If validation fails or content is not a list.
        KBDuplicateIdError: If duplicate recommendation IDs are found.
    """
    path = Path(file_path)
    raw_data = _read_yaml_file(path)

    if not isinstance(raw_data, list):
        raise KBValidationError(f"Expected a list of entries in {path}, got {type(raw_data).__name__}")

    recommendations: dict[str, RecommendationEntry] = {}
    seen_ids: set[str] = set()

    for idx, raw_item in enumerate(raw_data):
        if not isinstance(raw_item, dict):
            raise KBValidationError(f"Entry {idx} in {path} must be a dictionary")

        rec_id = raw_item.get("id")
        if not rec_id:
            raise KBValidationError(f"Entry {idx} in {path} is missing required 'id' field")

        if rec_id in seen_ids:
            raise KBDuplicateIdError(f"Duplicate recommendation ID '{rec_id}' found in {path}")
        seen_ids.add(rec_id)

        try:
            entry = RecommendationEntry.model_validate(raw_item)
        except ValidationError as e:
            raise KBValidationError(f"Validation failed for recommendation '{rec_id}' in {path}: {e}") from e

        if allow_drafts or entry.status == "approved":
            recommendations[entry.id] = entry

    logger.info(
        "Loaded %d recommendations from %s (allow_drafts=%s)",
        len(recommendations),
        path.name,
        allow_drafts,
    )
    return recommendations


def load_questions(
    file_path: Path | str, allow_drafts: bool = True
) -> dict[str, QuestionEntry]:
    """Load and validate questions.yaml.

    Args:
        file_path: Path to questions.yaml.
        allow_drafts: If False, exclude questions with status == 'draft'.

    Returns:
        Mapping of question ID to QuestionEntry.

    Raises:
        KBFileNotFoundError: If the file does not exist.
        KBValidationError: If validation fails or content is not a list.
        KBDuplicateIdError: If duplicate question IDs are found.
    """
    path = Path(file_path)
    raw_data = _read_yaml_file(path)

    if not isinstance(raw_data, list):
        raise KBValidationError(f"Expected a list of questions in {path}, got {type(raw_data).__name__}")

    questions: dict[str, QuestionEntry] = {}
    seen_ids: set[str] = set()

    for idx, raw_item in enumerate(raw_data):
        if not isinstance(raw_item, dict):
            raise KBValidationError(f"Question {idx} in {path} must be a dictionary")

        q_id = raw_item.get("id")
        if not q_id:
            raise KBValidationError(f"Question {idx} in {path} is missing required 'id' field")

        if q_id in seen_ids:
            raise KBDuplicateIdError(f"Duplicate question ID '{q_id}' found in {path}")
        seen_ids.add(q_id)

        try:
            entry = QuestionEntry.model_validate(raw_item)
        except ValidationError as e:
            raise KBValidationError(f"Validation failed for question '{q_id}' in {path}: {e}") from e

        if allow_drafts or entry.status == "approved":
            questions[entry.id] = entry

    logger.info("Loaded %d questions from %s (allow_drafts=%s)", len(questions), path.name, allow_drafts)
    return questions


def load_playbooks(
    file_path: Path | str, allow_drafts: bool = True
) -> dict[str, PlaybookEntry]:
    """Load and validate playbooks.yaml.

    Args:
        file_path: Path to playbooks.yaml.
        allow_drafts: If False, exclude playbooks with status == 'draft'.

    Returns:
        Mapping of playbook ID to PlaybookEntry.

    Raises:
        KBFileNotFoundError: If the file does not exist.
        KBValidationError: If validation fails or content is not a list.
        KBDuplicateIdError: If duplicate playbook IDs are found.
    """
    path = Path(file_path)
    raw_data = _read_yaml_file(path)

    if not isinstance(raw_data, list):
        raise KBValidationError(f"Expected a list of playbooks in {path}, got {type(raw_data).__name__}")

    playbooks: dict[str, PlaybookEntry] = {}
    seen_ids: set[str] = set()

    for idx, raw_item in enumerate(raw_data):
        if not isinstance(raw_item, dict):
            raise KBValidationError(f"Playbook {idx} in {path} must be a dictionary")

        pb_id = raw_item.get("id")
        if not pb_id:
            raise KBValidationError(f"Playbook {idx} in {path} is missing required 'id' field")

        if pb_id in seen_ids:
            raise KBDuplicateIdError(f"Duplicate playbook ID '{pb_id}' found in {path}")
        seen_ids.add(pb_id)

        try:
            entry = PlaybookEntry.model_validate(raw_item)
        except ValidationError as e:
            raise KBValidationError(f"Validation failed for playbook '{pb_id}' in {path}: {e}") from e

        if allow_drafts or entry.status == "approved":
            playbooks[entry.id] = entry

    logger.info("Loaded %d playbooks from %s (allow_drafts=%s)", len(playbooks), path.name, allow_drafts)
    return playbooks


def load_rules_config(file_path: Path | str) -> RulesConfig:
    """Load and validate rules.yaml.

    Args:
        file_path: Path to rules.yaml.

    Returns:
        Validated RulesConfig object.

    Raises:
        KBFileNotFoundError: If the file does not exist.
        KBValidationError: If validation fails.
        KBDuplicateIdError: If duplicate rule IDs are found.
    """
    path = Path(file_path)
    raw_data = _read_yaml_file(path)

    if not isinstance(raw_data, dict):
        raise KBValidationError(f"Expected a dict in {path}, got {type(raw_data).__name__}")

    try:
        config = RulesConfig.model_validate(raw_data)
    except ValidationError as e:
        raise KBValidationError(f"Validation failed for rules configuration in {path}: {e}") from e

    # Check for duplicate rule IDs
    seen_ids: set[str] = set()
    for rule in config.rules:
        if rule.id in seen_ids:
            raise KBDuplicateIdError(f"Duplicate rule ID '{rule.id}' found in {path}")
        seen_ids.add(rule.id)

    logger.info("Loaded %d detection rules from %s", len(config.rules), path.name)
    return config


# Alias for load_rules_config
load_rules = load_rules_config


class KBStore:
    """In-memory Knowledge Base and Rules registry."""

    def __init__(
        self,
        recommendations: dict[str, RecommendationEntry],
        questions: dict[str, QuestionEntry],
        playbooks: dict[str, PlaybookEntry],
        rules_config: RulesConfig | None = None,
        allow_drafts: bool = True,
    ) -> None:
        self.recommendations = recommendations
        self.questions = questions
        self.playbooks = playbooks
        self.rules_config = rules_config
        self.allow_drafts = allow_drafts

        self.rules_by_id: dict[str, RuleConfig] = {}
        if self.rules_config:
            self.rules_by_id = {r.id: r for r in self.rules_config.rules}

    def validate_cross_references(self) -> None:
        """Validate all internal cross-references across loaded KB data.

        Checks:
        1. Every question's recommendation_id must exist in self.recommendations.
        2. Every playbook step's kb_ref must exist in self.recommendations.
        3. Every rule's kb references must exist in self.recommendations.

        In production mode (allow_drafts=False), this guarantees that no approved
        question or playbook step references an unapproved draft recommendation,
        and that rules only reference approved recommendations.

        Raises:
            KBCrossReferenceError: If any referenced recommendation ID is missing.
        """
        # 1. Validate questions -> recommendations
        for q_id, q in self.questions.items():
            if q.recommendation_id not in self.recommendations:
                raise KBCrossReferenceError(
                    f"Question '{q_id}' references unknown recommendation_id '{q.recommendation_id}'"
                )

        # 2. Validate playbook steps -> recommendations
        for pb_id, pb in self.playbooks.items():
            for step in pb.steps:
                if step.kb_ref not in self.recommendations:
                    raise KBCrossReferenceError(
                        f"Playbook '{pb_id}' step '{step.id}' references unknown kb_ref '{step.kb_ref}'"
                    )

        # 3. Validate rules -> recommendations
        if self.rules_config:
            for rule in self.rules_config.rules:
                for kb_ref in rule.kb:
                    if kb_ref not in self.recommendations:
                        raise KBCrossReferenceError(
                            f"Rule '{rule.id}' references unknown kb recommendation '{kb_ref}'"
                        )

    @classmethod
    def load(
        cls,
        kb_dir: Path | str | None = None,
        rules_path: Path | str | None = None,
        allow_drafts: bool = True,
        validate_cross_refs: bool = True,
    ) -> KBStore:
        """Load and validate all Knowledge Base and rules files.

        Args:
            kb_dir: Directory containing recommendations.yaml, questions.yaml, playbooks.yaml.
            rules_path: Path to rules.yaml (optional).
            allow_drafts: Whether to include draft items (True for dev/test, False for production).
            validate_cross_refs: Whether to validate cross-references immediately upon load.

        Returns:
            Initialized and validated KBStore instance.
        """
        dir_path = Path(kb_dir) if kb_dir is not None else DEFAULT_KB_DIR
        rules_file = Path(rules_path) if rules_path is not None else DEFAULT_RULES_PATH

        recs = load_recommendations(dir_path / "recommendations.yaml", allow_drafts=allow_drafts)
        questions = load_questions(dir_path / "questions.yaml", allow_drafts=allow_drafts)
        playbooks = load_playbooks(dir_path / "playbooks.yaml", allow_drafts=allow_drafts)

        rules_cfg: RulesConfig | None = None
        if rules_file.exists():
            rules_cfg = load_rules_config(rules_file)

        store = cls(
            recommendations=recs,
            questions=questions,
            playbooks=playbooks,
            rules_config=rules_cfg,
            allow_drafts=allow_drafts,
        )

        if validate_cross_refs:
            store.validate_cross_references()

        return store

    def get_recommendation(self, kb_id: str) -> RecommendationEntry | None:
        """Lookup recommendation entry by ID."""
        return self.recommendations.get(kb_id)

    def get_recommendations(self, kb_ids: list[str]) -> list[RecommendationEntry]:
        """Lookup multiple recommendations by their IDs, preserving order and filtering missing."""
        results: list[RecommendationEntry] = []
        for kb_id in kb_ids:
            entry = self.get_recommendation(kb_id)
            if entry is not None:
                results.append(entry)
        return results

    def get_recommendations_for_rules(self, rule_ids: list[str]) -> list[RecommendationEntry]:
        """Lookup authorized recommendations associated with the triggered rule IDs.

        Maps rule IDs -> KB IDs using rules.yaml, deduplicates them while preserving
        order, and retrieves their RecommendationEntry records.
        """
        kb_ids_to_fetch: list[str] = []
        seen_kb_ids: set[str] = set()

        for r_id in rule_ids:
            rule = self.rules_by_id.get(r_id)
            if rule:
                for kb_ref in rule.kb:
                    if kb_ref not in seen_kb_ids:
                        seen_kb_ids.add(kb_ref)
                        kb_ids_to_fetch.append(kb_ref)

        return self.get_recommendations(kb_ids_to_fetch)

    def get_all_recommendation_ids(self) -> set[str]:
        """Return the complete set of valid recommendation IDs for whitelisting."""
        return set(self.recommendations.keys())

    def get_question(self, question_id: str) -> QuestionEntry | None:
        """Lookup question entry by ID."""
        return self.questions.get(question_id)

    def get_all_questions(self) -> list[QuestionEntry]:
        """Return all loaded questions."""
        return list(self.questions.values())

    def get_playbook(self, playbook_id: str) -> PlaybookEntry | None:
        """Lookup playbook entry by ID."""
        return self.playbooks.get(playbook_id)

    def get_all_playbooks(self) -> list[PlaybookEntry]:
        """Return all loaded playbooks."""
        return list(self.playbooks.values())

    def get_rule_config(self, rule_id: str) -> RuleConfig | None:
        """Lookup rule configuration by rule ID."""
        return self.rules_by_id.get(rule_id)

    def get_all_rules(self) -> list[RuleConfig]:
        """Return all configured rules."""
        return list(self.rules_by_id.values())

    def get_score_bands(self) -> dict[str, list[int]]:
        """Return score risk bands if configured."""
        if self.rules_config:
            return self.rules_config.bands
        return {}


_global_kb_store: KBStore | None = None


def get_kb_store(
    kb_dir: Path | str | None = None,
    rules_path: Path | str | None = None,
    allow_drafts: bool = True,
    validate_cross_refs: bool = True,
    force_reload: bool = False,
) -> KBStore:
    """Get or initialize the global KBStore instance."""
    global _global_kb_store
    if _global_kb_store is None or force_reload:
        _global_kb_store = KBStore.load(
            kb_dir=kb_dir,
            rules_path=rules_path,
            allow_drafts=allow_drafts,
            validate_cross_refs=validate_cross_refs,
        )
    return _global_kb_store
