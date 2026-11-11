"""Unit tests for Knowledge Base Loader and Schemas (Ticket T03).

Author: Person 3 - AI & Knowledge Engineer
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from app.services.kb import (
    KBCrossReferenceError,
    KBDuplicateIdError,
    KBFileNotFoundError,
    KBStore,
    KBValidationError,
    get_kb_store,
    load_playbooks,
    load_questions,
    load_recommendations,
    load_rules,
    load_rules_config,
)

# Project root paths
BASE_DIR = Path(__file__).resolve().parent.parent
KB_DIR = BASE_DIR / "app" / "kb"
RULES_PATH = BASE_DIR / "app" / "rules" / "rules.yaml"


class TestKBRealFilesLoading:
    """Tests that the actual repository YAML files load and validate cleanly."""

    def test_load_all_real_files(self) -> None:
        store = KBStore.load(kb_dir=KB_DIR, rules_path=RULES_PATH, allow_drafts=True)

        # 15 recommendations, 25 questions, 3 playbooks, 12 rules
        assert len(store.recommendations) == 15
        assert len(store.questions) == 25
        assert len(store.playbooks) == 3
        assert store.rules_config is not None
        assert len(store.rules_config.rules) == 12

    def test_recommendations_fields(self) -> None:
        recs = load_recommendations(KB_DIR / "recommendations.yaml", allow_drafts=True)
        assert "KB-EML-001" in recs
        eml_1 = recs["KB-EML-001"]
        assert eml_1.title == "Verify unexpected requests through a second channel"
        assert eml_1.area == "email"
        assert eml_1.effort == "low"
        assert eml_1.status == "draft"
        assert len(eml_1.steps) == 3

    def test_questions_fields(self) -> None:
        questions = load_questions(KB_DIR / "questions.yaml", allow_drafts=True)
        assert "Q01" in questions
        q1 = questions["Q01"]
        assert q1.area == "accounts"
        assert q1.weight == 4
        assert q1.recommendation_id == "KB-ACC-001"

    def test_playbooks_fields(self) -> None:
        playbooks = load_playbooks(KB_DIR / "playbooks.yaml", allow_drafts=True)
        assert "PB-INVOICE-FRAUD" in playbooks
        pb = playbooks["PB-INVOICE-FRAUD"]
        assert pb.title == "Suspicious invoice or payment change request"
        assert len(pb.steps) == 5
        assert pb.steps[0].id == "S1"
        assert pb.steps[0].kb_ref == "KB-PAY-001"

    def test_rules_fields(self) -> None:
        rules_cfg = load_rules_config(RULES_PATH)
        assert "likely_safe" in rules_cfg.bands
        assert "suspicious" in rules_cfg.bands
        assert "likely_phishing" in rules_cfg.bands
        assert rules_cfg.bands["likely_safe"] == [0, 24]
        assert rules_cfg.bands["suspicious"] == [25, 59]
        assert rules_cfg.bands["likely_phishing"] == [60, 100]

        r08 = next((r for r in rules_cfg.rules if r.id == "R08"), None)
        assert r08 is not None
        assert r08.weight == 30
        assert r08.kb == ["KB-PAY-001"]


class TestKBLookupAndHelperMethods:
    """Tests for store lookup utilities, rule-to-KB mapping, and ID whitelisting."""

    @pytest.fixture
    def store(self) -> KBStore:
        return KBStore.load(kb_dir=KB_DIR, rules_path=RULES_PATH, allow_drafts=True)

    def test_get_recommendation_found(self, store: KBStore) -> None:
        rec = store.get_recommendation("KB-PAY-001")
        assert rec is not None
        assert rec.title == "Verify payment detail changes by phone"

    def test_get_recommendation_not_found(self, store: KBStore) -> None:
        assert store.get_recommendation("KB-NON-EXISTENT") is None

    def test_get_multiple_recommendations(self, store: KBStore) -> None:
        recs = store.get_recommendations(["KB-EML-001", "KB-PAY-001", "DOES-NOT-EXIST"])
        assert len(recs) == 2
        assert recs[0].id == "KB-EML-001"
        assert recs[1].id == "KB-PAY-001"

    def test_get_recommendations_for_rules(self, store: KBStore) -> None:
        # R08 -> [KB-PAY-001], R02 -> [KB-EML-001, KB-ACC-002]
        recs = store.get_recommendations_for_rules(["R08", "R02"])
        ids = [r.id for r in recs]
        assert ids == ["KB-PAY-001", "KB-EML-001", "KB-ACC-002"]

    def test_get_recommendations_for_rules_deduplication(self, store: KBStore) -> None:
        # R01 -> [KB-EML-001], R06 -> [KB-EML-001]
        recs = store.get_recommendations_for_rules(["R01", "R06"])
        ids = [r.id for r in recs]
        assert ids == ["KB-EML-001"]  # Deduplicated

    def test_get_all_recommendation_ids(self, store: KBStore) -> None:
        all_ids = store.get_all_recommendation_ids()
        assert isinstance(all_ids, set)
        assert len(all_ids) == 15
        assert "KB-EML-001" in all_ids
        assert "KB-ACC-001" in all_ids

    def test_get_question_and_playbook(self, store: KBStore) -> None:
        assert store.get_question("Q01") is not None
        assert store.get_question("Q99") is None
        assert store.get_playbook("PB-RANSOM") is not None
        assert store.get_playbook("PB-UNKNOWN") is None


class TestKBCrossReferenceValidation:
    """Tests for validating references between questions, playbooks, rules, and recommendations."""

    def test_real_repo_files_pass_cross_reference_validation(self) -> None:
        store = KBStore.load(kb_dir=KB_DIR, rules_path=RULES_PATH, allow_drafts=True)
        # Should not raise any KBCrossReferenceError
        store.validate_cross_references()

    def test_question_referencing_unknown_recommendation_raises(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-ACC-001",
                "title": "Pass manager",
                "area": "accounts",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            }
        ]
        q_data = [
            {
                "id": "Q01",
                "area": "accounts",
                "text": "Question 1",
                "weight": 4,
                "recommendation_id": "KB-UNKNOWN-999",  # Does not exist
                "why_it_matters": "None",
                "status": "draft",
            }
        ]
        pb_data: list[dict] = []

        (tmp_path / "recommendations.yaml").write_text(yaml.dump(recs_data), encoding="utf-8")
        (tmp_path / "questions.yaml").write_text(yaml.dump(q_data), encoding="utf-8")
        (tmp_path / "playbooks.yaml").write_text(yaml.dump(pb_data), encoding="utf-8")

        with pytest.raises(KBCrossReferenceError) as exc_info:
            KBStore.load(kb_dir=tmp_path, rules_path=None, allow_drafts=True)
        assert "Question 'Q01' references unknown recommendation_id 'KB-UNKNOWN-999'" in str(exc_info.value)

    def test_playbook_step_referencing_unknown_recommendation_raises(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-EML-001",
                "title": "Verify requests",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            }
        ]
        q_data: list[dict] = []
        pb_data = [
            {
                "id": "PB-TEST",
                "title": "Test Playbook",
                "status": "draft",
                "steps": [
                    {
                        "id": "S1",
                        "action": "Do something",
                        "time_target": "5 min",
                        "who": "Owner",
                        "kb_ref": "KB-NONEXISTENT-REF",
                    }
                ],
            }
        ]

        (tmp_path / "recommendations.yaml").write_text(yaml.dump(recs_data), encoding="utf-8")
        (tmp_path / "questions.yaml").write_text(yaml.dump(q_data), encoding="utf-8")
        (tmp_path / "playbooks.yaml").write_text(yaml.dump(pb_data), encoding="utf-8")

        with pytest.raises(KBCrossReferenceError) as exc_info:
            KBStore.load(kb_dir=tmp_path, rules_path=None, allow_drafts=True)
        assert "Playbook 'PB-TEST' step 'S1' references unknown kb_ref 'KB-NONEXISTENT-REF'" in str(exc_info.value)

    def test_rule_referencing_unknown_recommendation_raises(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-EML-001",
                "title": "Verify requests",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            }
        ]
        q_data: list[dict] = []
        pb_data: list[dict] = []
        rules_data = {
            "bands": {"likely_safe": [0, 24], "suspicious": [25, 59], "likely_phishing": [60, 100]},
            "rules": [
                {"id": "R01", "weight: 15": 15, "description": "Urgency", "kb": ["KB-GHOST-REF"]},
            ],
        }
        # Fix format of rules_data
        rules_data["rules"] = [
            {"id": "R01", "weight": 15, "description": "Urgency", "kb": ["KB-GHOST-REF"]}
        ]

        (tmp_path / "recommendations.yaml").write_text(yaml.dump(recs_data), encoding="utf-8")
        (tmp_path / "questions.yaml").write_text(yaml.dump(q_data), encoding="utf-8")
        (tmp_path / "playbooks.yaml").write_text(yaml.dump(pb_data), encoding="utf-8")
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml.dump(rules_data), encoding="utf-8")

        with pytest.raises(KBCrossReferenceError) as exc_info:
            KBStore.load(kb_dir=tmp_path, rules_path=rules_file, allow_drafts=True)
        assert "Rule 'R01' references unknown kb recommendation 'KB-GHOST-REF'" in str(exc_info.value)


class TestKBProductionDraftHandlingAndIntegrity:
    """Tests that draft entries are excluded in production, and cross-reference integrity is enforced."""

    def test_draft_excluded_when_allow_drafts_is_false(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-TEST-001",
                "title": "Draft recommendation",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            },
            {
                "id": "KB-TEST-002",
                "title": "Approved recommendation",
                "area": "email",
                "effort": "low",
                "status": "approved",
                "source_org": "CISA",
                "source_url": "https://example.com/guidance",
                "steps": ["Step 1"],
            },
        ]
        test_file = tmp_path / "recommendations.yaml"
        test_file.write_text(yaml.dump(recs_data), encoding="utf-8")

        # In dev mode (allow_drafts=True), both are loaded
        dev_recs = load_recommendations(test_file, allow_drafts=True)
        assert len(dev_recs) == 2

        # In prod mode (allow_drafts=False), draft is excluded
        prod_recs = load_recommendations(test_file, allow_drafts=False)
        assert len(prod_recs) == 1
        assert "KB-TEST-002" in prod_recs
        assert "KB-TEST-001" not in prod_recs

    def test_approved_question_referencing_draft_recommendation_fails_in_production(
        self, tmp_path: Path
    ) -> None:
        # Recommendation is draft
        recs_data = [
            {
                "id": "KB-DRAFT-001",
                "title": "Draft",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            }
        ]
        # Question is approved, but references draft recommendation
        q_data = [
            {
                "id": "Q01",
                "area": "email",
                "text": "Approved question pointing to draft recommendation",
                "weight": 3,
                "recommendation_id": "KB-DRAFT-001",
                "why_it_matters": "None",
                "status": "approved",
            }
        ]
        pb_data: list[dict] = []

        (tmp_path / "recommendations.yaml").write_text(yaml.dump(recs_data), encoding="utf-8")
        (tmp_path / "questions.yaml").write_text(yaml.dump(q_data), encoding="utf-8")
        (tmp_path / "playbooks.yaml").write_text(yaml.dump(pb_data), encoding="utf-8")

        # In production mode (allow_drafts=False), KB-DRAFT-001 is omitted, so Q01 fails cross-reference check!
        with pytest.raises(KBCrossReferenceError) as exc_info:
            KBStore.load(kb_dir=tmp_path, rules_path=None, allow_drafts=False)
        assert "Question 'Q01' references unknown recommendation_id 'KB-DRAFT-001'" in str(exc_info.value)

    def test_all_approved_dataset_passes_in_production(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-APP-001",
                "title": "Approved rec",
                "area": "email",
                "effort": "low",
                "status": "approved",
                "source_org": "CISA",
                "source_url": "https://example.com",
                "steps": ["Step 1"],
            }
        ]
        q_data = [
            {
                "id": "Q01",
                "area": "email",
                "text": "Approved question",
                "weight": 3,
                "recommendation_id": "KB-APP-001",
                "why_it_matters": "None",
                "status": "approved",
            }
        ]
        pb_data = [
            {
                "id": "PB-01",
                "title": "Approved playbook",
                "status": "approved",
                "steps": [
                    {
                        "id": "S1",
                        "action": "Step 1",
                        "time_target": "5 min",
                        "who": "Owner",
                        "kb_ref": "KB-APP-001",
                    }
                ],
            }
        ]
        rules_data = {
            "bands": {"likely_safe": [0, 24], "suspicious": [25, 59], "likely_phishing": [60, 100]},
            "rules": [
                {"id": "R01", "weight": 15, "description": "Approved rule mapping", "kb": ["KB-APP-001"]}
            ],
        }

        (tmp_path / "recommendations.yaml").write_text(yaml.dump(recs_data), encoding="utf-8")
        (tmp_path / "questions.yaml").write_text(yaml.dump(q_data), encoding="utf-8")
        (tmp_path / "playbooks.yaml").write_text(yaml.dump(pb_data), encoding="utf-8")
        rules_file = tmp_path / "rules.yaml"
        rules_file.write_text(yaml.dump(rules_data), encoding="utf-8")

        store = KBStore.load(kb_dir=tmp_path, rules_path=rules_file, allow_drafts=False)
        assert len(store.recommendations) == 1
        assert len(store.questions) == 1
        assert len(store.playbooks) == 1


class TestKBDuplicateIdValidation:
    """Tests that duplicate IDs within any file fail fast with KBDuplicateIdError."""

    def test_duplicate_recommendation_id_fails(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-DUP-001",
                "title": "First",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            },
            {
                "id": "KB-DUP-001",
                "title": "Second with same ID",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            },
        ]
        test_file = tmp_path / "recommendations.yaml"
        test_file.write_text(yaml.dump(recs_data), encoding="utf-8")

        with pytest.raises(KBDuplicateIdError) as exc_info:
            load_recommendations(test_file)
        assert "KB-DUP-001" in str(exc_info.value)

    def test_duplicate_question_id_fails(self, tmp_path: Path) -> None:
        q_data = [
            {
                "id": "Q01",
                "area": "accounts",
                "text": "Question 1",
                "weight": 4,
                "recommendation_id": "KB-ACC-001",
                "why_it_matters": "None",
                "status": "draft",
            },
            {
                "id": "Q01",
                "area": "accounts",
                "text": "Question 1 duplicate",
                "weight": 3,
                "recommendation_id": "KB-ACC-001",
                "why_it_matters": "None",
                "status": "draft",
            },
        ]
        test_file = tmp_path / "questions.yaml"
        test_file.write_text(yaml.dump(q_data), encoding="utf-8")

        with pytest.raises(KBDuplicateIdError) as exc_info:
            load_questions(test_file)
        assert "Q01" in str(exc_info.value)

    def test_duplicate_rule_id_fails(self, tmp_path: Path) -> None:
        rules_data = {
            "bands": {"likely_safe": [0, 24], "suspicious": [25, 59], "likely_phishing": [60, 100]},
            "rules": [
                {"id": "R01", "weight": 15, "description": "Urgency", "kb": ["KB-EML-001"]},
                {"id": "R01", "weight": 20, "description": "Duplicate R01", "kb": ["KB-EML-001"]},
            ],
        }
        test_file = tmp_path / "rules.yaml"
        test_file.write_text(yaml.dump(rules_data), encoding="utf-8")

        with pytest.raises(KBDuplicateIdError) as exc_info:
            load_rules_config(test_file)
        assert "R01" in str(exc_info.value)


class TestKBMissingFieldsAndInvalidData:
    """Tests that missing required fields or invalid structures fail with KBValidationError."""

    def test_missing_required_field_fails(self, tmp_path: Path) -> None:
        # Missing 'title' and 'steps'
        recs_data = [
            {
                "id": "KB-BAD-001",
                "area": "email",
                "effort": "low",
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
            }
        ]
        test_file = tmp_path / "recommendations.yaml"
        test_file.write_text(yaml.dump(recs_data), encoding="utf-8")

        with pytest.raises(KBValidationError) as exc_info:
            load_recommendations(test_file)
        assert "Validation failed" in str(exc_info.value)

    def test_invalid_effort_enum_fails(self, tmp_path: Path) -> None:
        recs_data = [
            {
                "id": "KB-BAD-002",
                "title": "Bad Effort",
                "area": "email",
                "effort": "super-hard",  # Not in low/med/high
                "status": "draft",
                "source_org": "TODO",
                "source_url": "TODO",
                "steps": ["Step 1"],
            }
        ]
        test_file = tmp_path / "recommendations.yaml"
        test_file.write_text(yaml.dump(recs_data), encoding="utf-8")

        with pytest.raises(KBValidationError):
            load_recommendations(test_file)

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        with pytest.raises(KBFileNotFoundError):
            load_recommendations(tmp_path / "non_existent.yaml")

    def test_invalid_yaml_syntax_raises(self, tmp_path: Path) -> None:
        bad_yaml = tmp_path / "broken.yaml"
        bad_yaml.write_text("id: [unclosed list", encoding="utf-8")

        with pytest.raises(KBValidationError):
            load_recommendations(bad_yaml)

    def test_non_list_root_raises(self, tmp_path: Path) -> None:
        dict_yaml = tmp_path / "dict_instead_of_list.yaml"
        dict_yaml.write_text("some_key: some_value", encoding="utf-8")

        with pytest.raises(KBValidationError) as exc_info:
            load_recommendations(dict_yaml)
        assert "Expected a list" in str(exc_info.value)


class TestKBStoreGettersAndSingleton:
    """Tests for additional store getters, aliases, and singleton access."""

    @pytest.fixture
    def store(self) -> KBStore:
        return KBStore.load(kb_dir=KB_DIR, rules_path=RULES_PATH, allow_drafts=True)

    def test_get_all_questions(self, store: KBStore) -> None:
        all_q = store.get_all_questions()
        assert len(all_q) == 25
        assert all_q[0].id == "Q01"

    def test_get_all_playbooks(self, store: KBStore) -> None:
        all_pb = store.get_all_playbooks()
        assert len(all_pb) == 3
        ids = {p.id for p in all_pb}
        assert "PB-PHISH-CLICK" in ids
        assert "PB-INVOICE-FRAUD" in ids

    def test_get_all_rules(self, store: KBStore) -> None:
        all_rules = store.get_all_rules()
        assert len(all_rules) == 12
        assert all_rules[0].id == "R01"

    def test_get_score_bands(self, store: KBStore) -> None:
        bands = store.get_score_bands()
        assert bands["likely_safe"] == [0, 24]
        assert bands["suspicious"] == [25, 59]
        assert bands["likely_phishing"] == [60, 100]

    def test_load_rules_alias(self) -> None:
        rules_cfg = load_rules(RULES_PATH)
        assert len(rules_cfg.rules) == 12

    def test_get_kb_store_singleton(self) -> None:
        s1 = get_kb_store(kb_dir=KB_DIR, rules_path=RULES_PATH, allow_drafts=True, force_reload=True)
        s2 = get_kb_store()
        assert s1 is s2
