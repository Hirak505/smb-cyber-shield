"""Provider-agnostic LLM client for ShieldDesk scan explanations.

Ticket: T13
Policy:
- The LLM only explains existing detection results in simple language.
- It NEVER determines or modifies the verdict, risk score, or triggered rules.
- Grounding: all next steps must cite valid loaded Knowledge Base entries (kb_loader).
- Privacy: raw message bodies are never sent to the LLM. Only verdict, risk score,
  triggered rule IDs/descriptions, and verified KB recommendations are provided.
- Deterministic fallback: on any failure (missing key, API error, invalid JSON,
  schema mismatch, unknown kb_ref/rule_id), falls back to static template.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import ValidationError

from app.core.config import get_settings
from app.rules.scanner import RuleHit
from app.schemas.explanation import (
    NextStepExplanation,
    ReasonExplanation,
    ScanExplanation,
)
from app.services.kb_loader import KBRecommendation, kb

log = logging.getLogger(__name__)

_RULES_YAML_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.yaml"

# ---------------------------------------------------------------------------
# KB Grounding & Rule Mapping Helpers
# ---------------------------------------------------------------------------

def get_rule_kb_mapping() -> dict[str, list[str]]:
    """Return mapping of rule_id to allowed KB recommendation IDs from rules.yaml."""
    if not _RULES_YAML_PATH.exists():
        log.warning("rules.yaml not found at %s", _RULES_YAML_PATH)
        return {}
    try:
        with open(_RULES_YAML_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        mapping: dict[str, list[str]] = {}
        for rule in data.get("rules", []):
            rule_id = rule.get("id")
            if rule_id:
                mapping[rule_id] = rule.get("kb", [])
        return mapping
    except (yaml.YAMLError, OSError) as exc:
        log.warning("Failed to load rules.yaml: %s", exc)
        return {}


def get_kb_entries_for_hits(hits: list[RuleHit]) -> list[KBRecommendation]:
    """Retrieve verified KB recommendations from the active KB loader for triggered rules."""
    rule_map = get_rule_kb_mapping()
    seen_kb_ids: set[str] = set()
    kb_entries: list[KBRecommendation] = []

    for hit in hits:
        kb_ids = rule_map.get(hit.rule_id, [])
        for kb_id in kb_ids:
            if kb_id not in seen_kb_ids:
                seen_kb_ids.add(kb_id)
                rec = kb.get_recommendation(kb_id)
                if rec is not None:
                    kb_entries.append(rec)

    return kb_entries


# ---------------------------------------------------------------------------
# Deterministic Fallback Factory
# ---------------------------------------------------------------------------

def get_static_explanation(verdict: str, hits: list[RuleHit]) -> str:
    """Produce static explanation string identical to baseline scanner."""
    if hits:
        reasons = "; ".join(h.description for h in hits[:3])
        return f"This message triggered {len(hits)} detection rule(s): {reasons}."
    return "No suspicious patterns were detected."


def get_deterministic_fallback(
    verdict: str,
    rule_hits: list[RuleHit],
    kb_entries: list[KBRecommendation] | None = None,
) -> ScanExplanation:
    """Build a deterministic explanation with relevant approved KB steps."""
    summary = get_static_explanation(verdict, rule_hits)

    reasons = [
        ReasonExplanation(rule_id=h.rule_id, plain_text=h.description)
        for h in rule_hits
    ]

    relevant_entries = get_kb_entries_for_hits(rule_hits)
    if kb_entries is not None:
        supplied_ids = {entry.id for entry in kb_entries}
        relevant_entries = [
            entry for entry in relevant_entries if entry.id in supplied_ids
        ]
    next_steps = [
        NextStepExplanation(text=step_text, kb_ref=entry.id)
        for entry in relevant_entries
        if entry.status == "approved"
        for step_text in entry.steps
    ]

    return ScanExplanation(
        summary=summary,
        reasons=reasons,
        next_steps=next_steps,
        is_fallback=True,
    )


# ---------------------------------------------------------------------------
# Provider Abstractions
# ---------------------------------------------------------------------------

class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        """Send prompt to provider and return raw response text."""
        raise NotImplementedError


class MockLLMProvider(BaseLLMProvider):
    """Mock provider for unit testing without network or API keys."""

    def __init__(
        self,
        response: str | list[str] | Callable[[str, str | None], str] | Exception | None = None,
    ) -> None:
        self.response = response
        self._calls: list[dict[str, Any]] = []

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        self._calls.append({"prompt": prompt, "system_prompt": system_prompt})

        if isinstance(self.response, Exception):
            raise self.response

        if callable(self.response):
            return self.response(prompt, system_prompt)

        if isinstance(self.response, list):
            if not self.response:
                raise RuntimeError("No more mocked responses available.")
            return self.response.pop(0)

        if isinstance(self.response, str):
            return self.response

        # Default minimal valid response
        return json.dumps({
            "summary": "Mock explanation summary.",
            "reasons": [],
            "next_steps": [],
        })


class AnthropicProvider(BaseLLMProvider):
    """Anthropic Messages API provider."""

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.api_key = api_key
        self.model = model or "claude-3-haiku-20240307"
        self._http_client = http_client
        self._timeout = timeout

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        client = self._http_client or httpx.Client(timeout=self._timeout)
        try:
            resp = client.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data["content"][0]["text"])
        finally:
            if self._http_client is None:
                client.close()


class OpenAIProvider(BaseLLMProvider):
    """OpenAI Chat Completions API provider."""

    def __init__(
        self,
        api_key: str,
        model: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        self._http_client = http_client
        self._timeout = timeout

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }

        client = self._http_client or httpx.Client(timeout=self._timeout)
        try:
            resp = client.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return str(data["choices"][0]["message"]["content"])
        finally:
            if self._http_client is None:
                client.close()


# ---------------------------------------------------------------------------
# LLM Client Interface
# ---------------------------------------------------------------------------

class LLMClient:
    """Provider-agnostic LLM client for generating grounded scan explanations."""

    def __init__(
        self,
        provider: BaseLLMProvider | None = None,
        provider_name: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 5.0,
    ) -> None:
        settings = get_settings()
        self.provider_name = (provider_name or settings.LLM_PROVIDER).lower()
        self.api_key = api_key if api_key is not None else settings.LLM_API_KEY
        self.model = model if model is not None else settings.LLM_MODEL
        self._http_client = http_client
        self._timeout = timeout

        if provider is not None:
            self._provider = provider
        elif not self.api_key:
            # Missing API key: no provider instantiated, will use fallback
            self._provider = None
        elif self.provider_name in ("anthropic", "claude"):
            self._provider = AnthropicProvider(
                api_key=self.api_key,
                model=self.model,
                http_client=self._http_client,
                timeout=self._timeout,
            )
        elif self.provider_name in ("openai", "gpt"):
            self._provider = OpenAIProvider(
                api_key=self.api_key,
                model=self.model,
                http_client=self._http_client,
                timeout=self._timeout,
            )
        else:
            log.warning("Unknown LLM provider '%s'; deterministic fallback will be used.", self.provider_name)
            self._provider = None

    @property
    def has_active_provider(self) -> bool:
        """True if an active provider with credentials is configured."""
        return self._provider is not None

    def explain(
        self,
        verdict: str,
        rule_hits: list[RuleHit],
        kb_entries: list[KBRecommendation] | None = None,
        risk_score: int | None = None,
    ) -> ScanExplanation:
        """Generate a validated plain-language explanation of scan results.

        Falls back to deterministic explanation on any failure or missing provider.
        Invariants preserved:
        - Never sets scores, verdicts, or rules.
        - Only references verified KB recommendations.
        - Privacy: raw message body is never sent to the LLM.
        """
        if kb_entries is None:
            kb_entries = get_kb_entries_for_hits(rule_hits)

        # 1. Check for missing provider / missing API key
        if self._provider is None:
            log.info("LLM provider not configured or missing API key; using deterministic fallback.")
            return get_deterministic_fallback(verdict, rule_hits, kb_entries)

        rule_kb_mapping = get_rule_kb_mapping()
        triggered_kb_ids = {
            kb_id
            for hit in rule_hits
            for kb_id in rule_kb_mapping.get(hit.rule_id, [])
        }
        supplied_kb_ids = {entry.id for entry in kb_entries}
        allowed_kb_ids = triggered_kb_ids.intersection(supplied_kb_ids)

        # 2. Build prompt with minimal necessary data (no raw text!)
        system_prompt, user_prompt = self._build_prompts(verdict, rule_hits, kb_entries, risk_score)

        # 3. Request generation from provider
        try:
            raw_text = self._provider.generate(user_prompt, system_prompt=system_prompt)
        except Exception as exc:  # noqa: BLE001
            log.warning("LLM provider request failed: %s; falling back to deterministic explanation.", exc)
            return get_deterministic_fallback(verdict, rule_hits, kb_entries)

        # 4. Parse JSON
        parsed_data = self._parse_json(raw_text)
        if parsed_data is None:
            log.warning("LLM response was not valid JSON; falling back to deterministic explanation.")
            return get_deterministic_fallback(verdict, rule_hits, kb_entries)

        # 5. Validate Schema with Pydantic
        try:
            explanation = ScanExplanation.model_validate(parsed_data)
        except ValidationError as exc:
            log.warning("LLM response failed schema validation: %s; falling back.", exc)
            return get_deterministic_fallback(verdict, rule_hits, kb_entries)

        # 6. Validate Rule IDs
        triggered_rule_ids = {h.rule_id for h in rule_hits}
        for reason in explanation.reasons:
            if reason.rule_id not in triggered_rule_ids:
                log.warning(
                    "LLM hallucinated rule ID '%s' not among triggered rules %s; falling back.",
                    reason.rule_id,
                    triggered_rule_ids,
                )
                return get_deterministic_fallback(verdict, rule_hits, kb_entries)

        # 7. Validate KB Grounding
        grounded_next_steps: list[NextStepExplanation] = []
        seen_kb_ids: set[str] = set()
        for step in explanation.next_steps:
            rec = kb.get_recommendation(step.kb_ref)
            if rec is None:
                log.warning(
                    "LLM returned unknown or unapproved KB reference '%s'; falling back.",
                    step.kb_ref,
                )
                return get_deterministic_fallback(verdict, rule_hits, kb_entries)

            if rec.id not in allowed_kb_ids:
                log.warning(
                    "LLM returned KB reference '%s' not allowed for triggered rules.",
                    rec.id,
                )
                return get_deterministic_fallback(verdict, rule_hits, kb_entries)

            if rec.id not in seen_kb_ids:
                seen_kb_ids.add(rec.id)
                grounded_next_steps.extend(
                    NextStepExplanation(text=kb_step, kb_ref=rec.id)
                    for kb_step in rec.steps
                )

        # Keep the response schema, but display only steps sourced from the KB.
        return explanation.model_copy(update={"next_steps": grounded_next_steps})

    def _build_prompts(
        self,
        verdict: str,
        rule_hits: list[RuleHit],
        kb_entries: list[KBRecommendation],
        risk_score: int | None,
    ) -> tuple[str, str]:
        """Construct system and user prompts with minimum necessary data."""
        system_prompt = (
            "You are ShieldDesk, an AI cybersecurity assistant for small business owners.\n"
            "Explain the detection scanner results in calm, simple, plain English.\n"
            "Rules you must strictly follow:\n"
            "1. You must NEVER change or dispute the verdict or risk score.\n"
            "2. In 'reasons', only explain the triggered rules provided below using their exact rule_id.\n"
            "3. In 'next_steps', every step MUST cite a valid kb_ref from the provided Knowledge Base entries.\n"
            "4. NEVER invent recommendations, URLs, or KB IDs not in the provided entries.\n"
            "5. Respond with ONLY valid JSON matching this schema:\n"
            "{\n"
            '  "summary": "Plain-language explanation",\n'
            '  "reasons": [{"rule_id": "R02", "plain_text": "Explanation"}],\n'
            '  "next_steps": [{"text": "Recommended action", "kb_ref": "KB-EML-001"}]\n'
            "}"
        )

        user_content_lines = [
            f"Verdict: {verdict}",
        ]
        if risk_score is not None:
            user_content_lines.append(f"Risk Score: {risk_score}")

        user_content_lines.append("\nTriggered Detection Rules:")
        if rule_hits:
            for hit in rule_hits:
                user_content_lines.append(f"- Rule {hit.rule_id}: {hit.description}")
        else:
            user_content_lines.append("- None (Message is safe)")

        user_content_lines.append("\nApproved Knowledge Base Recommendations:")
        if kb_entries:
            for rec in kb_entries:
                steps_str = "; ".join(rec.steps) if rec.steps else "Follow standard safety practices"
                user_content_lines.append(f"- ID: {rec.id} | Title: {rec.title} | Guidance: {steps_str}")
        else:
            user_content_lines.append("- Standard baseline caution")

        user_prompt = "\n".join(user_content_lines)
        return system_prompt, user_prompt

    @staticmethod
    def _parse_json(raw_text: str) -> dict[str, Any] | None:
        """Extract and parse JSON from raw text, stripping code blocks if present."""
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
            return None
        except (json.JSONDecodeError, ValueError):
            return None


# ---------------------------------------------------------------------------
# Singleton Accessor
# ---------------------------------------------------------------------------

_global_client: LLMClient | None = None


def get_llm_client() -> LLMClient:
    """Return shared LLMClient instance."""
    global _global_client
    if _global_client is None:
        _global_client = LLMClient()
    return _global_client
