"""Detection rule engine.

Rules are PURE functions: no I/O, no randomness, no network.
Each rule returns a RuleHit (with evidence spans) or None.
Risk = min(100, sum(weights)).
Bands: 0-24 Likely safe | 25-59 Suspicious | 60+ Likely phishing.

Contract (DETECTION_RULES.md):
    def rule_rXX(msg: ParsedMessage, ctx: Context) -> RuleHit | None
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import NamedTuple

import tldextract
from rapidfuzz import fuzz


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class EvidenceSpan(NamedTuple):
    start: int
    end: int
    rule_id: str
    text: str


@dataclass
class RuleHit:
    rule_id: str
    weight: int
    description: str
    evidence: list[EvidenceSpan] = field(default_factory=list)


@dataclass
class ParsedMessage:
    """Normalised input passed to every rule."""
    text: str
    sender: str | None = None
    urls: list[str] | None = None

    # Pre-computed lower-case text for matching
    @property
    def text_lower(self) -> str:
        return self.text.lower()


@dataclass
class Context:
    """Caller-supplied context (known vendor list, etc.)."""
    known_vendors: list[str] = field(default_factory=list)
    rule_config: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Keywords – kept here so rules stay pure; ultimate move to rules.yaml later
# ---------------------------------------------------------------------------

_URGENCY_PHRASES = [
    "urgent", "immediately", "within 24 hours", "within 24 hrs",
    "account will be", "action required", "verify now", "act now",
    "your account is suspended", "respond today", "before noon",
    "account will be closed", "expires today", "final notice",
    "offer ends", "limited time",
]

_CREDENTIAL_PHRASES = [
    "enter your password", "enter your login", "verify your password",
    "confirm your card", "enter your otp", "enter otp",
    "provide your card", "bank otp", "your card number",
    "one-time code", "your account credentials",
]

_PAYMENT_CHANGE_PHRASES = [
    "bank details have changed", "bank details changed",
    "new bank account", "updated account details",
    "new account details", "new payee", "new upi id",
    "upi id has changed", "pay to the new",
]

_GIFT_WIRE_CRYPTO_PHRASES = [
    "gift card", "gift cards", "wire transfer", "wire to",
    "bitcoin", " btc ", "cryptocurrency", "crypto",
    "send a wire", "buy gift", "google play card",
    "itunes card", "amazon gift",
]

_RISKY_ATTACHMENT_EXTS = re.compile(
    r"\.(exe|iso|vbs|js|ps1|bat|cmd|msi|html?|hta|jar|lnk|scr|wsf)\b",
    re.IGNORECASE,
)

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "short.io", "tiny.cc",
    "youtu.be",
}

_FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "proton.me", "protonmail.com", "icloud.com", "aol.com",
    "mail.com", "yandex.com", "zohomail.com",
}

_EXECUTIVE_PHRASES = [
    "ceo", "cfo", "md", "director", "owner", "president",
    "managing director", "chief executive",
]

_GENERIC_GREETING = re.compile(
    r"^(dear\s+(customer|user|sir|madam|valued|member)|hello there|hi there)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_all(text: str, phrases: list[str]) -> list[tuple[int, int, str]]:
    """Return (start, end, phrase) for every match of any phrase in text."""
    hits: list[tuple[int, int, str]] = []
    low = text.lower()
    for phrase in phrases:
        start = 0
        while True:
            idx = low.find(phrase, start)
            if idx == -1:
                break
            hits.append((idx, idx + len(phrase), text[idx : idx + len(phrase)]))
            start = idx + 1
    return hits


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract bare URLs from free text."""
    return re.findall(r"https?://[^\s\">]+", text)


def _sender_domain(sender: str | None) -> str | None:
    if not sender:
        return None
    match = re.search(r"@([\w.\-]+)", sender)
    return match.group(1).lower() if match else None


def _registered_domain(url_or_domain: str) -> str | None:
    try:
        ext = tldextract.extract(url_or_domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    return None


def _is_ip_host(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        # IPv4
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            return True
        # IPv6
        if host.startswith("["):
            return True
    except Exception:
        pass
    return False


def _has_homoglyph(domain: str) -> bool:
    """Detect punycode or common character substitutions."""
    if domain.startswith("xn--"):
        return True
    homoglyphs = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"}
    # Check if substituting digits back gives a common word pattern
    # (lightweight heuristic; full homoglyph table out of scope for MVP)
    for digit, letter in homoglyphs.items():
        if digit in domain:
            return True
    return False


def _lookalike_score(a: str, b: str) -> int:
    return fuzz.ratio(a, b)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def rule_r01(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R01 – Urgency or threat language (weight 15)."""
    hits = _find_all(msg.text, _URGENCY_PHRASES)
    if not hits:
        return None
    evidence = [
        EvidenceSpan(s, e, "R01", phrase) for s, e, phrase in hits[:3]
    ]
    return RuleHit("R01", 15, "Urgency or threat language", evidence)


def rule_r02(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R02 – Asks for credentials, OTP or card details (weight 30)."""
    hits = _find_all(msg.text, _CREDENTIAL_PHRASES)
    if not hits:
        return None
    evidence = [EvidenceSpan(s, e, "R02", phrase) for s, e, phrase in hits[:3]]
    return RuleHit("R02", 30, "Asks for credentials, OTP or card details", evidence)


def rule_r03(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R03 – Link text domain differs from actual link domain (weight 25)."""
    # Pattern: <href="actual">display text</a> or markdown [text](url)
    html_links = re.findall(
        r'href=["\']?(https?://[^\s"\']+)["\']?[^>]*>([^<]+)<',
        msg.text,
        re.IGNORECASE,
    )
    md_links = re.findall(r"\[([^\]]+)\]\((https?://[^\)]+)\)", msg.text)

    evidence: list[EvidenceSpan] = []

    for actual_url, display_text in html_links:
        actual_domain = _registered_domain(actual_url)
        display_domain = _registered_domain(display_text.strip())
        if actual_domain and display_domain and actual_domain != display_domain:
            idx = msg.text.find(display_text)
            if idx != -1:
                evidence.append(
                    EvidenceSpan(idx, idx + len(display_text), "R03", display_text[:50])
                )

    for display_text, actual_url in md_links:
        actual_domain = _registered_domain(actual_url)
        display_domain = _registered_domain(display_text.strip())
        if actual_domain and display_domain and actual_domain != display_domain:
            idx = msg.text.find(display_text)
            if idx != -1:
                evidence.append(
                    EvidenceSpan(idx, idx + len(display_text), "R03", display_text[:50])
                )

    if not evidence:
        return None
    return RuleHit("R03", 25, "Link text domain differs from actual link domain", evidence)


def rule_r04(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R04 – Lookalike, homoglyph or punycode domain (weight 25)."""
    urls = list(msg.urls or []) + _extract_urls_from_text(msg.text)
    evidence: list[EvidenceSpan] = []

    well_known = [
        "paypal.com", "microsoft.com", "google.com", "amazon.com",
        "apple.com", "bankofamerica.com", "chase.com", "linkedin.com",
        "dropbox.com", "facebook.com",
    ]

    for url in urls:
        domain = _registered_domain(url)
        if not domain or domain in well_known:
            continue
        if _has_homoglyph(domain):
            idx = msg.text.find(url)
            start = max(0, idx)
            end = min(len(msg.text), start + len(url))
            evidence.append(EvidenceSpan(start, end, "R04", url[:80]))
            continue
        # Fuzzy match against well-known brands
        for known in well_known:
            score = _lookalike_score(domain, known)
            if 70 < score < 100:  # similar but NOT identical
                idx = msg.text.find(url)
                start = max(0, idx)
                end = min(len(msg.text), start + len(url))
                evidence.append(EvidenceSpan(start, end, "R04", url[:80]))
                break

    if not evidence:
        return None
    return RuleHit("R04", 25, "Lookalike, homoglyph or punycode domain", evidence[:3])


def rule_r05(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R05 – URL shortener or IP-literal host (weight 15)."""
    urls = list(msg.urls or []) + _extract_urls_from_text(msg.text)
    evidence: list[EvidenceSpan] = []

    for url in urls:
        short = False
        domain = _registered_domain(url)
        if domain in _SHORTENER_DOMAINS:
            short = True
        if _is_ip_host(url):
            short = True

        if short:
            idx = msg.text.find(url)
            evidence.append(
                EvidenceSpan(max(0, idx), max(0, idx) + len(url), "R05", url[:80])
            )

    if not evidence:
        return None
    return RuleHit("R05", 15, "URL shortener or IP-literal host", evidence[:3])


def rule_r06(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R06 – Display name vs sender domain mismatch (weight 20)."""
    if not msg.sender:
        return None

    last_lt = msg.sender.rfind("<")
    last_gt = msg.sender.rfind(">")

    if last_lt != -1 and last_gt > last_lt:
        email_addr = msg.sender[last_lt + 1 : last_gt].strip()
        display_name = msg.sender[:last_lt].strip().strip('"\'')
    else:
        return None

    email_domain = _sender_domain(email_addr) or ""

    # If display name contains a domain-like string that differs from sender domain
    display_domain_match = re.search(r"([\w\-]+\.(com|org|net|io|co|in|xyz|top))", display_name, re.IGNORECASE)
    if display_domain_match:
        apparent_domain = display_domain_match.group(0).lower()
        if apparent_domain != email_domain:
            idx = msg.text.lower().find(display_name.lower())
            if idx != -1:
                start = idx
                end = min(len(msg.text), idx + len(display_name))
            else:
                start = 0
                end = min(len(msg.text), len(apparent_domain))
            evidence = [
                EvidenceSpan(
                    start,
                    end,
                    "R06",
                    f"'{display_name}' but sent from {email_domain}",
                )
            ]
            return RuleHit(
                "R06", 20, "Display name vs sender domain mismatch", evidence
            )
    return None


def rule_r07(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R07 – Free-mail sender posing as company/executive (weight 15)."""
    if not msg.sender:
        return None
    sender_domain = _sender_domain(msg.sender)
    if sender_domain not in _FREE_MAIL_DOMAINS:
        return None

    text_low = msg.text_lower
    sender_low = msg.sender.lower()
    for phrase in _EXECUTIVE_PHRASES:
        if phrase in sender_low or phrase in text_low:
            idx = text_low.find(phrase)
            evidence = [EvidenceSpan(max(0, idx), max(0, idx) + len(phrase), "R07", phrase)]
            return RuleHit(
                "R07", 15, "Free-mail sender posing as company or executive", evidence
            )
    return None


def rule_r08(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R08 – Payment detail change request (weight 30)."""
    hits = _find_all(msg.text, _PAYMENT_CHANGE_PHRASES)
    if not hits:
        return None
    evidence = [EvidenceSpan(s, e, "R08", phrase) for s, e, phrase in hits[:3]]
    return RuleHit("R08", 30, "Payment detail change request", evidence)


def rule_r09(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R09 – Risky attachment type (weight 25)."""
    matches = list(_RISKY_ATTACHMENT_EXTS.finditer(msg.text))
    if not matches:
        return None
    evidence = [
        EvidenceSpan(m.start(), m.end(), "R09", m.group(0)) for m in matches[:3]
    ]
    return RuleHit("R09", 25, "Risky attachment type", evidence)


def rule_r10(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R10 – Gift-card, wire or crypto request (weight 30)."""
    hits = _find_all(msg.text, _GIFT_WIRE_CRYPTO_PHRASES)
    if not hits:
        return None
    evidence = [EvidenceSpan(s, e, "R10", phrase) for s, e, phrase in hits[:3]]
    return RuleHit("R10", 30, "Gift-card, wire or crypto request", evidence)


def rule_r11(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R11 – Generic greeting and odd tone (weight 5)."""
    if not _GENERIC_GREETING.search(msg.text):
        return None
    idx = _GENERIC_GREETING.search(msg.text).start()
    match = _GENERIC_GREETING.search(msg.text)
    evidence = [
        EvidenceSpan(match.start(), match.end(), "R11", match.group(0))
    ]
    return RuleHit("R11", 5, "Generic greeting and odd tone", evidence)


def rule_r12(msg: ParsedMessage, ctx: Context) -> RuleHit | None:
    """R12 – Invoice not matching known vendor list (weight 15)."""
    # Only fires if message mentions 'invoice' and sender domain is unknown
    if "invoice" not in msg.text_lower:
        return None
    if not msg.sender:
        return None
    sender_domain = _sender_domain(msg.sender)
    if not sender_domain:
        return None
    if any(
        _lookalike_score(sender_domain, v) >= 90
        for v in (ctx.known_vendors or [])
    ):
        return None  # recognized vendor
    # Sender is unknown and message mentions invoice
    idx = msg.text_lower.find("invoice")
    evidence = [EvidenceSpan(idx, idx + 7, "R12", msg.text[idx : idx + 7])]
    return RuleHit("R12", 15, "Invoice not matching known vendor list", evidence)


# ---------------------------------------------------------------------------
# Scoring + verdict
# ---------------------------------------------------------------------------

_ALL_RULES = [
    rule_r01, rule_r02, rule_r03, rule_r04, rule_r05,
    rule_r06, rule_r07, rule_r08, rule_r09, rule_r10,
    rule_r11, rule_r12,
]

_BANDS = {
    "Likely safe": (0, 24),
    "Suspicious": (25, 59),
    "Likely phishing": (60, 100),
}


def score_message(
    msg: ParsedMessage,
    ctx: Context | None = None,
) -> tuple[int, str, list[RuleHit]]:
    """Run all rules; return (risk_score, verdict, hits)."""
    ctx = ctx or Context()
    hits: list[RuleHit] = []
    for rule_fn in _ALL_RULES:
        hit = rule_fn(msg, ctx)
        if hit is not None:
            hits.append(hit)

    score = min(100, sum(h.weight for h in hits))
    if score >= 60:
        verdict = "Likely phishing"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Likely safe"

    return score, verdict, hits
