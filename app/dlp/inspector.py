"""
app/dlp/inspector.py
────────────────────
Wraps the existing PII detector (app.privacy.detector) and adds:
1. Strict Luhn validation for credit card numbers.
2. Secrets and credentials detection (API keys, AWS keys, GitHub tokens, Bearer tokens, JWTs, passwords).
3. Production-grade safe masked previews (zero raw sensitive values returned in DLPFinding).
"""

from __future__ import annotations

import re
import hashlib
from typing import List, Optional, Tuple

from app.privacy.detector import detect_pii, EntityType, DetectedEntity
from app.privacy.validators import validate_luhn, validate_credit_card
from app.dlp.models import DLPFinding


# ─────────────────────────────────────────────────────────────────────────────
# Secrets & Credentials Regex Patterns
# ─────────────────────────────────────────────────────────────────────────────
_SECRETS_PATTERNS = [
    # JWT Tokens (header.payload.signature)
    (
        "JWT_TOKEN",
        "rule_jwt_token",
        re.compile(r"\b(?:Bearer\s+)?(eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"),
    ),
    # OpenAI and modern service API keys
    ("SECRET_KEY", "rule_openai_key", re.compile(r"\b(sk-[a-zA-Z0-9_\-]{20,})\b")),
    # AWS Access Key ID
    ("SECRET_KEY", "rule_aws_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    # GitHub Personal Access / Fine-Grained Tokens
    ("SECRET_KEY", "rule_github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b")),
    # Bearer Tokens (non-JWT)
    ("SECRET_KEY", "rule_bearer_token", re.compile(r"\bBearer\s+([a-zA-Z0-9_\-\.]{20,})\b")),
    # Passwords or generic secrets in key-value config/assignments
    (
        "PASSWORD",
        "rule_password_assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\";]{4,})['\"]?"),
    ),
    (
        "SECRET_KEY",
        "rule_secret_assignment",
        re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?([^\s'\";]{8,})['\"]?"),
    ),
]

# Generic credit card regex fallback to ensure 13-19 digit cards with spaces/dashes are captured
_CARD_FALLBACK_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Direct statutory PAN regex
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")

_HIGH_PRIORITY_TYPES = frozenset({
    "AADHAAR", "PAN", "CREDIT_CARD", "SECRET_KEY", "JWT_TOKEN",
    "PASSWORD", "EMAIL", "PHONE", "GSTIN", "BANK_ACCOUNT", "PASSPORT"
})


def generate_masked_preview(entity_type: str, raw_value: str) -> str:
    """
    Generate a non-reversible, safe preview of a sensitive value.
    Raw value is never leaked.
    """
    cleaned = raw_value.strip()
    digits_only = re.sub(r"\D", "", cleaned)

    if entity_type == "AADHAAR":
        if len(digits_only) >= 4:
            return f"XXXX-XXXX-{digits_only[-4:]}"
        return "XXXX-XXXX-XXXX"

    if entity_type == "CREDIT_CARD":
        if len(digits_only) >= 4:
            return f"****-****-****-{digits_only[-4:]}"
        return "****-****-****-****"

    if entity_type == "PAN":
        if len(cleaned) == 10:
            return f"{cleaned[:2]}*****{cleaned[-1]}"
        return "XXXXX****X"

    if entity_type == "PHONE":
        if len(digits_only) >= 4:
            return f"{digits_only[:2]}******{digits_only[-2:]}"
        return "XX******XX"

    if entity_type == "EMAIL":
        parts = cleaned.split("@", 1)
        if len(parts) == 2:
            user, domain = parts
            masked_user = f"{user[0]}***" if user else "***"
            return f"{masked_user}@{domain}"
        return "***@***.***"

    if entity_type == "PASSWORD":
        return "********"

    if entity_type == "JWT_TOKEN":
        return "eyJ***...***[JWT]"

    if entity_type == "SECRET_KEY":
        if cleaned.startswith("sk-"):
            return f"sk-****...{cleaned[-4:]}" if len(cleaned) > 8 else "sk-****"
        if cleaned.startswith("AKIA"):
            return f"AKIA****...{cleaned[-4:]}" if len(cleaned) > 8 else "AKIA****"
        if cleaned.startswith("gh"):
            return f"gh*...{cleaned[-4:]}" if len(cleaned) > 8 else "gh****"
        return "********[SECRET]"

    # Default fallback: show first character and last character
    if len(cleaned) > 4:
        return f"{cleaned[:1]}***{cleaned[-1:]}"
    return "***"


class DLPInspector:
    """Inspector combining PII detection, Luhn validation, and Secrets detection."""

    def __init__(self) -> None:
        pass

    def inspect_internal(
        self, text: str, page: Optional[int] = None
    ) -> List[Tuple[DLPFinding, str]]:
        """
        Inspect text and return list of (DLPFinding, raw_value).
        Internal use for redactor; raw_value is discarded before returning to clients.
        """
        if not text:
            return []

        raw_candidates: List[Tuple[int, int, str, float, str, str]] = []
        # (start, end, entity_type, confidence, rule_id, raw_value)

        # 1. Run existing PII Detector
        base_entities: List[DetectedEntity] = detect_pii(text)
        for e in base_entities:
            rule_id = f"pii_{e.entity_type.lower()}"
            # Extra validation for CREDIT_CARD via Luhn
            if e.entity_type == EntityType.CREDIT_CARD:
                if not (validate_credit_card(e.value) or validate_luhn(re.sub(r"\D", "", e.value))):
                    continue
            raw_candidates.append((e.start, e.end, e.entity_type, e.confidence, rule_id, e.value))

        # 2. Standalone Credit Card Luhn check over uncaptured card patterns
        for m in _CARD_FALLBACK_RE.finditer(text):
            val = m.group(0)
            digits = re.sub(r"\D", "", val)
            if 13 <= len(digits) <= 19 and validate_luhn(digits):
                start, end = m.start(), m.end()
                raw_candidates.append(
                    (start, end, "CREDIT_CARD", 0.99, "rule_credit_card_luhn", val)
                )

        # 3. Direct statutory PAN check
        for m in _PAN_RE.finditer(text):
            val = m.group(0)
            from app.privacy.validators import validate_pan
            if validate_pan(val):
                raw_candidates.append(
                    (m.start(), m.end(), "PAN", 0.99, "rule_pan", val)
                )

        # 4. Detect Secrets, Tokens, and Passwords
        for ent_type, rule_id, pattern in _SECRETS_PATTERNS:
            for match in pattern.finditer(text):
                # If pattern has a capturing group for the secret value itself, use it
                if match.groups():
                    val = match.group(1)
                    start = match.start(1)
                    end = match.end(1)
                else:
                    val = match.group(0)
                    start = match.start()
                    end = match.end()

                raw_candidates.append((start, end, ent_type, 0.98, rule_id, val))

        # 5. Resolve overlapping spans
        # Strict priority: High priority statutory/secrets beat generic NAME/ADDRESS
        def candidate_prio(c):
            # (priority_tier, start, -length, -confidence)
            tier = -1 if c[2] in _HIGH_PRIORITY_TYPES else 0
            return (tier, c[0], -(c[1] - c[0]), -c[3])

        raw_candidates.sort(key=candidate_prio)

        resolved: List[Tuple[int, int, str, float, str, str]] = []
        for cand in raw_candidates:
            c_start, c_end = cand[0], cand[1]
            overlap = False
            for r in resolved:
                r_start, r_end = r[0], r[1]
                if not (c_end <= r_start or c_start >= r_end):
                    overlap = True
                    break
            if not overlap:
                resolved.append(cand)

        resolved.sort(key=lambda x: x[0])

        # 5. Build DLPFinding models (WITHOUT raw value) paired with raw_value for redactor
        results: List[Tuple[DLPFinding, str]] = []
        for start, end, ent_type, conf, rule, raw_val in resolved:
            preview = generate_masked_preview(ent_type, raw_val)
            finding = DLPFinding(
                entity_type=ent_type,
                confidence=round(conf, 2),
                page=page,
                start=start,
                end=end,
                masked_preview=preview,
                rule_id=rule,
            )
            results.append((finding, raw_val))

        return results

    def inspect(self, text: str, page: Optional[int] = None) -> List[DLPFinding]:
        """Inspect text and return list of DLPFinding instances (NO raw values)."""
        pairs = self.inspect_internal(text, page=page)
        return [finding for finding, _ in pairs]


_DEFAULT_INSPECTOR = DLPInspector()


def inspect_text(text: str, page: Optional[int] = None) -> List[DLPFinding]:
    """Inspect text for sensitive PII and secrets, returning safe DLP findings."""
    return _DEFAULT_INSPECTOR.inspect(text, page=page)
