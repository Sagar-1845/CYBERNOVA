"""
app/dlp/redactor.py
───────────────────
Multi-mode sensitive data redactor:
- full: [REDACTED: {ENTITY_TYPE}]
- partial: Masked preview (e.g. XXXX-XXXX-1234, j***@corp.com)
- irreversible: Solid blackout unicode blocks (e.g. ████████)
- tokenize: Format-preserving reversible tokens ([AADHAAR_1], [PAN_1])
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from app.dlp.inspector import DLPInspector, generate_masked_preview
from app.dlp.models import DLPFinding


class DLPRedactor:
    """Performs redaction on text content according to specified mode."""

    def __init__(self, inspector: Optional[DLPInspector] = None) -> None:
        self.inspector = inspector or DLPInspector()

    def _get_replacement(
        self,
        entity_type: str,
        raw_val: str,
        mode: str,
        token_counts: Dict[str, int],
    ) -> str:
        norm_mode = (mode or "full").lower().strip()

        if norm_mode == "full":
            return f"[REDACTED: {entity_type}]"

        if norm_mode == "partial":
            return generate_masked_preview(entity_type, raw_val)

        if norm_mode == "irreversible":
            # Solid block characters matching length of the secret value
            return "█" * max(len(raw_val), 4)

        if norm_mode == "tokenize":
            idx = token_counts.get(entity_type, 0) + 1
            token_counts[entity_type] = idx
            return f"[{entity_type}_{idx}]"

        # Default fallback
        return f"[REDACTED: {entity_type}]"

    def redact_text(
        self, text: str, mode: str = "full"
    ) -> Tuple[str, int, List[DLPFinding]]:
        """
        Redact sensitive information from text string.

        Returns:
            Tuple of (redacted_text, count_removed, findings_list)
        """
        if not text:
            return "", 0, []

        pairs = self.inspector.inspect_internal(text)
        if not pairs:
            return text, 0, []

        # Sort pairs by start offset descending so replacements do not alter preceding indices
        sorted_pairs = sorted(pairs, key=lambda p: p[0].start, reverse=True)

        token_counts: Dict[str, int] = {}
        # Precompute forward token numbering if tokenize mode is selected
        if mode == "tokenize":
            forward_pairs = sorted(pairs, key=lambda p: p[0].start)
            forward_replacements = {}
            for finding, raw_val in forward_pairs:
                idx = token_counts.get(finding.entity_type, 0) + 1
                token_counts[finding.entity_type] = idx
                forward_replacements[finding.start] = f"[{finding.entity_type}_{idx}]"

        chars = list(text)
        for finding, raw_val in sorted_pairs:
            start, end = finding.start, finding.end
            if mode == "tokenize":
                replacement = forward_replacements[start]
            else:
                replacement = self._get_replacement(
                    finding.entity_type, raw_val, mode, token_counts
                )
            chars[start:end] = list(replacement)

        redacted_text = "".join(chars)
        findings = [f for f, _ in pairs]
        return redacted_text, len(findings), findings


_DEFAULT_REDACTOR = DLPRedactor()


def redact_text(text: str, mode: str = "full") -> Tuple[str, int]:
    """Convenience helper to redact plain text."""
    redacted_str, count, _ = _DEFAULT_REDACTOR.redact_text(text, mode=mode)
    return redacted_str, count
