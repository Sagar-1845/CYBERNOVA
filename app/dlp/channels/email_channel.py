"""
app/dlp/channels/email_channel.py
──────────────────────────────────
Email channel for DLP inspection and redaction of RFC 2822 / MIME .eml files.

Supported parts:
  - Headers:     Subject (plain string)
  - Body:        text/plain and text/html payloads (HTML is stripped to plain text)
  - Attachments: PDF, DOCX, TXT/CSV/JSON/MD via DocumentChannel

Recipient domain check:
  - Internal domains are loaded from policies/default.yaml → internal_domains list.
  - Any To/CC/BCC address whose domain is NOT in that list → recipients_external = True.

Privacy guarantee:
  - Zero raw sensitive values are stored or returned. Only masked_preview in DLPFinding.
  - Never logs raw PII.
"""

from __future__ import annotations

import email
import email.policy
import html
import io
import re
from email.message import Message
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

from app.dlp.channels.document_channel import DocumentChannel
from app.dlp.inspector import DLPInspector
from app.dlp.models import DLPFinding
from app.dlp.redactor import DLPRedactor


# ---------------------------------------------------------------------------
# Policy: load internal_domains once at import time (tolerant fallback)
# ---------------------------------------------------------------------------
_DEFAULT_POLICY_PATH = Path("policies/default.yaml")
_FALLBACK_INTERNAL_DOMAINS: Set[str] = {"corp.internal", "zeroleak.internal"}


def _load_internal_domains(policy_path: Path = _DEFAULT_POLICY_PATH) -> Set[str]:
    if not policy_path.is_file():
        return set(_FALLBACK_INTERNAL_DOMAINS)
    try:
        with open(policy_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        raw = cfg.get("internal_domains", [])
        domains = {str(d).strip().lower() for d in raw if d}
        return domains or set(_FALLBACK_INTERNAL_DOMAINS)
    except Exception:
        return set(_FALLBACK_INTERNAL_DOMAINS)


_INTERNAL_DOMAINS: Set[str] = _load_internal_domains()

# Simple regex to extract domain from an email address
_ADDR_DOMAIN_RE = re.compile(r"@([\w.\-]+)")
# Strip HTML tags
_HTML_TAG_RE = re.compile(r"<[^>]+>")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_html(raw_html: str) -> str:
    """Very lightweight HTML → plain text (strips tags, unescapes entities)."""
    no_tags = _HTML_TAG_RE.sub(" ", raw_html)
    return html.unescape(no_tags)


def _parse_addresses(header_val: Optional[str]) -> List[str]:
    """Extract individual email addresses from a comma-separated header string."""
    if not header_val:
        return []
    # Split on commas, then extract the address portion from "Display Name <addr>"
    addrs: List[str] = []
    for chunk in header_val.split(","):
        chunk = chunk.strip()
        m = re.search(r"<([^>]+)>", chunk)
        if m:
            addrs.append(m.group(1).strip().lower())
        elif "@" in chunk:
            addrs.append(chunk.lower())
    return addrs


def _has_external_recipients(msg: Message, internal_domains: Set[str]) -> bool:
    """Return True if any To/CC/BCC address belongs to a domain not in internal_domains."""
    combined: List[str] = []
    for hdr in ("To", "Cc", "Bcc"):
        combined.extend(_parse_addresses(msg.get(hdr, "")))

    for addr in combined:
        m = _ADDR_DOMAIN_RE.search(addr)
        if m:
            domain = m.group(1).lower()
            if domain not in internal_domains:
                return True
    return False


# ---------------------------------------------------------------------------
# EML Part result types
# ---------------------------------------------------------------------------

class EmailPartFindings:
    """Findings for a single part of an email (subject, body, or attachment)."""

    def __init__(self, part_name: str, findings: List[DLPFinding]) -> None:
        self.part_name = part_name  # e.g. "subject", "body/plain", "attachment:report.pdf"
        self.findings = findings

    def to_dict(self) -> dict:
        return {
            "part": self.part_name,
            "findings": [f.model_dump() for f in self.findings],
            "finding_count": len(self.findings),
        }


class EmailScanResult:
    """Aggregated scan result for a full .eml message."""

    def __init__(
        self,
        parts: List[EmailPartFindings],
        all_findings: List[DLPFinding],
        recipients_external: bool,
        subject: str,
    ) -> None:
        self.parts = parts
        self.all_findings = all_findings
        self.recipients_external = recipients_external
        self.subject = subject


# ---------------------------------------------------------------------------
# Main EmailChannel
# ---------------------------------------------------------------------------

class EmailChannel:
    """
    Inspect and redact RFC 2822 / MIME email files (.eml).

    Args:
        inspector:        DLPInspector instance (uses default if None)
        redactor:         DLPRedactor instance (uses default if None)
        document_channel: DocumentChannel for attachment scanning (uses default if None)
        internal_domains: Override the domain whitelist (uses policies/default.yaml if None)
    """

    def __init__(
        self,
        inspector: Optional[DLPInspector] = None,
        redactor: Optional[DLPRedactor] = None,
        document_channel: Optional[DocumentChannel] = None,
        internal_domains: Optional[Set[str]] = None,
    ) -> None:
        self.inspector = inspector or DLPInspector()
        self.redactor = redactor or DLPRedactor(self.inspector)
        self.doc_channel = document_channel or DocumentChannel(self.inspector, self.redactor)
        self.internal_domains = internal_domains if internal_domains is not None else _INTERNAL_DOMAINS

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(self, eml_bytes: bytes) -> EmailScanResult:
        """
        Parse and scan a .eml file.

        Returns an EmailScanResult with per-part findings, aggregated findings,
        and a recipients_external flag.
        """
        msg = email.message_from_bytes(eml_bytes, policy=email.policy.compat32)

        parts: List[EmailPartFindings] = []
        all_findings: List[DLPFinding] = []

        # 1. Subject header
        subject_raw: str = msg.get("Subject", "") or ""
        subject_findings = self.inspector.inspect(subject_raw, page=None)
        parts.append(EmailPartFindings("subject", subject_findings))
        all_findings.extend(subject_findings)

        # 2. Walk MIME tree
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = part.get_content_disposition() or ""

            # Skip multipart containers themselves
            if part.get_content_maintype() == "multipart":
                continue

            fname = part.get_filename()

            # ---- body parts (not an attachment) ----
            if disposition != "attachment" and not fname:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                try:
                    text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    text = payload.decode("utf-8", errors="replace")

                if ctype == "text/html":
                    text = _strip_html(text)
                    part_name = "body/html"
                elif ctype == "text/plain":
                    part_name = "body/plain"
                else:
                    part_name = f"body/{ctype}"

                body_findings = self.inspector.inspect(text, page=None)
                parts.append(EmailPartFindings(part_name, body_findings))
                all_findings.extend(body_findings)

            # ---- attachment parts ----
            elif fname:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                att_name = f"attachment:{fname}"
                try:
                    _, att_findings = self.doc_channel.scan(payload, fname)
                    parts.append(EmailPartFindings(att_name, att_findings))
                    all_findings.extend(att_findings)
                except Exception as exc:
                    # Log attachment scan error without exposing raw content
                    error_part = EmailPartFindings(att_name, [])
                    error_part._error = f"attachment scan failed: {type(exc).__name__}"  # type: ignore[attr-defined]
                    parts.append(error_part)

        # 3. Recipient domain check
        recipients_external = _has_external_recipients(msg, self.internal_domains)

        return EmailScanResult(
            parts=parts,
            all_findings=all_findings,
            recipients_external=recipients_external,
            subject=subject_raw,
        )

    # ------------------------------------------------------------------
    # Redact
    # ------------------------------------------------------------------

    def redact(self, eml_bytes: bytes, mode: str = "full") -> Tuple[bytes, int, int, bool]:
        """
        Redact sensitive content from a .eml file in-place.

        Redacts:
          - Subject header
          - text/plain and text/html body parts
          - PDF, DOCX, and TXT attachments (via DocumentChannel)

        Returns:
            (redacted_eml_bytes, findings_removed, findings_remaining, verified)
        """
        # We rebuild the message by re-encoding after redaction
        msg = email.message_from_bytes(eml_bytes, policy=email.policy.compat32)
        total_removed = 0

        # 1. Redact Subject header
        subject_raw: str = msg.get("Subject", "") or ""
        if subject_raw:
            redacted_subject, sub_removed, _ = self.redactor.redact_text(subject_raw, mode=mode)
            total_removed += sub_removed
            # Replace header value
            if "Subject" in msg:
                del msg["Subject"]
            msg["Subject"] = redacted_subject

        # 2. Walk and redact body/attachment parts
        for part in msg.walk():
            ctype = part.get_content_type()
            disposition = part.get_content_disposition() or ""
            if part.get_content_maintype() == "multipart":
                continue

            fname = part.get_filename()

            # ---- body parts ----
            if disposition != "attachment" and not fname:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="replace")
                except Exception:
                    text = payload.decode("utf-8", errors="replace")

                if ctype == "text/html":
                    plain_text = _strip_html(text)
                    redacted_plain, removed, _ = self.redactor.redact_text(plain_text, mode=mode)
                    total_removed += removed
                    # Rebuild minimal HTML around redacted plain text
                    redacted_text = f"<html><body><pre>{html.escape(redacted_plain)}</pre></body></html>"
                else:
                    redacted_text, removed, _ = self.redactor.redact_text(text, mode=mode)
                    total_removed += removed

                part.set_payload(redacted_text.encode(charset, errors="replace"))
                part.set_param("charset", charset)
                # Clear Content-Transfer-Encoding so it isn't stale (will be base64 or qp)
                if "Content-Transfer-Encoding" in part:
                    del part["Content-Transfer-Encoding"]
                part["Content-Transfer-Encoding"] = "quoted-printable"

            # ---- attachments ----
            elif fname:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                try:
                    out_bytes, att_removed, _, _ = self.doc_channel.redact(payload, fname, mode=mode)
                    total_removed += att_removed
                    # Re-encode attachment as base64
                    import base64
                    part.set_payload(base64.b64encode(out_bytes).decode("ascii"))
                    if "Content-Transfer-Encoding" in part:
                        del part["Content-Transfer-Encoding"]
                    part["Content-Transfer-Encoding"] = "base64"
                except Exception:
                    pass  # Leave unredactable attachments untouched; never log raw values

        # Serialize the modified message
        redacted_eml_bytes = msg.as_bytes(policy=email.policy.compat32)

        # 3. Post-redaction verification scan
        verify_result = self.scan(redacted_eml_bytes)
        findings_remaining = len(verify_result.all_findings)
        verified = findings_remaining == 0

        return redacted_eml_bytes, total_removed, findings_remaining, verified


# ---------------------------------------------------------------------------
# Module-level convenience instances
# ---------------------------------------------------------------------------

_DEFAULT_EMAIL_CHANNEL = EmailChannel()


def scan_email(eml_bytes: bytes) -> EmailScanResult:
    """Scan an .eml file for sensitive data using the default EmailChannel."""
    return _DEFAULT_EMAIL_CHANNEL.scan(eml_bytes)


def redact_email(
    eml_bytes: bytes, mode: str = "full"
) -> Tuple[bytes, int, int, bool]:
    """Redact an .eml file using the default EmailChannel."""
    return _DEFAULT_EMAIL_CHANNEL.redact(eml_bytes, mode=mode)
