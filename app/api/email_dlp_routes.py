"""
app/api/email_dlp_routes.py
────────────────────────────
Email DLP REST API routes:
  POST /api/v1/dlp/email/scan    — Inspect a .eml for PII/secrets per-part + policy verdict
  POST /api/v1/dlp/email/redact  — Redact and re-verify a .eml; download link returned

Privacy guarantee: zero raw sensitive values in responses or logs.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field

from app.dlp.channels.email_channel import scan_email, redact_email, EmailScanResult
from app.dlp.models import DLPDecision, DLPFinding
from app.dlp.policy_engine import evaluate_dlp_policy
from app.dlp.incident_vault import record_incident


router = APIRouter(prefix="/api/v1/dlp/email", tags=["dlp-email"])

# Ephemeral in-memory store: doc_id → (filename, bytes)
_EMAIL_DOWNLOAD_STORE: Dict[str, Tuple[str, bytes]] = {}


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class EmailPartResult(BaseModel):
    """Findings for one MIME part of the email."""
    part: str = Field(..., description="Part label: 'subject', 'body/plain', 'attachment:report.txt'")
    finding_count: int
    findings: List[DLPFinding] = Field(default_factory=list)


class EmailScanResponse(BaseModel):
    """Response from POST /api/v1/dlp/email/scan."""
    findings: Dict[str, List[DLPFinding]] = Field(
        default_factory=dict,
        description="Findings grouped by part (subject, body, attachment name)",
    )
    decision: DLPDecision
    recipients_external: bool
    doc_id: str
    filename: str
    subject: str
    sensitivity: str
    risk_score: float
    parts: List[EmailPartResult] = Field(default_factory=list)
    all_findings: List[DLPFinding] = Field(default_factory=list)


class EmailRedactResponse(BaseModel):
    """Response from POST /api/v1/dlp/email/redact."""
    doc_id: str
    download_url: str
    findings_removed: int
    findings_remaining: int
    verified: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=EmailScanResponse, status_code=status.HTTP_200_OK)
async def scan_email_file(
    file: UploadFile = File(..., description=".eml file to inspect"),
    destination: str = Form(
        default="external",
        description="Override destination for policy evaluation: 'external' or 'internal'. "
                    "If the email has at least one external recipient, 'external' is also forced.",
    ),
) -> EmailScanResponse:
    """
    Inspect a .eml file for sensitive PII and credentials across all MIME parts.

    - Scans Subject header, text/plain and text/html bodies, and PDF/DOCX/TXT attachments.
    - Checks recipient (To/Cc/Bcc) domains against the internal_domains whitelist in
      policies/default.yaml; sets recipients_external = true when any external domain found.
    - Applies DLP policy based on the effective destination.
    - Returns per-part findings and an aggregated policy decision.
    - Guarantees: zero raw PII in findings or response.
    """
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded .eml file is empty.",
        )

    doc_id = f"email_{uuid.uuid4().hex[:10]}"
    filename = file.filename or "uploaded.eml"

    # Inspect all MIME parts
    try:
        result: EmailScanResult = scan_email(content)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to parse .eml file: {str(exc)}",
        )

    # If any external recipient detected, force external destination for policy eval
    effective_destination = destination
    if result.recipients_external:
        effective_destination = "external"

    # Policy evaluation across all findings
    decision: DLPDecision = evaluate_dlp_policy(
        findings=result.all_findings,
        destination=effective_destination,
        department="email",
    )

    # Build per-part response list
    part_results: List[EmailPartResult] = [
        EmailPartResult(
            part=p.part_name,
            finding_count=len(p.findings),
            findings=p.findings,
        )
        for p in result.parts
    ]

    # Sanitized audit record (zero raw PII)
    record_incident(
        doc_id=doc_id,
        filename=filename,
        destination=effective_destination,
        department="email",
        sensitivity=decision.sensitivity,
        risk_score=decision.risk_score,
        decision=decision,
        findings=result.all_findings,
    )

    return EmailScanResponse(
        doc_id=doc_id,
        filename=filename,
        subject=result.subject,
        sensitivity=decision.sensitivity.value,
        risk_score=decision.risk_score,
        recipients_external=result.recipients_external,
        parts=part_results,
        all_findings=result.all_findings,
        decision=decision,
    )


@router.post("/redact", response_model=EmailRedactResponse, status_code=status.HTTP_200_OK)
async def redact_email_file(
    file: UploadFile = File(..., description=".eml file to redact"),
    mode: str = Form(
        default="full",
        description="Redaction mode: 'full', 'partial', 'irreversible', or 'tokenize'",
    ),
) -> EmailRedactResponse:
    """
    Redact sensitive content from a .eml file.

    - Redacts Subject, body (plain and HTML), and attachments (PDF/DOCX/TXT).
    - Re-scans the output and sets verified = true only when findings_remaining == 0.
    - Stores the sanitized .eml in-memory and returns a download URL.
    - Guarantees: zero raw PII in response or logs.
    """
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded .eml file is empty.",
        )

    valid_modes = {"full", "partial", "irreversible", "tokenize"}
    if mode not in valid_modes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(valid_modes))}.",
        )

    filename = file.filename or "uploaded.eml"

    try:
        redacted_bytes, removed, remaining, verified = redact_email(content, mode=mode)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to redact .eml file: {str(exc)}",
        )

    doc_id = f"email_{uuid.uuid4().hex[:10]}"
    _EMAIL_DOWNLOAD_STORE[doc_id] = (filename, redacted_bytes)
    download_url = f"/api/v1/dlp/email/download/{doc_id}"

    return EmailRedactResponse(
        doc_id=doc_id,
        download_url=download_url,
        findings_removed=removed,
        findings_remaining=remaining,
        verified=verified,
    )


@router.get("/download/{doc_id}")
async def download_redacted_email(doc_id: str) -> Response:
    """Download a redacted .eml file by doc_id."""
    item = _EMAIL_DOWNLOAD_STORE.get(doc_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Redacted email not found or download link expired.",
        )
    filename, content = item
    headers = {
        "Content-Disposition": f'attachment; filename="redacted_{filename}"',
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
    return Response(
        content=content,
        media_type="message/rfc822",
        headers=headers,
    )
