"""
app/api/dlp_routes.py
─────────────────────
DLP and Sensitive Data Redaction REST API routes:
- POST /api/v1/dlp/scan       Multi-format document inspection & policy verdict
- POST /api/v1/dlp/redact     Multi-mode document redaction with verification
- GET  /api/v1/dlp/download/{doc_id}  Download redacted document
- GET  /api/v1/dlp/audit      Zero-PII tamper-evident DLP incident ledger
"""

from __future__ import annotations

import mimetypes
import uuid
from typing import Dict, List, Optional, Tuple
from fastapi import APIRouter, File, Form, HTTPException, Response, UploadFile, status

from app.dlp.models import (
    DLPDecision,
    DLPIncident,
    DLPRedactResult,
    DLPScanResult,
)
from app.dlp.channels.document_channel import (
    detect_format,
    scan_document,
    redact_document,
)
from app.dlp.policy_engine import evaluate_dlp_policy
from app.dlp.incident_vault import record_incident, get_incidents

router = APIRouter(prefix="/api/v1/dlp", tags=["dlp"])

# Ephemeral in-memory store for redacted document downloads
# doc_id -> (filename, content_bytes, content_type)
_DOWNLOAD_STORE: Dict[str, Tuple[str, bytes, str]] = {}


def _get_media_type(filename: str, fmt: str) -> str:
    """Resolve correct HTTP media type."""
    if fmt == "pdf" or filename.lower().endswith(".pdf"):
        return "application/pdf"
    if fmt == "docx" or filename.lower().endswith(".docx"):
        return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return "text/plain; charset=utf-8"


@router.post("/scan", response_model=DLPScanResult, status_code=status.HTTP_200_OK)
async def scan_file(
    file: UploadFile = File(..., description="Target document (PDF, DOCX, TXT)"),
    destination: str = Form(default="external", description="Destination: 'external' or 'internal'"),
    department: str = Form(default="general", description="Department: 'hr', 'finance', 'engineering', etc."),
) -> DLPScanResult:
    """
    Inspect an uploaded document for sensitive PII, credit cards, credentials, and evaluate DLP policy.
    Guarantees: Zero raw PII in returned findings or logs.
    """
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    doc_id = f"doc_{uuid.uuid4().hex[:10]}"
    filename = file.filename or "uploaded_document.txt"

    # Scan document across formats
    fmt, findings = scan_document(content, filename)

    # Evaluate DLP policy
    decision: DLPDecision = evaluate_dlp_policy(
        findings=findings,
        destination=destination,
        department=department,
    )

    # Record sanitized incident in zero-raw-PII audit ledger
    record_incident(
        doc_id=doc_id,
        filename=filename,
        destination=destination,
        department=department,
        sensitivity=decision.sensitivity,
        risk_score=decision.risk_score,
        decision=decision,
        findings=findings,
    )

    return DLPScanResult(
        doc_id=doc_id,
        filename=filename,
        format=fmt,
        sensitivity=decision.sensitivity,
        risk_score=decision.risk_score,
        findings=findings,
        decision=decision,
    )


@router.post("/redact", response_model=DLPRedactResult, status_code=status.HTTP_200_OK)
async def redact_file(
    file: UploadFile = File(..., description="Document to redact (PDF, DOCX, TXT)"),
    mode: str = Form(default="full", description="Redaction mode: 'full', 'partial', 'irreversible', or 'tokenize'"),
) -> DLPRedactResult:
    """
    Redact sensitive information from the uploaded document, re-scan to verify removal,
    and generate a secure download link.
    """
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    doc_id = f"doc_{uuid.uuid4().hex[:10]}"
    filename = file.filename or "redacted_document.txt"

    out_bytes, removed, remaining, verified = redact_document(
        content=content,
        filename=filename,
        mode=mode,
    )

    fmt = detect_format(filename, content)
    media_type = _get_media_type(filename, fmt)

    # Save to ephemeral download store
    _DOWNLOAD_STORE[doc_id] = (filename, out_bytes, media_type)

    download_url = f"/api/v1/dlp/download/{doc_id}"

    return DLPRedactResult(
        doc_id=doc_id,
        download_url=download_url,
        findings_removed=removed,
        findings_remaining=remaining,
        verified=verified,
    )


@router.get("/download/{doc_id}")
async def download_file(doc_id: str):
    """Download a redacted document by doc_id."""
    item = _DOWNLOAD_STORE.get(doc_id)
    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found or download link expired.",
        )

    filename, content, media_type = item
    headers = {
        "Content-Disposition": f'attachment; filename="redacted_{filename}"',
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/audit", response_model=List[DLPIncident], status_code=status.HTTP_200_OK)
async def get_audit_log(limit: int = 100) -> List[DLPIncident]:
    """Retrieve DLP audit ledger incidents with zero raw sensitive data."""
    return get_incidents(limit=limit)
