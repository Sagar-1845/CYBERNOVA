"""
app/dlp/models.py
─────────────────
Pydantic models and schemas for ZeroLeak AI DLP.
Guarantees: DLPFinding and DLPIncident never contain raw sensitive values.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DLPSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"


class DLPAction(str, Enum):
    ALLOW = "ALLOW"
    REDACT_AND_FORWARD = "REDACT_AND_FORWARD"
    BLOCK = "BLOCK"


class DLPFinding(BaseModel):
    """
    Represents a detected sensitive entity.
    STRICT PRIVACY: Never stores the raw sensitive text.
    """
    entity_type: str = Field(..., description="Entity category, e.g. AADHAAR, PAN, SECRET_KEY")
    type: Optional[str] = Field(default=None, description="Frontend alias for entity_type")
    id: Optional[str] = Field(default=None, description="Finding identifier")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Detection confidence")
    page: Optional[int] = Field(default=None, description="1-based page index if paginated")
    start: int = Field(..., description="Start character offset")
    end: int = Field(..., description="End character offset")
    masked_preview: str = Field(..., description="Safe masked preview, e.g. XXXX-XXXX-1234")
    rule_id: Optional[str] = Field(default=None, description="Identifier of triggering rule")

    def __init__(self, **data):
        super().__init__(**data)
        if not self.type:
            self.type = self.entity_type
        if not self.id:
            self.id = self.rule_id


class DLPDecision(BaseModel):
    """Policy engine verdict for a document or text payload."""
    action: DLPAction = Field(..., description="ALLOW, REDACT_AND_FORWARD, or BLOCK")
    reasons: List[str] = Field(default_factory=list, description="Explanations for the decision")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="0-100 composite risk score")
    sensitivity: DLPSensitivity = Field(default=DLPSensitivity.PUBLIC, description="Document sensitivity tier")


class DLPScanResult(BaseModel):
    """Result returned by POST /api/v1/dlp/scan."""
    doc_id: str
    filename: str
    format: str
    sensitivity: DLPSensitivity
    risk_score: float
    findings: List[DLPFinding] = Field(default_factory=list)
    decision: DLPDecision


class DLPRedactResult(BaseModel):
    """Result returned by POST /api/v1/dlp/redact."""
    doc_id: str
    download_url: str
    findings_removed: int
    findings_remaining: int
    verified: bool


class DLPIncident(BaseModel):
    """
    Sanitized audit log entry for a DLP event.
    Zero raw PII: stores type, count, offset, sha256, and decision.
    """
    incident_id: str
    doc_id: str
    timestamp: str
    filename: str
    destination: str
    department: str
    sensitivity: DLPSensitivity
    risk_score: float
    decision: DLPDecision
    findings_summary: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of {entity_type, count, offsets, sha256} records with NO raw values"
    )
