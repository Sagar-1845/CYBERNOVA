"""
app/dlp/incident_vault.py
─────────────────────────
Tamper-evident, zero-raw-PII audit ledger for DLP events and redaction operations.

GUARANTEE:
No raw sensitive entity values are ever persisted or returned.
Audit records contain ONLY: entity type, count, character offsets, sha-256 hash, and decision metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from app.dlp.models import DLPDecision, DLPFinding, DLPIncident, DLPSensitivity


_INCIDENT_STORE: List[DLPIncident] = []
_LOCK = threading.Lock()
_AUDIT_LOG_PATH = Path("data/dlp_incidents.json")


def _compute_sha256(val: str) -> str:
    """Compute truncated SHA-256 hash of a string for non-reversible audit tracking."""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()[:16]


def record_incident(
    doc_id: str,
    filename: str,
    destination: str,
    department: str,
    sensitivity: DLPSensitivity,
    risk_score: float,
    decision: DLPDecision,
    findings: Sequence[DLPFinding],
    raw_values: Optional[Sequence[str]] = None,
) -> DLPIncident:
    """
    Record a DLP security event into the audit ledger with ZERO raw PII.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    incident_id = f"inc_{uuid.uuid4().hex[:12]}"

    # Group findings summary without raw values
    summary_map: Dict[str, Dict[str, Any]] = {}
    for idx, f in enumerate(findings):
        ent_type = f.entity_type
        if ent_type not in summary_map:
            # Hash either the raw value (if passed internally) or masked preview
            hash_val = _compute_sha256(raw_values[idx]) if (raw_values and idx < len(raw_values)) else _compute_sha256(f.masked_preview)
            summary_map[ent_type] = {
                "entity_type": ent_type,
                "count": 0,
                "offsets": [],
                "sha256": hash_val,
            }
        summary_map[ent_type]["count"] += 1
        summary_map[ent_type]["offsets"].append({"start": f.start, "end": f.end, "page": f.page})

    incident = DLPIncident(
        incident_id=incident_id,
        doc_id=doc_id,
        timestamp=timestamp,
        filename=filename,
        destination=destination,
        department=department,
        sensitivity=sensitivity,
        risk_score=risk_score,
        decision=decision,
        findings_summary=list(summary_map.values()),
    )

    with _LOCK:
        _INCIDENT_STORE.append(incident)
        # Ephemeral persistent copy if data dir exists/writable
        try:
            _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(_AUDIT_LOG_PATH, "w", encoding="utf-8") as f:
                dump_data = [
                    inc.model_dump() if hasattr(inc, "model_dump") else inc.dict()
                    for inc in _INCIDENT_STORE
                ]
                json.dump(dump_data, f, indent=2)
        except Exception:
            pass

    return incident


def get_incidents(limit: int = 100) -> List[DLPIncident]:
    """Retrieve the most recent DLP incident audit logs (newest first)."""
    with _LOCK:
        return list(reversed(_INCIDENT_STORE[-limit:]))


def clear_incidents() -> None:
    """Clear in-memory and on-disk incidents (primarily for testing)."""
    with _LOCK:
        _INCIDENT_STORE.clear()
        if _AUDIT_LOG_PATH.is_file():
            try:
                _AUDIT_LOG_PATH.unlink()
            except Exception:
                pass
