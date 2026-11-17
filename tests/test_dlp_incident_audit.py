"""
tests/test_dlp_incident_audit.py
────────────────────────────────
Tests for DLP incident audit vault:
- Zero raw PII guarantee in incident summaries
- Tamper-evident ledger record keeping
- REST API integration: scan records audit incidents, and audit endpoint returns them
"""

import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.dlp.models import DLPAction, DLPDecision, DLPFinding, DLPSensitivity
from app.dlp.incident_vault import record_incident, get_incidents, clear_incidents


@pytest.fixture(autouse=True)
def clean_vault():
    clear_incidents()
    yield
    clear_incidents()


def test_record_incident_zero_raw_pii():
    findings = [
        DLPFinding(
            entity_type="AADHAAR",
            confidence=0.99,
            start=10,
            end=24,
            masked_preview="XXXX-XXXX-6012",
        ),
        DLPFinding(
            entity_type="SECRET_KEY",
            confidence=0.98,
            start=30,
            end=65,
            masked_preview="sk-****...5678",
        ),
    ]
    raw_sensitive_values = ["3675 9834 6012", "sk-proj-1234567890abcdefghijklmnop"]

    decision = DLPDecision(
        action=DLPAction.BLOCK,
        reasons=["Blocked critical PII"],
        risk_score=75.0,
        sensitivity=DLPSensitivity.CONFIDENTIAL,
    )

    incident = record_incident(
        doc_id="doc_audit_test_1",
        filename="payroll.txt",
        destination="external",
        department="finance",
        sensitivity=decision.sensitivity,
        risk_score=decision.risk_score,
        decision=decision,
        findings=findings,
        raw_values=raw_sensitive_values,
    )

    assert incident.doc_id == "doc_audit_test_1"
    assert incident.filename == "payroll.txt"
    assert len(incident.findings_summary) == 2

    # STRICT ZERO-RAW-PII VERIFICATION:
    # Ensure neither of the raw values appears anywhere in the incident serialization
    incident_dict = incident.model_dump() if hasattr(incident, "model_dump") else incident.dict()
    incident_json = json.dumps(incident_dict)

    for raw_val in raw_sensitive_values:
        assert raw_val not in incident_json, f"Raw value '{raw_val}' was leaked into incident audit log!"

    # Verify sha256 hash presence
    for item in incident.findings_summary:
        assert "sha256" in item
        assert len(item["sha256"]) == 16
        assert "offsets" in item


def test_api_audit_endpoints():
    client = TestClient(app)

    # 1. Scan a document via API
    scan_resp = client.post(
        "/api/v1/dlp/scan",
        files={"file": ("test_leak.txt", b"Aadhaar 3675 9834 6012 and card 4111-1111-1111-1111")},
        data={"destination": "external", "department": "hr"},
    )
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["decision"]["action"] == "BLOCK"

    # 2. Query the audit ledger
    audit_resp = client.get("/api/v1/dlp/audit")
    assert audit_resp.status_code == 200
    incidents = audit_resp.json()
    assert len(incidents) >= 1

    latest = incidents[0]
    assert latest["filename"] == "test_leak.txt"
    assert latest["destination"] == "external"

    # Ensure no raw sensitive text exists in audit API response
    raw_response_text = audit_resp.text
    assert "3675 9834 6012" not in raw_response_text
    assert "4111-1111-1111-1111" not in raw_response_text
