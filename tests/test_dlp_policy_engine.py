"""
tests/test_dlp_policy_engine.py
───────────────────────────────
Tests for DLP Policy Engine:
- Destination rules:
  * External destination: Aadhaar/Card/Secrets -> BLOCK
  * External destination: PAN/Phone/Email -> REDACT_AND_FORWARD
  * Clean document -> ALLOW
  * Internal destination: Aadhaar/Card -> REDACT_AND_FORWARD, Secrets -> BLOCK
- Sensitivity classification: PUBLIC, INTERNAL, CONFIDENTIAL
- Risk score evaluation
"""

import pytest
from app.dlp.models import DLPAction, DLPFinding, DLPSensitivity
from app.dlp.policy_engine import DLPPolicyEngine, evaluate_dlp_policy


@pytest.fixture
def policy_engine():
    return DLPPolicyEngine()


def test_clean_document_allowed(policy_engine):
    findings = []
    decision = policy_engine.evaluate(findings, destination="external")
    assert decision.action == DLPAction.ALLOW
    assert decision.sensitivity == DLPSensitivity.PUBLIC
    assert decision.risk_score == 0.0


def test_external_aadhaar_blocked(policy_engine):
    findings = [
        DLPFinding(
            entity_type="AADHAAR",
            confidence=0.99,
            start=10,
            end=24,
            masked_preview="XXXX-XXXX-6012",
        )
    ]
    decision = policy_engine.evaluate(findings, destination="external")
    assert decision.action == DLPAction.BLOCK
    assert decision.sensitivity == DLPSensitivity.CONFIDENTIAL
    assert "Critical entities [AADHAAR]" in decision.reasons[0]


def test_external_pan_redact_and_forward(policy_engine):
    findings = [
        DLPFinding(
            entity_type="PAN",
            confidence=0.98,
            start=5,
            end=15,
            masked_preview="AB*****F",
        ),
        DLPFinding(
            entity_type="EMAIL",
            confidence=0.95,
            start=20,
            end=35,
            masked_preview="s***@zeroleak.ai",
        ),
    ]
    decision = policy_engine.evaluate(findings, destination="external")
    assert decision.action == DLPAction.REDACT_AND_FORWARD
    assert decision.sensitivity == DLPSensitivity.INTERNAL
    assert "must be redacted" in decision.reasons[0]


def test_internal_destination_handling(policy_engine):
    # Aadhaar internal is REDACT_AND_FORWARD, not BLOCK
    aadhaar_findings = [
        DLPFinding(
            entity_type="AADHAAR",
            confidence=0.99,
            start=10,
            end=24,
            masked_preview="XXXX-XXXX-6012",
        )
    ]
    decision = policy_engine.evaluate(aadhaar_findings, destination="internal")
    assert decision.action == DLPAction.REDACT_AND_FORWARD

    # Secret keys internal are still BLOCK
    secret_findings = [
        DLPFinding(
            entity_type="SECRET_KEY",
            confidence=0.99,
            start=5,
            end=30,
            masked_preview="sk-****...1234",
        )
    ]
    secret_decision = policy_engine.evaluate(secret_findings, destination="internal")
    assert secret_decision.action == DLPAction.BLOCK


def test_convenience_evaluate_dlp_policy():
    findings = [
        DLPFinding(
            entity_type="CREDIT_CARD",
            confidence=0.99,
            start=0,
            end=19,
            masked_preview="****-****-****-1111",
        )
    ]
    decision = evaluate_dlp_policy(findings, destination="external")
    assert decision.action == DLPAction.BLOCK
    assert decision.sensitivity == DLPSensitivity.CONFIDENTIAL
