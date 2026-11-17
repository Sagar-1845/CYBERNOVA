"""
tests/test_dlp_inspector.py
───────────────────────────
Tests for DLP inspector:
- Indian PII detection (Aadhaar, PAN, Phone, Email)
- Strict Credit Card Luhn validation (valid accepted, invalid rejected)
- Secrets detection (API keys, AWS keys, GitHub tokens, Bearer tokens, Passwords, JWTs)
- Privacy safety: zero raw values in DLPFinding models
"""

import pytest
from app.dlp.inspector import DLPInspector, inspect_text, generate_masked_preview


@pytest.fixture
def inspector():
    return DLPInspector()


def test_aadhaar_and_pan_detection(inspector):
    # Valid Aadhaar with Verhoeff checksum & valid PAN with 'P' (Person) 4th char
    text = "Citizen Aadhaar is 3675 9834 6012 and PAN is ABCPE1234F."
    findings = inspector.inspect(text)
    
    types = [f.entity_type for f in findings]
    assert "AADHAAR" in types
    assert "PAN" in types

    aadhaar_f = next(f for f in findings if f.entity_type == "AADHAAR")
    assert aadhaar_f.masked_preview == "XXXX-XXXX-6012"
    assert "3675" not in aadhaar_f.masked_preview

    pan_f = next(f for f in findings if f.entity_type == "PAN")
    assert pan_f.masked_preview.startswith("AB")
    assert pan_f.masked_preview.endswith("F")
    assert "CPE123" not in pan_f.masked_preview


def test_credit_card_luhn_validation(inspector):
    # 4111111111111111 is a valid Visa test number (passes Luhn)
    valid_text = "Card number 4111-1111-1111-1111 for checkout"
    findings_valid = inspector.inspect(valid_text)
    card_types = [f.entity_type for f in findings_valid if f.entity_type == "CREDIT_CARD"]
    assert len(card_types) == 1
    assert findings_valid[0].masked_preview == "****-****-****-1111"

    # 4532015012345677 fails Luhn checksum
    invalid_text = "Bad card 4532 0150 1234 5677 will fail check"
    findings_invalid = inspector.inspect(invalid_text)
    invalid_cards = [f for f in findings_invalid if f.entity_type == "CREDIT_CARD"]
    assert len(invalid_cards) == 0


def test_secrets_and_credentials_detection(inspector):
    text = (
        "Config:\n"
        "openai_key = sk-proj-1234567890abcdefghijklmnop\n"
        "aws_key = AKIAIOSFODNN7EXAMPLE\n"
        "github = ghp_1234567890abcdefghijklmnopqrstuvwxyz\n"
        "auth: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_this_signature\n"
        "password = SuperSecretMasterKey!2026\n"
    )
    findings = inspector.inspect(text)
    entity_types = {f.entity_type for f in findings}

    assert "SECRET_KEY" in entity_types
    assert "PASSWORD" in entity_types
    assert "JWT_TOKEN" in entity_types

    # Ensure no raw secrets in previews
    for f in findings:
        assert "SuperSecretMasterKey" not in f.masked_preview
        assert "do_not_leak_this_signature" not in f.masked_preview
        assert "AKIAIOSFODNN7EXAMPLE" != f.masked_preview


def test_convenience_inspect_text():
    findings = inspect_text("Contact us at support@zeroleak.ai or +91 9876543210")
    types = {f.entity_type for f in findings}
    assert "EMAIL" in types
    assert "PHONE" in types
