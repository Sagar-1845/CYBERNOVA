"""
tests/test_dlp_redactor.py
──────────────────────────
Tests for DLP Redactor:
- Modes: full, partial, irreversible, tokenize
- Multi-format document redaction: TXT, DOCX, and PDF
- Verification guarantee: Proves that in redacted PDF, sensitive text is physically stripped
  and cannot be extracted via PyMuPDF get_text().
"""

import io
import pymupdf
import docx
import pytest

from app.dlp.redactor import DLPRedactor, redact_text
from app.dlp.channels.document_channel import DocumentChannel, redact_document


def test_text_redaction_modes():
    text = "Account with Aadhaar 3675 9834 6012 and secret sk-proj-1234567890abcdefghijklmnop"

    # 1. Full mode
    full_out, count = redact_text(text, mode="full")
    assert count >= 2
    assert "[REDACTED: AADHAAR]" in full_out
    assert "[REDACTED: SECRET_KEY]" in full_out
    assert "3675 9834 6012" not in full_out

    # 2. Partial mode
    partial_out, _ = redact_text(text, mode="partial")
    assert "XXXX-XXXX-6012" in partial_out
    assert "3675 9834 6012" not in partial_out

    # 3. Irreversible mode
    irrev_out, _ = redact_text(text, mode="irreversible")
    assert "████" in irrev_out
    assert "3675 9834 6012" not in irrev_out

    # 4. Tokenize mode
    tok_out, _ = redact_text(text, mode="tokenize")
    assert "[AADHAAR_1]" in tok_out or "[AADHAAR" in tok_out
    assert "3675 9834 6012" not in tok_out


def test_docx_redaction():
    chan = DocumentChannel()
    doc = docx.Document()
    doc.add_paragraph("Customer PAN ABCPE1234F recorded.")
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Card"
    table.rows[0].cells[1].text = "4111-1111-1111-1111"

    buf = io.BytesIO()
    doc.save(buf)
    docx_bytes = buf.getvalue()

    out_bytes, removed, remaining, verified = chan.redact(docx_bytes, "audit.docx", mode="full")

    assert removed >= 2
    assert remaining == 0
    assert verified is True

    # Re-read docx and verify raw strings are gone
    re_doc = docx.Document(io.BytesIO(out_bytes))
    all_text = " ".join([p.text for p in re_doc.paragraphs] + [c.text for r in re_doc.tables[0].rows for c in r.cells])
    assert "ABCPE1234F" not in all_text
    assert "4111-1111-1111-1111" not in all_text
    assert "[REDACTED:" in all_text


def test_pdf_redaction_proves_text_cannot_be_extracted():
    """
    CRITICAL SECURITY PROOF:
    Demonstrates that PyMuPDF's apply_redactions() physically destroys and removes
    the underlying character glyphs from the PDF content stream.
    """
    chan = DocumentChannel()

    # 1. Create a synthetic PDF containing sensitive PII and secrets
    doc = pymupdf.open()
    page = doc.new_page()
    sensitive_aadhaar = "3675 9834 6012"
    sensitive_card = "4111-1111-1111-1111"
    sensitive_key = "sk-proj-1234567890abcdefghijklmnop"

    page.insert_text(
        (50, 80),
        f"Confidential Report:\n"
        f"Aadhaar Number: {sensitive_aadhaar}\n"
        f"Payment Card: {sensitive_card}\n"
        f"Access Token: {sensitive_key}\n"
    )
    raw_pdf_bytes = doc.tobytes()
    doc.close()

    # Pre-condition check: verify the raw PDF definitely contains the sensitive text
    probe_doc = pymupdf.open(stream=raw_pdf_bytes, filetype="pdf")
    initial_text = probe_doc[0].get_text("text")
    assert sensitive_aadhaar in initial_text
    assert sensitive_card in initial_text
    assert sensitive_key in initial_text
    probe_doc.close()

    # 2. Execute document redaction (irreversible mode)
    redacted_pdf_bytes, removed, remaining, verified = chan.redact(
        raw_pdf_bytes, "report.pdf", mode="irreversible"
    )

    assert removed >= 3
    assert remaining == 0
    assert verified is True

    # 3. Security proof: Open the resulting PDF and verify extraction failure
    redacted_doc = pymupdf.open(stream=redacted_pdf_bytes, filetype="pdf")
    extracted_text = redacted_doc[0].get_text("text")
    redacted_doc.close()

    # PROVE that sensitive raw strings CANNOT be extracted from the PDF stream
    assert sensitive_aadhaar not in extracted_text, "Aadhaar was extractable from redacted PDF!"
    assert sensitive_card not in extracted_text, "Card was extractable from redacted PDF!"
    assert sensitive_key not in extracted_text, "Secret key was extractable from redacted PDF!"
