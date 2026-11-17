"""
app/dlp/channels/document_channel.py
────────────────────────────────────
Multi-format document inspector and redactor supporting:
- PDF (via PyMuPDF / fitz: uses add_redact_annot + apply_redactions so text is physically removed)
- DOCX (via python-docx: runs and tables)
- TXT / Structured text files

Guarantees:
- Re-scans output after redacting and calculates findings_remaining.
- Returns verified status (True only if findings_remaining == 0).
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import List, Optional, Tuple

import pymupdf
import docx

from app.dlp.inspector import DLPInspector, generate_masked_preview
from app.dlp.models import DLPFinding
from app.dlp.redactor import DLPRedactor


def detect_format(filename: str, content: bytes = b"") -> str:
    """Detect format from filename extension or magic bytes."""
    suffix = Path(filename).suffix.lower()
    if suffix in [".pdf"]:
        return "pdf"
    if suffix in [".docx"]:
        return "docx"
    if suffix in [".txt", ".log", ".md", ".json", ".csv", ".tsv"]:
        return "txt"

    # Magic byte inspection fallback
    if content.startswith(b"%PDF"):
        return "pdf"
    if content.startswith(b"PK\x03\x04"):
        return "docx"

    return "txt"


class DocumentChannel:
    """Channel for scanning and redacting PDF, DOCX, and TXT documents."""

    def __init__(
        self,
        inspector: Optional[DLPInspector] = None,
        redactor: Optional[DLPRedactor] = None,
    ) -> None:
        self.inspector = inspector or DLPInspector()
        self.redactor = redactor or DLPRedactor(self.inspector)

    def scan(self, content: bytes, filename: str) -> Tuple[str, List[DLPFinding]]:
        """
        Scan a document content in-memory and return (file_format, findings).
        """
        fmt = detect_format(filename, content)
        findings: List[DLPFinding] = []

        if fmt == "pdf":
            doc = pymupdf.open(stream=content, filetype="pdf")
            for page_idx in range(len(doc)):
                page = doc[page_idx]
                page_text = page.get_text("text")
                page_findings = self.inspector.inspect(page_text, page=page_idx + 1)
                findings.extend(page_findings)
            doc.close()

        elif fmt == "docx":
            doc = docx.Document(io.BytesIO(content))
            full_text_parts: List[str] = []
            for p in doc.paragraphs:
                if p.text:
                    full_text_parts.append(p.text)
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text:
                            full_text_parts.append(cell.text)
            doc_text = "\n".join(full_text_parts)
            findings = self.inspector.inspect(doc_text, page=1)

        else:  # txt
            text = content.decode("utf-8", errors="replace")
            findings = self.inspector.inspect(text, page=1)

        return fmt, findings

    def redact(
        self, content: bytes, filename: str, mode: str = "full"
    ) -> Tuple[bytes, int, int, bool]:
        """
        Redact document according to mode ('full', 'partial', 'irreversible', 'tokenize').
        Re-scans output to calculate findings_remaining and returns:
        (output_bytes, findings_removed, findings_remaining, verified)
        """
        fmt = detect_format(filename, content)
        findings_removed = 0

        if fmt == "pdf":
            doc = pymupdf.open(stream=content, filetype="pdf")
            for page_idx in range(len(doc)):
                page = doc[page_idx]
                page_text = page.get_text("text")
                pairs = self.inspector.inspect_internal(page_text, page=page_idx + 1)
                findings_removed += len(pairs)

                for finding, raw_val in pairs:
                    rects = page.search_for(raw_val)
                    if not rects:
                        # Fallback search if formatted differently
                        rects = page.search_for(raw_val.strip())

                    for rect in rects:
                        if mode == "irreversible":
                            page.add_redact_annot(rect, fill=(0, 0, 0))
                        elif mode == "partial":
                            page.add_redact_annot(
                                rect,
                                text=finding.masked_preview,
                                fill=(0.92, 0.92, 0.92),
                                fontname="helv",
                                text_color=(0, 0, 0),
                            )
                        else:  # full or tokenize
                            lbl = f"[{finding.entity_type}]" if mode == "tokenize" else f"[REDACTED: {finding.entity_type}]"
                            page.add_redact_annot(
                                rect,
                                text=lbl,
                                fill=(0.88, 0.88, 0.88),
                                fontname="helv",
                                text_color=(0, 0, 0),
                            )
                page.apply_redactions()

            output_bytes = doc.tobytes(deflate=True, clean=True)
            doc.close()

            # Post-redaction verification scan
            verify_doc = pymupdf.open(stream=output_bytes, filetype="pdf")
            findings_remaining = 0
            for p_idx in range(len(verify_doc)):
                p = verify_doc[p_idx]
                rem = self.inspector.inspect(p.get_text("text"), page=p_idx + 1)
                findings_remaining += len(rem)
            verify_doc.close()

            verified = (findings_remaining == 0)
            return output_bytes, findings_removed, findings_remaining, verified

        elif fmt == "docx":
            doc = docx.Document(io.BytesIO(content))
            # Collect all paragraphs from body and tables
            all_paragraphs = list(doc.paragraphs)
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        all_paragraphs.extend(cell.paragraphs)

            for p in all_paragraphs:
                if not p.text:
                    continue
                redacted_p, count, _ = self.redactor.redact_text(p.text, mode=mode)
                if count > 0:
                    findings_removed += count
                    p.text = redacted_p

            buf = io.BytesIO()
            doc.save(buf)
            output_bytes = buf.getvalue()

            # Post-redaction verification scan
            verify_doc = docx.Document(io.BytesIO(output_bytes))
            re_extracted_parts: List[str] = []
            for p in verify_doc.paragraphs:
                if p.text:
                    re_extracted_parts.append(p.text)
            for table in verify_doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text:
                            re_extracted_parts.append(cell.text)
            re_text = "\n".join(re_extracted_parts)
            rem_findings = self.inspector.inspect(re_text)
            findings_remaining = len(rem_findings)
            verified = (findings_remaining == 0)

            return output_bytes, findings_removed, findings_remaining, verified

        else:  # txt
            text = content.decode("utf-8", errors="replace")
            redacted_text, findings_removed, _ = self.redactor.redact_text(text, mode=mode)
            output_bytes = redacted_text.encode("utf-8")

            # Post-redaction verification scan
            rem_findings = self.inspector.inspect(redacted_text)
            findings_remaining = len(rem_findings)
            verified = (findings_remaining == 0)

            return output_bytes, findings_removed, findings_remaining, verified


_DEFAULT_CHANNEL = DocumentChannel()


def scan_document(content: bytes, filename: str) -> Tuple[str, List[DLPFinding]]:
    """Scan document content using default DocumentChannel."""
    return _DEFAULT_CHANNEL.scan(content, filename)


def redact_document(
    content: bytes, filename: str, mode: str = "full"
) -> Tuple[bytes, int, int, bool]:
    """Redact document content using default DocumentChannel."""
    return _DEFAULT_CHANNEL.redact(content, filename, mode=mode)
