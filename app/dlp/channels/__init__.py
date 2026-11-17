"""
app/dlp/channels
────────────────
DLP channels for inspecting and redacting across different data surfaces.
"""

from app.dlp.channels.document_channel import (
    DocumentChannel,
    detect_format,
    scan_document,
    redact_document,
)

__all__ = [
    "DocumentChannel",
    "detect_format",
    "scan_document",
    "redact_document",
]
