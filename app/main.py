"""
app/main.py
────────────
PRIVAGUARD AI — Unified Enterprise Privacy Firewall Entry Point
────────────────────────────────────────────────────────────────
Directly mounts the complete Member 1 Backend (Privacy Engine, Consent Manager,
DPDP Rights, Document Gateway), Member 3 Security Intelligence, and Member 2
LLM Orchestrator into one cohesive, robust service.
"""

from __future__ import annotations

import sys
import os
from pathlib import Path

# Ensure paths
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
PRIVAGUARD_DIR = ROOT_DIR / "PRIVAGUARD_AI"
PRIVAGUARD_BACKEND = PRIVAGUARD_DIR / "backend"

for path_str in [str(APP_DIR), str(ROOT_DIR), str(PRIVAGUARD_DIR), str(PRIVAGUARD_BACKEND)]:
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

from PRIVAGUARD_AI.backend.main import app

# Ensure DLP routes are mounted
try:
    from app.api.dlp_routes import router as dlp_router
    if not any(getattr(r, "path", None) == "/api/v1/dlp/scan" for r in getattr(app, "routes", [])):
        app.include_router(dlp_router)
    from app.api.email_dlp_routes import router as email_dlp_router
    if not any(getattr(r, "path", None) == "/api/v1/dlp/email/scan" for r in getattr(app, "routes", [])):
        app.include_router(email_dlp_router)
except Exception as e:
    pass

__all__ = ["app"]
