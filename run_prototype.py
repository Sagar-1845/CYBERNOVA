"""
run_prototype.py
────────────────
PRIVAGUARD AI — Master Execution & Launcher Script
─────────────────────────────────────────────────
Launches the integrated PRIVAGUARD AI prototype:
1. Unified FastAPI Gateway Backend on port 8000
2. Cyber-Enclave React / Vite UI Prototype on port 3000

Usage:
    python run_prototype.py             # Launches both backend & frontend
    python run_prototype.py --backend   # Backend only
    python run_prototype.py --frontend  # Frontend only
"""

import os
import sys
import time
import subprocess
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

def check_python_executable():
    venv_py = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable

def main():
    args = sys.argv[1:]
    py_exec = check_python_executable()

    backend_only = "--backend" in args
    frontend_only = "--frontend" in args
    launch_both = not backend_only and not frontend_only

    banner = r"""
  ____  ____  _____     ___    ____ _   _    _    ____  ____      _    ___ 
 |  _ \|  _ \|_ _\ \   / / \  / ___| | | |  / \  |  _ \|  _ \    / \  |_ _|
 | |_) | |_) || | \ \ / / _ \| |  _| | | | / _ \ | |_) | | | |  / _ \  | | 
 |  __/|  _ < | |  \ V / ___ \ |_| | |_| |/ ___ \|  _ <| |_| | / ___ \ | | 
 |_|   |_| \_\___|  \_/_/   \_\____|\___//_/   \_\_| \_\____/ /_/   \_\___|
 ───────────────────────────────────────────────────────────────────────────
   INTELLIGENT PRIVACY FIREWALL FOR ENTERPRISE AI & INDIA DPDP ACT 2023
    """
    print(banner)

    processes = []

    # 1. Start Backend
    if launch_both or backend_only:
        print("[*] Launching PRIVAGUARD AI Backend (FastAPI on http://127.0.0.1:8000)...")
        backend_env = {
            **os.environ,
            "PYTHONPATH": f"{ROOT_DIR};{ROOT_DIR / 'PRIVAGUARD_AI'};{ROOT_DIR / 'PRIVAGUARD_AI' / 'backend'}",
            "ADMIN_API_TOKEN": os.getenv("ADMIN_API_TOKEN", "privaguard-admin-secret-2026"),
            "PYTHONIOENCODING": "utf-8",
        }
        backend_cmd = [
            py_exec, "-m", "uvicorn",
            "app.main:app",
            "--host", "127.0.0.1",
            "--port", "8000",
            "--reload",
        ]
        p_backend = subprocess.Popen(backend_cmd, env=backend_env)
        processes.append(p_backend)
        print("    -> FastAPI Swagger Docs:  http://127.0.0.1:8000/docs")
        print("    -> Statutory Health:      http://127.0.0.1:8000/health")
        time.sleep(1.5)

    # 2. Start Frontend
    if launch_both or frontend_only:
        print("[*] Launching PRIVAGUARD AI Frontend UI Prototype (Vite on http://localhost:3000)...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        p_frontend = subprocess.Popen([npm_cmd, "run", "dev"])
        processes.append(p_frontend)
        print("    -> Web UI Hub:            http://localhost:3000")
        print("    -> DPDP Rights & Consent: http://localhost:3000/#/consent")
        print("    -> Multilingual Indic:    http://localhost:3000/#/demo")

    print("\n" + "=" * 75)
    print("  PRIVAGUARD AI Prototype is running!")
    print("  Press Ctrl+C to terminate all services.")
    print("=" * 75 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping PRIVAGUARD AI services...")
        for p in processes:
            p.terminate()
        print("[✓] All services stopped cleanly.")

if __name__ == "__main__":
    main()
