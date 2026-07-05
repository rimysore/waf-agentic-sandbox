"""Vercel entrypoint: read-only dashboard over the bundled golden run."""
from __future__ import annotations

import os
from pathlib import Path

from src.dashboard.server import create_dashboard_app

ROOT = Path(__file__).resolve().parent
DB_PATH = os.environ.get("RUN_DB_PATH", str(ROOT / "data" / "golden_run.db"))

app = create_dashboard_app(DB_PATH)
