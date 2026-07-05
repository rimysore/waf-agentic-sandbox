"""Manual verification entrypoint: `python -m src.dev_server` runs the wired
sample-app+WAF stack on port 8000 for hand-testing with curl."""
from __future__ import annotations

import os

import uvicorn

from src.wired_app import build_wired_app

app, _state = build_wired_app()

if __name__ == "__main__":
    # 0.0.0.0 by default so this is reachable via Docker's port mapping too;
    # harmless for plain local use (still only reachable on your machine).
    host = os.environ.get("DEV_SERVER_HOST", "0.0.0.0")
    uvicorn.run(app, host=host, port=8000, log_level="info")
