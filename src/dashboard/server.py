"""Read-only dashboard over a run.db -- the same code path serves a live
run (poll while the orchestrator is writing) and a "golden run" replay
(static file, zero LLM/network dependency), since both are just SQLite."""
from __future__ import annotations

import argparse
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from src.orchestrator.persistence import RunStore

STATIC_DIR = Path(__file__).parent / "static"


def create_dashboard_app(db_path: str) -> FastAPI:
    app = FastAPI(title="waf-sandbox-dashboard")

    def _store() -> RunStore:
        if not Path(db_path).exists():
            raise HTTPException(status_code=404, detail=f"no such run database: {db_path}")
        return RunStore(db_path)

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/rounds")
    async def rounds():
        store = _store()
        data = store.fetch_rounds()
        store.close()
        return data

    @app.get("/api/rule_changes")
    async def rule_changes():
        store = _store()
        data = store.fetch_rule_changes()
        store.close()
        return data

    @app.get("/api/metrics")
    async def metrics():
        store = _store()
        data = store.fetch_metrics()
        store.close()
        return data

    @app.get("/api/sampled_logs")
    async def sampled_logs(round: int, limit: int = 50):
        store = _store()
        data = store.fetch_sampled_logs(round, limit)
        store.close()
        return data

    @app.get("/api/web_acl")
    async def web_acl(round: int):
        store = _store()
        data = store.fetch_web_acl_snapshot(round)
        store.close()
        return data or {}

    @app.get("/api/attacker_memory")
    async def attacker_memory(round: int):
        store = _store()
        data = store.fetch_attacker_memory(round)
        store.close()
        return data or {}

    @app.get("/api/defender_memory")
    async def defender_memory(round: int):
        store = _store()
        data = store.fetch_defender_memory(round)
        store.close()
        return data or {}

    return app


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="Run the WAF sandbox dashboard against a run.db")
    parser.add_argument("--db", default="data/run.db")
    parser.add_argument("--port", type=int, default=8050)
    # 0.0.0.0 so this is reachable via Docker's port mapping, not just from
    # inside the container's own network namespace.
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    app = create_dashboard_app(args.db)
    print(f"Dashboard serving {args.db} at http://127.0.0.1:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
