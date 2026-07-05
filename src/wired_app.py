"""Wires the sample app + WAF middleware + seed WebACL together.

Used by manual/test verification now (M2), and later by the orchestrator
(M6) and dashboard (M7) so there's a single source of truth for how the
stack is assembled.
"""
from __future__ import annotations

from typing import Optional

from fastapi import FastAPI

from .sampleapp.app import create_app
from .wafsim.middleware import EvalHook, WAFEngineState, WAFMiddleware
from .wafsim.seed_acl import build_seed_web_acl


def build_wired_app(
    state: Optional[WAFEngineState] = None,
    on_evaluated: Optional[EvalHook] = None,
) -> tuple[FastAPI, WAFEngineState]:
    engine_state = state or WAFEngineState(web_acl=build_seed_web_acl())
    app = create_app()
    app.add_middleware(WAFMiddleware, state=engine_state, on_evaluated=on_evaluated)
    return app, engine_state
