"""A small, deliberately naive web app for attacks to land on.

Not a real production pattern -- it exists purely as a target with
measurable "exploited" outcomes distinct from "the WAF didn't block me":
- /login: a classic tautology-based SQL-injection auth bypass.
- /search, /comments: reflected/stored content with no output escaping,
  so a payload that reaches the app "succeeds" as XSS.

This module has zero awareness of the WAF -- it's wrapped by
src.wafsim.middleware.WAFMiddleware externally (see src/wired_app.py).
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

_FAKE_USERS = {"admin": "correct-horse-battery-staple", "alice": "hunter2"}

_TAUTOLOGY_MARKERS = [
    "' or '1'='1",
    "' or 1=1",
    "'or'1'='1",
    "admin'--",
    "admin' --",
    "' or 'a'='a",
]

_COMMENTS: list[str] = []


def _looks_like_tautology_bypass(username: str) -> bool:
    lowered = username.lower()
    return any(marker in lowered for marker in _TAUTOLOGY_MARKERS)


async def _extract_fields(request: Request, keys: list[str]) -> dict[str, str]:
    """Best-effort field extraction across JSON body, form body, or query
    params -- attack payloads won't always be well-formed for one shape."""
    values: dict[str, str] = {}
    content_type = request.headers.get("content-type", "")
    body_bytes = await request.body()

    if "application/json" in content_type and body_bytes:
        import json

        try:
            data = json.loads(body_bytes)
            for k in keys:
                if k in data:
                    values[k] = str(data[k])
        except Exception:
            pass
    elif body_bytes:
        try:
            form = dict(x.split("=", 1) for x in body_bytes.decode("utf-8", "ignore").split("&") if "=" in x)
            import urllib.parse

            for k in keys:
                if k in form:
                    values[k] = urllib.parse.unquote_plus(form[k])
        except Exception:
            pass

    for k in keys:
        if k not in values and k in request.query_params:
            values[k] = request.query_params[k]

    return values


def create_app() -> FastAPI:
    app = FastAPI(title="sampleapp")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/login")
    async def login(request: Request):
        fields = await _extract_fields(request, ["username", "password"])
        username = fields.get("username", "")
        password = fields.get("password", "")

        if _looks_like_tautology_bypass(username):
            return JSONResponse(
                {"status": "authenticated", "user": "admin", "via": "sqli-bypass"}, status_code=200
            )

        expected = _FAKE_USERS.get(username)
        if expected is not None and expected == password:
            return JSONResponse({"status": "authenticated", "user": username}, status_code=200)

        return JSONResponse({"status": "invalid credentials"}, status_code=401)

    @app.get("/search", response_class=HTMLResponse)
    async def search(q: str = ""):
        # Intentionally unescaped -- models a naive app with no output encoding.
        return f"<html><body><h1>Results for: {q}</h1><p>No results found.</p></body></html>"

    @app.post("/comments")
    async def post_comment(request: Request):
        fields = await _extract_fields(request, ["comment"])
        text = fields.get("comment", "")
        _COMMENTS.append(text)
        return {"status": "posted", "count": len(_COMMENTS)}

    @app.get("/comments", response_class=HTMLResponse)
    async def list_comments():
        items = "".join(f"<li>{c}</li>" for c in _COMMENTS)
        return f"<html><body><ul>{items}</ul></body></html>"

    @app.get("/comments/reset")
    async def reset_comments():
        _COMMENTS.clear()
        return {"status": "cleared"}

    return app
