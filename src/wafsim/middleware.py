"""ASGI middleware that puts the WAF engine in front of an app, the same
role AWS WAF plays sitting in front of an ALB/CloudFront/API Gateway."""
from __future__ import annotations

from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from .evaluator import EvaluationResult, evaluate
from .ipset import IPSetStore, RegexPatternSetStore
from .rate_limit import SlidingWindowRateLimiter
from .schema import Action, HttpRequest, WebACL

EvalHook = Callable[[HttpRequest, EvaluationResult], None]


class WAFEngineState:
    """Mutable state shared between the middleware and whatever controls the
    WAF (defender agent, orchestrator, manual test code). ``web_acl`` is
    swapped out in place as rules are staged/promoted/rolled back -- the
    middleware always evaluates against whatever is currently set here."""

    def __init__(
        self,
        web_acl: WebACL,
        ip_sets: Optional[IPSetStore] = None,
        regex_sets: Optional[RegexPatternSetStore] = None,
        rate_limiter: Optional[SlidingWindowRateLimiter] = None,
    ):
        self.web_acl = web_acl
        self.ip_sets = ip_sets or IPSetStore()
        self.regex_sets = regex_sets or RegexPatternSetStore()
        self.rate_limiter = rate_limiter or SlidingWindowRateLimiter()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    demo_override = request.headers.get("x-demo-source-ip")
    if demo_override:
        return demo_override
    if request.client:
        return request.client.host
    return "0.0.0.0"


class WAFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, state: WAFEngineState, on_evaluated: Optional[EvalHook] = None):
        super().__init__(app)
        self.state = state
        self.on_evaluated = on_evaluated

    async def dispatch(self, request: Request, call_next) -> Response:
        body_bytes = await request.body()
        waf_request = HttpRequest(
            client_ip=_client_ip(request),
            country=request.headers.get("x-demo-country", "US"),
            method=request.method,
            uri_path=request.url.path,
            query_string=request.url.query or "",
            body=body_bytes.decode("utf-8", errors="ignore"),
            headers={k.lower(): v for k, v in request.headers.items()},
        )

        result = evaluate(
            self.state.web_acl,
            waf_request,
            ip_sets=self.state.ip_sets,
            regex_sets=self.state.regex_sets,
            rate_limiter=self.state.rate_limiter,
        )

        if self.on_evaluated:
            self.on_evaluated(waf_request, result)

        if result.action == Action.BLOCK:
            return PlainTextResponse(
                "Forbidden",
                status_code=403,
                headers={"x-waf-rule": result.terminating_rule_id},
            )

        response = await call_next(request)
        response.headers["x-waf-rule"] = result.terminating_rule_id
        return response
