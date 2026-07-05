from starlette.testclient import TestClient

from src.wafsim.middleware import WAFEngineState
from src.wafsim.rate_limit import SlidingWindowRateLimiter
from src.wafsim.schema import Action, RateBasedStatement, Rule, Statement, VisibilityConfig
from src.wafsim.seed_acl import build_seed_web_acl
from src.wired_app import build_wired_app


def make_client(state: WAFEngineState | None = None) -> TestClient:
    app, engine_state = build_wired_app(state=state)
    client = TestClient(app)
    client.engine_state = engine_state  # stash for test access
    return client


def test_health_check_passes_through():
    client = make_client()
    resp = client.get("/health")
    assert resp.status_code == 200


def test_plain_login_attempt_allowed_through_waf():
    client = make_client()
    resp = client.post("/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401  # reached the app; WAF didn't block it
    assert resp.headers["x-waf-rule"] == "Default_Action"


def test_raw_sqli_in_json_body_blocked_by_seed_rule():
    # JSON bodies preserve special characters literally, unlike a GET query
    # string which any real HTTP client percent-encodes -- see the encoded
    # bypass test below for why that distinction matters.
    client = make_client()
    resp = client.post("/comments", json={"comment": "' OR 1=1--"})
    assert resp.status_code == 403
    assert resp.headers["x-waf-rule"] == "generic-sqli-basic"


def test_url_encoded_sqli_bypasses_seed_rule_and_exploits_login():
    client = make_client()
    # Seed rule has TextTransformations=[NONE] -- no URL_DECODE -- so an encoded
    # tautology payload sails through the WAF and reaches the vulnerable app.
    resp = client.post(
        "/login",
        content="username=admin%27--&password=x",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert resp.headers["x-waf-rule"] == "Default_Action"  # not blocked
    assert resp.status_code == 200
    assert resp.json()["via"] == "sqli-bypass"  # and the app got exploited


def test_raw_xss_in_json_body_blocked_by_seed_rule():
    # JSON bodies preserve special characters literally (only quotes/backslashes
    # are JSON-escaped), unlike GET query strings which any real HTTP client
    # percent-encodes -- so this is the realistic "raw payload" case for XSS.
    client = make_client()
    resp = client.post("/comments", json={"comment": "<script>alert(1)</script>"})
    assert resp.status_code == 403
    assert resp.headers["x-waf-rule"] == "generic-xss-basic"


def test_url_encoded_xss_in_query_bypasses_seed_rule():
    # A GET query string is always percent-encoded on the wire, so this is
    # the same "missing URL_DECODE" gap as SQLi, on a different endpoint.
    client = make_client()
    resp = client.get("/search", params={"q": "<script>alert(1)</script>"})
    assert resp.status_code == 200  # bypasses the WAF entirely
    assert resp.headers["x-waf-rule"] == "Default_Action"
    assert "<script>alert(1)</script>" in resp.text  # and the app reflects it unescaped


def test_no_rate_limiting_present_in_seed_acl_so_bursts_pass():
    client = make_client()
    statuses = [client.post("/login", json={"username": "alice", "password": "wrong"}).status_code for _ in range(10)]
    assert all(s == 401 for s in statuses)  # no rate-based rule yet -- all reach the app


def test_defender_added_rate_rule_blocks_bursts():
    acl = build_seed_web_acl()
    acl.rules.append(
        Rule(
            name="rate-limit-login",
            priority=5,
            statement=Statement(rate_based_statement=RateBasedStatement(limit=3, evaluation_window_sec=60)),
            action=Action.BLOCK,
            visibility_config=VisibilityConfig(metric_name="rateLimitLogin"),
        )
    )
    clock = {"t": 0.0}
    state = WAFEngineState(web_acl=acl, rate_limiter=SlidingWindowRateLimiter(clock=lambda: clock["t"]))
    client = make_client(state=state)

    statuses = []
    for i in range(6):
        clock["t"] = float(i)
        statuses.append(client.post("/login", json={"username": "alice", "password": "wrong"}).status_code)

    assert statuses[:3] == [401, 401, 401]
    assert statuses[3:] == [403, 403, 403]
