from starlette.testclient import TestClient

from src.dashboard.server import create_dashboard_app
from src.orchestrator.persistence import RunStore
from src.wafsim.seed_acl import build_seed_web_acl


def make_populated_db(tmp_path) -> str:
    db_path = str(tmp_path / "run.db")
    store = RunStore(db_path)
    store.start_round(1)
    store.save_web_acl_snapshot(1, build_seed_web_acl())
    store.record_rule_change(1, "promoted", "generic-sqli-basic-fixed", {"fp_rate": 0.0}, "closed the URL_DECODE gap")
    store.record_sampled_logs_batch(1, [{"action": "BLOCK", "terminatingRuleId": "generic-sqli-basic",
                                          "httpRequest": {"clientIp": "203.0.113.9", "httpMethod": "GET", "uri": "/search"}}])
    store.record_metrics(1, {"generic-sqli-basic": {"ALLOWED": 0, "BLOCKED": 3, "COUNTED": 0}})
    store.save_attacker_memory(1, {"success_rate": 0.5, "next_round_hypothesis": "try encoding"})
    store.save_defender_memory(1, {"notes": "fixed the sqli gap"})
    store.end_round(1, attack_success_rate=0.5, fp_rate=0.0, wcu_used=6)
    store.close()
    return db_path


def test_index_page_served(tmp_path):
    db_path = make_populated_db(tmp_path)
    app = create_dashboard_app(db_path)
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "WAF Red-Team" in resp.text


def test_api_rounds_and_rule_changes(tmp_path):
    db_path = make_populated_db(tmp_path)
    client = TestClient(create_dashboard_app(db_path))

    rounds = client.get("/api/rounds").json()
    assert len(rounds) == 1
    assert rounds[0]["attack_success_rate"] == 0.5

    changes = client.get("/api/rule_changes").json()
    assert changes[0]["event_type"] == "promoted"


def test_api_metrics_sampled_logs_and_web_acl(tmp_path):
    db_path = make_populated_db(tmp_path)
    client = TestClient(create_dashboard_app(db_path))

    metrics = client.get("/api/metrics").json()
    assert metrics[0]["rule_name"] == "generic-sqli-basic"

    logs = client.get("/api/sampled_logs", params={"round": 1}).json()
    assert logs[0]["action"] == "BLOCK"

    acl = client.get("/api/web_acl", params={"round": 1}).json()
    assert acl["name"] == "demo-web-acl"

    missing_acl = client.get("/api/web_acl", params={"round": 99}).json()
    assert missing_acl == {}


def test_api_agent_memory(tmp_path):
    db_path = make_populated_db(tmp_path)
    client = TestClient(create_dashboard_app(db_path))

    am = client.get("/api/attacker_memory", params={"round": 1}).json()
    assert am["success_rate"] == 0.5

    dm = client.get("/api/defender_memory", params={"round": 1}).json()
    assert dm["notes"] == "fixed the sqli gap"


def test_missing_db_returns_404(tmp_path):
    client = TestClient(create_dashboard_app(str(tmp_path / "nonexistent.db")))
    resp = client.get("/api/rounds")
    assert resp.status_code == 404
