from src.orchestrator.persistence import RunStore
from src.wafsim.seed_acl import build_seed_web_acl


def test_round_trip_round_lifecycle(tmp_path):
    store = RunStore(str(tmp_path / "run.db"))
    store.start_round(1)
    store.save_web_acl_snapshot(1, build_seed_web_acl())
    store.record_rule_change(1, "staged", "new-rate-rule", {"limit": 20}, "credential stuffing observed")
    store.record_sampled_logs_batch(1, [{"action": "BLOCK", "terminatingRuleId": "x"}])
    store.record_metrics(1, {"rule-a": {"ALLOWED": 3, "BLOCKED": 1, "COUNTED": 0}})
    store.save_attacker_memory(1, {"success_rate": 0.5})
    store.save_defender_memory(1, {"notes": "staged a rate rule"})
    store.end_round(1, attack_success_rate=0.5, fp_rate=0.0, wcu_used=6)
    store.close()

    store2 = RunStore(str(tmp_path / "run.db"))
    rounds = store2.fetch_rounds()
    assert len(rounds) == 1
    assert rounds[0]["attack_success_rate"] == 0.5
    assert rounds[0]["wcu_used"] == 6

    changes = store2.fetch_rule_changes()
    assert len(changes) == 1
    assert changes[0]["event_type"] == "staged"
    assert changes[0]["rule_name"] == "new-rate-rule"

    metrics = store2.fetch_metrics()
    assert metrics == [{"round_num": 1, "rule_name": "rule-a", "allowed": 3, "blocked": 1, "counted": 0}]

    logs = store2.fetch_sampled_logs(1)
    assert logs == [{"action": "BLOCK", "terminatingRuleId": "x"}]

    snapshot = store2.fetch_web_acl_snapshot(1)
    assert snapshot["name"] == "demo-web-acl"

    assert store2.fetch_attacker_memory(1) == {"success_rate": 0.5}
    assert store2.fetch_defender_memory(1) == {"notes": "staged a rate rule"}
    assert store2.max_round() == 1
    assert store2.fetch_web_acl_snapshot(99) is None
    assert store2.fetch_attacker_memory(99) is None

    store2.close()


def test_db_created_in_nested_directory(tmp_path):
    db_path = tmp_path / "nested" / "dir" / "run.db"
    store = RunStore(str(db_path))
    assert db_path.exists()
    store.close()
