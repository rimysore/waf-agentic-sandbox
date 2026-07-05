from src.wafsim.evaluator import evaluate
from src.wafsim.metrics import MetricsStore
from src.wafsim.schema import (
    Action,
    FieldToMatch,
    FieldToMatchType,
    HttpRequest,
    Rule,
    SqliMatchStatement,
    Statement,
    VisibilityConfig,
    WebACL,
)


def make_acl():
    rule = Rule(
        name="block-sqli",
        priority=1,
        statement=Statement(
            sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING))
        ),
        action=Action.BLOCK,
        visibility_config=VisibilityConfig(metric_name="sqli"),
    )
    return WebACL(name="test", rules=[rule], default_action=Action.ALLOW)


def test_metrics_record_blocked_and_allowed():
    acl = make_acl()
    metrics = MetricsStore()

    metrics.record(evaluate(acl, HttpRequest(client_ip="1.1.1.1", query_string="id=1' OR 1=1--")))
    metrics.record(evaluate(acl, HttpRequest(client_ip="1.1.1.1", query_string="id=5")))

    totals = metrics.totals()
    assert totals["block-sqli"]["BLOCKED"] == 1
    assert totals["Default_Action"]["ALLOWED"] == 1


def test_snapshot_and_reset_round_clears_round_but_keeps_totals():
    acl = make_acl()
    metrics = MetricsStore()
    metrics.record(evaluate(acl, HttpRequest(client_ip="1.1.1.1", query_string="id=1' OR 1=1--")))

    snap1 = metrics.snapshot_and_reset_round()
    assert snap1["block-sqli"]["BLOCKED"] == 1

    snap2 = metrics.snapshot_and_reset_round()
    assert snap2 == {}
    assert metrics.totals()["block-sqli"]["BLOCKED"] == 1  # totals persist across rounds


def test_non_matching_rule_produces_no_metric():
    acl = make_acl()
    metrics = MetricsStore()
    metrics.record(evaluate(acl, HttpRequest(client_ip="1.1.1.1", query_string="id=5")))
    assert "block-sqli" not in metrics.totals()
