import json
from pathlib import Path

from src.wafsim.evaluator import evaluate
from src.wafsim.logging_format import build_sampled_log
from src.wafsim.schema import (
    Action,
    HttpRequest,
    Rule,
    SqliMatchStatement,
    FieldToMatch,
    FieldToMatchType,
    Statement,
    VisibilityConfig,
    WebACL,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "aws_sample_log.json"


def test_sampled_log_matches_real_aws_shape_structurally():
    fixture = json.loads(FIXTURE_PATH.read_text())

    rule = Rule(
        name="block-sqli-01",
        priority=1,
        statement=Statement(
            sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING))
        ),
        action=Action.BLOCK,
        visibility_config=VisibilityConfig(metric_name="sqli"),
    )
    acl = WebACL(name="demo-web-acl", rules=[rule])
    request = HttpRequest(
        client_ip="203.0.113.5", uri_path="/login", query_string="user=admin&pass=' OR 1=1--", headers={"host": "example.com"}
    )
    result = evaluate(acl, request)
    log = build_sampled_log("demo-web-acl", request, result)

    assert set(log.keys()) == set(fixture.keys())
    assert set(log["httpRequest"].keys()) == set(fixture["httpRequest"].keys())
    assert log["action"] == "BLOCK"
    assert log["terminatingRuleId"] == "block-sqli-01"
    assert log["terminatingRuleType"] == "REGULAR"


def test_sampled_log_default_action_has_no_rule_type():
    acl = WebACL(name="demo-web-acl", rules=[], default_action=Action.ALLOW)
    request = HttpRequest(client_ip="203.0.113.5", uri_path="/health")
    result = evaluate(acl, request)
    log = build_sampled_log("demo-web-acl", request, result)

    assert log["terminatingRuleId"] == "Default_Action"
    assert log["terminatingRuleType"] is None
    assert log["action"] == "ALLOW"


def test_non_terminating_count_rules_appear_in_log():
    from src.wafsim.schema import ByteMatchStatement, PositionalConstraint

    count_rule = Rule(
        name="count-admin-probe",
        priority=1,
        statement=Statement(
            byte_match_statement=ByteMatchStatement(
                field_to_match=FieldToMatch(type=FieldToMatchType.URI_PATH),
                search_string="/admin",
                positional_constraint=PositionalConstraint.STARTS_WITH,
            )
        ),
        action=Action.COUNT,
        visibility_config=VisibilityConfig(metric_name="count"),
    )
    acl = WebACL(name="demo-web-acl", rules=[count_rule], default_action=Action.ALLOW)
    request = HttpRequest(client_ip="203.0.113.5", uri_path="/admin/panel")
    result = evaluate(acl, request)
    log = build_sampled_log("demo-web-acl", request, result)

    assert log["nonTerminatingMatchingRules"] == [{"ruleId": "count-admin-probe", "action": "COUNT"}]
