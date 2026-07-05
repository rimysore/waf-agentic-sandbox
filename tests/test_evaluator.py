from src.wafsim.evaluator import DEFAULT_ACTION_RULE_ID, evaluate
from src.wafsim.ipset import IPSetStore, RegexPatternSetStore
from src.wafsim.rate_limit import SlidingWindowRateLimiter
from src.wafsim.schema import (
    Action,
    ByteMatchStatement,
    FieldToMatch,
    FieldToMatchType,
    HttpRequest,
    IPSetReferenceStatement,
    LabelMatchScope,
    LabelMatchStatement,
    PositionalConstraint,
    RateBasedStatement,
    Rule,
    SqliMatchStatement,
    Statement,
    TextTransformation,
    VisibilityConfig,
    WebACL,
)


def make_request(**kwargs) -> HttpRequest:
    defaults = dict(client_ip="203.0.113.5", country="US", method="GET", uri_path="/", query_string="", body="")
    defaults.update(kwargs)
    return HttpRequest(**defaults)


def vc(name: str) -> VisibilityConfig:
    return VisibilityConfig(metric_name=name)


def test_default_allow_when_no_rule_matches():
    acl = WebACL(name="test", default_action=Action.ALLOW, rules=[])
    result = evaluate(acl, make_request())
    assert result.action == Action.ALLOW
    assert result.terminating_rule_id == DEFAULT_ACTION_RULE_ID


def test_sqli_blocked_without_transformation():
    stmt = Statement(
        sqli_match_statement=SqliMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
            text_transformations=[TextTransformation.NONE],
        )
    )
    rule = Rule(name="block-sqli", priority=1, statement=stmt, action=Action.BLOCK, visibility_config=vc("sqli"))
    acl = WebACL(name="test", rules=[rule])

    blocked = evaluate(acl, make_request(query_string="id=1' OR 1=1--"))
    assert blocked.action == Action.BLOCK
    assert blocked.terminating_rule_id == "block-sqli"


def test_url_encoded_sqli_bypasses_rule_missing_url_decode():
    stmt = Statement(
        sqli_match_statement=SqliMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
            text_transformations=[TextTransformation.NONE],
        )
    )
    rule = Rule(name="block-sqli", priority=1, statement=stmt, action=Action.BLOCK, visibility_config=vc("sqli"))
    acl = WebACL(name="test", rules=[rule])

    encoded_payload = "id=1%27%20OR%201%3D1%2D%2D"  # fully encoded, including the trailing "--"
    result = evaluate(acl, make_request(query_string=encoded_payload))
    assert result.action == Action.ALLOW  # bypass: rule never URL-decodes the value


def test_url_decode_transformation_catches_the_bypass():
    stmt = Statement(
        sqli_match_statement=SqliMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
            text_transformations=[TextTransformation.URL_DECODE],
        )
    )
    rule = Rule(name="block-sqli-fixed", priority=1, statement=stmt, action=Action.BLOCK, visibility_config=vc("sqli"))
    acl = WebACL(name="test", rules=[rule])

    encoded_payload = "id=1%27%20OR%201%3D1%2D%2D"
    result = evaluate(acl, make_request(query_string=encoded_payload))
    assert result.action == Action.BLOCK


def test_priority_ordering_and_short_circuit():
    allow_rule = Rule(
        name="allow-trusted-ip",
        priority=1,
        statement=Statement(ip_set_reference_statement=IPSetReferenceStatement(ip_set_id="trusted")),
        action=Action.ALLOW,
        visibility_config=vc("allow"),
    )
    block_rule = Rule(
        name="block-sqli",
        priority=2,
        statement=Statement(
            sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING))
        ),
        action=Action.BLOCK,
        visibility_config=vc("sqli"),
    )
    acl = WebACL(name="test", rules=[block_rule, allow_rule])  # intentionally out of priority order in the list

    ip_sets = IPSetStore()
    ip_sets.put("trusted", ["203.0.113.5/32"])

    result = evaluate(acl, make_request(client_ip="203.0.113.5", query_string="' OR 1=1--"), ip_sets=ip_sets)
    assert result.action == Action.ALLOW
    assert result.terminating_rule_id == "allow-trusted-ip"


def test_count_rule_does_not_terminate_and_adds_label():
    count_rule = Rule(
        name="count-suspicious",
        priority=1,
        statement=Statement(
            byte_match_statement=ByteMatchStatement(
                field_to_match=FieldToMatch(type=FieldToMatchType.URI_PATH),
                search_string="/admin",
                positional_constraint=PositionalConstraint.STARTS_WITH,
            )
        ),
        action=Action.COUNT,
        rule_labels=["suspect:admin-probe"],
        visibility_config=vc("count"),
    )
    label_block_rule = Rule(
        name="block-labeled",
        priority=2,
        statement=Statement(
            label_match_statement=LabelMatchStatement(scope=LabelMatchScope.LABEL, key="suspect:admin-probe")
        ),
        action=Action.BLOCK,
        visibility_config=vc("labelblock"),
    )
    acl = WebACL(name="test", rules=[count_rule, label_block_rule])

    result = evaluate(acl, make_request(uri_path="/admin/panel"))
    assert result.action == Action.BLOCK
    assert result.terminating_rule_id == "block-labeled"
    assert len(result.rule_hits) == 2
    assert result.rule_hits[0].terminating is False
    assert result.rule_hits[1].terminating is True


def test_rate_based_statement_blocks_after_limit_within_window():
    stmt = Statement(rate_based_statement=RateBasedStatement(limit=3, evaluation_window_sec=60))
    rule = Rule(name="rate-limit", priority=1, statement=stmt, action=Action.BLOCK, visibility_config=vc("rate"))
    acl = WebACL(name="test", rules=[rule])

    clock = {"t": 0.0}
    limiter = SlidingWindowRateLimiter(clock=lambda: clock["t"])

    results = []
    for i in range(5):
        clock["t"] = float(i)
        results.append(evaluate(acl, make_request(), rate_limiter=limiter).action)

    assert results[:3] == [Action.ALLOW, Action.ALLOW, Action.ALLOW]
    assert results[3] == Action.BLOCK
    assert results[4] == Action.BLOCK


def test_rate_based_statement_window_expires():
    stmt = Statement(rate_based_statement=RateBasedStatement(limit=2, evaluation_window_sec=10))
    rule = Rule(name="rate-limit", priority=1, statement=stmt, action=Action.BLOCK, visibility_config=vc("rate"))
    acl = WebACL(name="test", rules=[rule])

    clock = {"t": 0.0}
    limiter = SlidingWindowRateLimiter(clock=lambda: clock["t"])

    for t in (0.0, 1.0, 2.0):
        clock["t"] = t
        evaluate(acl, make_request(), rate_limiter=limiter)
    # by t=20 the earlier hits have fallen out of the 10s window
    clock["t"] = 20.0
    result = evaluate(acl, make_request(), rate_limiter=limiter)
    assert result.action == Action.ALLOW


def test_regex_set_reference():
    from src.wafsim.schema import RegexPatternSetReferenceStatement

    regex_sets = RegexPatternSetStore()
    regex_sets.put("bot-agents", [r"(?i)curl|sqlmap|nikto"])

    stmt = Statement(
        regex_pattern_set_reference_statement=RegexPatternSetReferenceStatement(
            regex_set_id="bot-agents",
            field_to_match=FieldToMatch(type=FieldToMatchType.SINGLE_HEADER, name="user-agent"),
        )
    )
    rule = Rule(name="block-scanner-ua", priority=1, statement=stmt, action=Action.BLOCK, visibility_config=vc("ua"))
    acl = WebACL(name="test", rules=[rule])

    result = evaluate(acl, make_request(headers={"user-agent": "sqlmap/1.6"}), regex_sets=regex_sets)
    assert result.action == Action.BLOCK
