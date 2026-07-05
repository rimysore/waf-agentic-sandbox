import pytest

from src.wafsim.schema import (
    Action,
    AndStatement,
    ByteMatchStatement,
    FieldToMatch,
    FieldToMatchType,
    PositionalConstraint,
    RateBasedStatement,
    Rule,
    SizeConstraintStatement,
    SqliMatchStatement,
    Statement,
    TextTransformation,
    VisibilityConfig,
    WebACL,
)
from src.wafsim.wcu import WCUBudgetExceeded, rule_wcu, statement_wcu, validate_budget, web_acl_capacity


def vc(name):
    return VisibilityConfig(metric_name=name)


def test_byte_match_base_cost_is_one():
    stmt = Statement(
        byte_match_statement=ByteMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.URI_PATH),
            search_string="/admin",
            positional_constraint=PositionalConstraint.STARTS_WITH,
        )
    )
    assert statement_wcu(stmt) == 1


def test_extra_text_transformations_add_surcharge():
    stmt = Statement(
        byte_match_statement=ByteMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
            search_string="foo",
            positional_constraint=PositionalConstraint.CONTAINS,
            text_transformations=[TextTransformation.URL_DECODE, TextTransformation.LOWERCASE],
        )
    )
    assert statement_wcu(stmt) == 2  # 1 base + 1 surcharge for the second transformation


def test_rate_based_statement_costs_two_plus_scope_down():
    scope_down = Statement(
        sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING))
    )
    stmt = Statement(rate_based_statement=RateBasedStatement(limit=100, scope_down_statement=scope_down))
    assert statement_wcu(stmt) == 3  # 2 base + 1 for the scope-down SqliMatchStatement


def test_and_statement_sums_children_plus_one():
    child_a = Statement(
        size_constraint_statement=SizeConstraintStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.BODY),
            comparison_operator="GT",
            size=8192,
        )
    )
    child_b = Statement(
        sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.BODY))
    )
    stmt = Statement(and_statement=AndStatement(statements=[child_a, child_b]))
    assert statement_wcu(stmt) == 3  # 1 + 1 + 1


def test_web_acl_capacity_sums_all_rules():
    r1 = Rule(
        name="r1",
        priority=1,
        statement=Statement(
            byte_match_statement=ByteMatchStatement(
                field_to_match=FieldToMatch(type=FieldToMatchType.URI_PATH),
                search_string="/x",
                positional_constraint=PositionalConstraint.CONTAINS,
            )
        ),
        action=Action.BLOCK,
        visibility_config=vc("r1"),
    )
    r2 = Rule(
        name="r2",
        priority=2,
        statement=Statement(
            sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING))
        ),
        action=Action.BLOCK,
        visibility_config=vc("r2"),
    )
    acl = WebACL(name="acl", rules=[r1, r2])
    assert rule_wcu(r1) == 1
    assert rule_wcu(r2) == 1
    assert web_acl_capacity(acl) == 2


def test_validate_budget_raises_when_exceeded():
    rules = []
    for i in range(5):
        rules.append(
            Rule(
                name=f"r{i}",
                priority=i,
                statement=Statement(
                    and_statement=AndStatement(
                        statements=[
                            Statement(
                                sqli_match_statement=SqliMatchStatement(
                                    field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING)
                                )
                            )
                        ]
                        * 10
                    )
                ),
                action=Action.BLOCK,
                visibility_config=vc(f"r{i}"),
            )
        )
    acl = WebACL(name="acl", rules=rules, max_capacity_wcu=10)
    with pytest.raises(WCUBudgetExceeded):
        validate_budget(acl)
