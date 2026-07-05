import random

import pytest

from src.corpus.legit_traffic import generate_round_traffic
from src.defender.promotion import (
    PromotionRejected,
    compute_fp_rate,
    promote_rule,
    retire_rule,
    rollback_rule,
    run_regression_check,
    stage_rule,
)
from src.wafsim.schema import (
    Action,
    AndStatement,
    ByteMatchStatement,
    FieldToMatch,
    FieldToMatchType,
    PositionalConstraint,
    Rule,
    Statement,
    VisibilityConfig,
    WebACL,
)
from src.wafsim.wcu import WCUBudgetExceeded


def legit_batch(n=60, seed=1):
    return generate_round_traffic(n, random.Random(seed))


def rule_matching_word(name: str, word: str, action: Action = Action.COUNT) -> Rule:
    return Rule(
        name=name,
        priority=1,
        statement=Statement(
            byte_match_statement=ByteMatchStatement(
                field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
                search_string=word,
                positional_constraint=PositionalConstraint.CONTAINS,
            )
        ),
        action=action,
        visibility_config=VisibilityConfig(metric_name=name),
    )


def test_stage_rule_forces_count_mode():
    acl = WebACL(name="acl", rules=[], max_capacity_wcu=250)
    staged = stage_rule(acl, rule_matching_word("candidate", "xyz", action=Action.BLOCK))
    assert staged.action == Action.COUNT
    assert acl.rules[0].action == Action.COUNT


def test_stage_rule_rejects_over_budget_and_does_not_mutate():
    acl = WebACL(name="acl", rules=[], max_capacity_wcu=0)
    with pytest.raises(WCUBudgetExceeded):
        stage_rule(acl, rule_matching_word("candidate", "xyz"))
    assert acl.rules == []


def test_promote_succeeds_when_fp_rate_zero():
    acl = WebACL(name="acl", rules=[], max_capacity_wcu=250)
    rule = stage_rule(acl, rule_matching_word("block-nonsense", "zzz_never_appears_zzz"))
    fp_rate = promote_rule(acl, rule.name, legit_batch(), threshold=0.01)
    assert fp_rate == 0.0
    assert acl.rules[0].action == Action.BLOCK


def test_promote_rejected_when_fp_rate_too_high_leaves_rule_in_count():
    acl = WebACL(name="acl", rules=[], max_capacity_wcu=250)
    # "the" appears constantly in ordinary search queries/comments -- guaranteed high FP bait.
    rule = stage_rule(acl, rule_matching_word("overbroad", "the"))
    with pytest.raises(PromotionRejected) as exc_info:
        promote_rule(acl, rule.name, legit_batch(), threshold=0.01)
    assert exc_info.value.fp_rate > 0.01
    assert acl.rules[0].action == Action.COUNT  # unchanged


def test_rollback_sets_action_back_to_count():
    acl = WebACL(name="acl", rules=[rule_matching_word("r1", "zzz", action=Action.BLOCK)])
    rollback_rule(acl, "r1")
    assert acl.rules[0].action == Action.COUNT


def test_retire_removes_rule():
    acl = WebACL(name="acl", rules=[rule_matching_word("r1", "zzz")])
    retire_rule(acl, "r1")
    assert acl.rules == []


def test_regression_check_auto_rolls_back_high_fp_promoted_rule():
    acl = WebACL(name="acl", rules=[rule_matching_word("overbroad", "the", action=Action.BLOCK)])
    rolled_back = run_regression_check(acl, legit_batch(), threshold=0.01)
    assert len(rolled_back) == 1
    assert rolled_back[0].rule_name == "overbroad"
    assert acl.rules[0].action == Action.COUNT


def test_regression_check_leaves_good_rule_promoted():
    acl = WebACL(name="acl", rules=[rule_matching_word("precise", "zzz_never_appears_zzz", action=Action.BLOCK)])
    rolled_back = run_regression_check(acl, legit_batch(), threshold=0.01)
    assert rolled_back == []
    assert acl.rules[0].action == Action.BLOCK


def test_compute_fp_rate_empty_corpus_is_zero():
    rule = rule_matching_word("r1", "anything")
    assert compute_fp_rate(rule, []) == 0.0
