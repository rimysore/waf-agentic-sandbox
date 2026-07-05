"""Priority-ordered WebACL evaluation, matching AWS WAFv2 semantics:

- Rules run in ascending Priority order.
- The first rule that matches AND has a terminating action (BLOCK/ALLOW)
  stops evaluation ("short-circuit"); COUNT never terminates.
- Labels added by a matching rule (regardless of its action) become
  visible to statements evaluated later in the *same* pass, enabling
  LabelMatchStatement-based rule chaining -- same as real AWS.
- If no rule terminates, the WebACL's DefaultAction applies.
- Only rules that actually matched get a metric/log entry, mirroring
  AWS CloudWatch's per-rule metrics (non-matching rules produce nothing).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ipset import IPSetStore, RegexPatternSetStore
from .rate_limit import SlidingWindowRateLimiter
from .schema import Action, HttpRequest, Rule, WebACL
from .statements import EvalContext, evaluate_statement

DEFAULT_ACTION_RULE_ID = "Default_Action"


@dataclass
class RuleHit:
    rule_name: str
    action: Action
    terminating: bool


@dataclass
class EvaluationResult:
    action: Action
    terminating_rule_id: str
    terminating_rule_type: str | None  # "REGULAR", "RATE_BASED", or None for default action
    labels: list[str] = field(default_factory=list)
    rule_hits: list[RuleHit] = field(default_factory=list)


def evaluate(
    web_acl: WebACL,
    request: HttpRequest,
    ip_sets: IPSetStore | None = None,
    regex_sets: RegexPatternSetStore | None = None,
    rate_limiter: SlidingWindowRateLimiter | None = None,
) -> EvaluationResult:
    ctx = EvalContext(
        request=request,
        ip_sets=ip_sets or IPSetStore(),
        regex_sets=regex_sets or RegexPatternSetStore(),
        rate_limiter=rate_limiter or SlidingWindowRateLimiter(),
    )

    hits: list[RuleHit] = []
    labels: list[str] = []

    for rule in web_acl.sorted_rules():
        if not evaluate_statement(rule.statement, ctx, rule.name):
            continue

        for lbl in rule.rule_labels:
            if lbl not in ctx.labels_so_far:
                ctx.labels_so_far.add(lbl)
                labels.append(lbl)

        terminating = rule.action in (Action.BLOCK, Action.ALLOW)
        hits.append(RuleHit(rule_name=rule.name, action=rule.action, terminating=terminating))

        if terminating:
            rule_type = "RATE_BASED" if rule.statement.kind == "rate_based_statement" else "REGULAR"
            return EvaluationResult(
                action=rule.action,
                terminating_rule_id=rule.name,
                terminating_rule_type=rule_type,
                labels=labels,
                rule_hits=hits,
            )

    return EvaluationResult(
        action=web_acl.default_action,
        terminating_rule_id=DEFAULT_ACTION_RULE_ID,
        terminating_rule_type=None,
        labels=labels,
        rule_hits=hits,
    )
