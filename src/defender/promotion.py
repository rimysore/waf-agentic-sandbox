"""Rule lifecycle: stage (COUNT) -> promote (BLOCK) -> rollback (back to
COUNT) or retire (removed). Guardrails are enforced here in code, not
trusted to the defender agent: staging rejects over-budget rules, promotion
rejects rules whose false-positive rate against the legit corpus exceeds
the configured threshold, and the orchestrator's regression check can
demote any already-promoted rule the same way.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.wafsim.ipset import IPSetStore, RegexPatternSetStore
from src.wafsim.rate_limit import SlidingWindowRateLimiter
from src.wafsim.schema import Action, HttpRequest, Rule, WebACL
from src.wafsim.statements import EvalContext, evaluate_statement
from src.wafsim.wcu import validate_budget


class PromotionRejected(Exception):
    def __init__(self, rule_name: str, fp_rate: float, threshold: float):
        super().__init__(
            f"Promotion of '{rule_name}' rejected: FP rate {fp_rate:.2%} exceeds threshold {threshold:.2%}"
        )
        self.rule_name = rule_name
        self.fp_rate = fp_rate
        self.threshold = threshold


def compute_fp_rate(
    rule: Rule,
    legit_requests: list[HttpRequest],
    ip_sets: IPSetStore | None = None,
    regex_sets: RegexPatternSetStore | None = None,
) -> float:
    """Fraction of legit_requests this rule's statement alone would match,
    evaluated in isolation (a fresh rate limiter every call, so this never
    pollutes/reads real production rate-limit state)."""
    if not legit_requests:
        return 0.0
    ip_sets = ip_sets or IPSetStore()
    regex_sets = regex_sets or RegexPatternSetStore()
    rate_limiter = SlidingWindowRateLimiter()
    matches = 0
    for req in legit_requests:
        ctx = EvalContext(request=req, ip_sets=ip_sets, regex_sets=regex_sets, rate_limiter=rate_limiter)
        if evaluate_statement(rule.statement, ctx, rule.name):
            matches += 1
    return matches / len(legit_requests)


def find_rule(web_acl: WebACL, rule_name: str) -> Rule:
    for r in web_acl.rules:
        if r.name == rule_name:
            return r
    raise KeyError(f"No such rule: {rule_name}")


def stage_rule(web_acl: WebACL, rule: Rule) -> Rule:
    """Adds a rule in COUNT mode regardless of the action it was authored
    with, and validates the WCU budget with it included -- raises
    WCUBudgetExceeded (leaving web_acl unmodified) if that would blow the
    budget."""
    staged = rule.model_copy(update={"action": Action.COUNT})
    trial_acl = web_acl.model_copy(update={"rules": [*web_acl.rules, staged]})
    validate_budget(trial_acl)  # raises without mutating web_acl if over budget
    web_acl.rules.append(staged)
    return staged


def promote_rule(
    web_acl: WebACL,
    rule_name: str,
    legit_requests: list[HttpRequest],
    threshold: float,
    ip_sets: IPSetStore | None = None,
    regex_sets: RegexPatternSetStore | None = None,
) -> float:
    rule = find_rule(web_acl, rule_name)
    fp_rate = compute_fp_rate(rule, legit_requests, ip_sets, regex_sets)
    if fp_rate > threshold:
        raise PromotionRejected(rule_name, fp_rate, threshold)
    rule.action = Action.BLOCK
    return fp_rate


def rollback_rule(web_acl: WebACL, rule_name: str) -> None:
    find_rule(web_acl, rule_name).action = Action.COUNT


def retire_rule(web_acl: WebACL, rule_name: str) -> None:
    find_rule(web_acl, rule_name)  # raises KeyError if missing
    web_acl.rules = [r for r in web_acl.rules if r.name != rule_name]


@dataclass
class RegressionResult:
    rule_name: str
    fp_rate: float


def run_regression_check(
    web_acl: WebACL,
    legit_requests: list[HttpRequest],
    threshold: float,
    ip_sets: IPSetStore | None = None,
    regex_sets: RegexPatternSetStore | None = None,
) -> list[RegressionResult]:
    """Auto-rollback (to COUNT) any currently-BLOCK rule whose FP rate
    against this round's legit traffic exceeds the threshold -- a safety
    net that runs regardless of whether the defender agent notices."""
    rolled_back = []
    for rule in web_acl.rules:
        if rule.action != Action.BLOCK:
            continue
        fp_rate = compute_fp_rate(rule, legit_requests, ip_sets, regex_sets)
        if fp_rate > threshold:
            rule.action = Action.COUNT
            rolled_back.append(RegressionResult(rule.name, fp_rate))
    return rolled_back
