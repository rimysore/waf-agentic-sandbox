"""Web ACL Capacity Unit (WCU) accounting, using AWS's published per-statement
costs (see AWS WAF developer guide "WCU costs" -- values here are a snapshot
and should be re-checked against current AWS pricing docs before quoting them
as authoritative). A deliberately tight demo budget forces the defender agent
to consolidate/retire rules instead of freely stacking new ones.
"""
from __future__ import annotations

from .schema import Rule, SensitivityLevel, Statement, WebACL

_TEXT_TRANSFORM_STATEMENT_KINDS = {
    "byte_match_statement",
    "sqli_match_statement",
    "xss_match_statement",
    "size_constraint_statement",
    "regex_pattern_set_reference_statement",
}


class WCUBudgetExceeded(Exception):
    def __init__(self, used: int, budget: int):
        super().__init__(f"WebACL capacity {used} WCU exceeds budget of {budget} WCU")
        self.used = used
        self.budget = budget


def _transform_surcharge(stmt: Statement) -> int:
    inner = getattr(stmt, stmt.kind)
    transformations = getattr(inner, "text_transformations", None)
    if not transformations:
        return 0
    return max(0, len(transformations) - 1)


def statement_wcu(stmt: Statement) -> int:
    kind = stmt.kind

    if kind == "byte_match_statement":
        return 1 + _transform_surcharge(stmt)
    if kind == "sqli_match_statement":
        cost = 1 + _transform_surcharge(stmt)
        if stmt.sqli_match_statement.sensitivity_level == SensitivityLevel.HIGH:
            cost += 1
        return cost
    if kind == "xss_match_statement":
        return 1 + _transform_surcharge(stmt)
    if kind == "size_constraint_statement":
        return 1 + _transform_surcharge(stmt)
    if kind == "geo_match_statement":
        return 1
    if kind == "ip_set_reference_statement":
        return 1
    if kind == "regex_pattern_set_reference_statement":
        return 1 + _transform_surcharge(stmt)
    if kind == "label_match_statement":
        return 1
    if kind == "rate_based_statement":
        s = stmt.rate_based_statement
        cost = 2
        if s.scope_down_statement is not None:
            cost += statement_wcu(s.scope_down_statement)
        return cost
    if kind == "and_statement":
        return 1 + sum(statement_wcu(child) for child in stmt.and_statement.statements)
    if kind == "or_statement":
        return 1 + sum(statement_wcu(child) for child in stmt.or_statement.statements)
    if kind == "not_statement":
        return 1 + statement_wcu(stmt.not_statement.statement)

    raise ValueError(f"Unhandled statement kind for WCU costing: {kind}")


def rule_wcu(rule: Rule) -> int:
    return statement_wcu(rule.statement)


def web_acl_capacity(web_acl: WebACL) -> int:
    return sum(rule_wcu(r) for r in web_acl.rules)


def validate_budget(web_acl: WebACL) -> int:
    """Return the used capacity, raising WCUBudgetExceeded if over budget."""
    used = web_acl_capacity(web_acl)
    if used > web_acl.max_capacity_wcu:
        raise WCUBudgetExceeded(used, web_acl.max_capacity_wcu)
    return used
