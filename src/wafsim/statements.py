"""Predicate implementations for each WAFv2 statement type.

AWS's SQLi/XSS detection is proprietary ML-assisted pattern matching; we
approximate it with a documented, reasonable heuristic (common operator/
tag patterns) -- good enough to demonstrate encoding-based evasion and
detection-gap dynamics, which is the point of the sandbox.
"""
from __future__ import annotations

import re

from .ipset import IPSetStore, RegexPatternSetStore
from .rate_limit import SlidingWindowRateLimiter
from .schema import (
    AndStatement,
    ComparisonOperator,
    GeoMatchStatement,
    HttpRequest,
    IPSetReferenceStatement,
    LabelMatchScope,
    LabelMatchStatement,
    NotStatement,
    OrStatement,
    PositionalConstraint,
    RateBasedStatement,
    RegexPatternSetReferenceStatement,
    SizeConstraintStatement,
    Statement,
)
from .transformations import apply_transformations

_SQLI_PATTERNS = [
    re.compile(r"'\s*or\s*'?\d*'?\s*=\s*'?\d*", re.I),
    re.compile(r"\bunion\b\s+\bselect\b", re.I),
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"'\s*--"),  # classic comment-out bypass, e.g. admin'-- or ' OR 1=1--
    re.compile(r";\s*--"),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.I),
    re.compile(r"\bsleep\(\d+\)", re.I),
    re.compile(r"' *; *drop", re.I),
]

_XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.I),
    re.compile(r"onerror\s*=", re.I),
    re.compile(r"onload\s*=", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"<img[^>]+src", re.I),
    re.compile(r"<svg[^>]*>", re.I),
]


def looks_like_sqli(value: str) -> bool:
    return any(p.search(value) for p in _SQLI_PATTERNS)


def looks_like_xss(value: str) -> bool:
    return any(p.search(value) for p in _XSS_PATTERNS)


class EvalContext:
    """Everything a statement predicate might need, bundled so evaluator.py
    doesn't have to pass a growing argument list."""

    def __init__(
        self,
        request: HttpRequest,
        ip_sets: IPSetStore,
        regex_sets: RegexPatternSetStore,
        rate_limiter: SlidingWindowRateLimiter,
        labels_so_far: set[str] | None = None,
    ):
        self.request = request
        self.ip_sets = ip_sets
        self.regex_sets = regex_sets
        self.rate_limiter = rate_limiter
        self.labels_so_far = labels_so_far if labels_so_far is not None else set()


def _positional_match(value: str, search: str, constraint: PositionalConstraint) -> bool:
    if constraint == PositionalConstraint.EXACTLY:
        return value == search
    if constraint == PositionalConstraint.STARTS_WITH:
        return value.startswith(search)
    if constraint == PositionalConstraint.ENDS_WITH:
        return value.endswith(search)
    if constraint == PositionalConstraint.CONTAINS:
        return search in value
    if constraint == PositionalConstraint.CONTAINS_WORD:
        return re.search(rf"\b{re.escape(search)}\b", value) is not None
    raise ValueError(f"Unsupported positional constraint: {constraint}")


def _compare(actual: int, op: ComparisonOperator, expected: int) -> bool:
    return {
        ComparisonOperator.EQ: actual == expected,
        ComparisonOperator.NE: actual != expected,
        ComparisonOperator.LE: actual <= expected,
        ComparisonOperator.LT: actual < expected,
        ComparisonOperator.GE: actual >= expected,
        ComparisonOperator.GT: actual > expected,
    }[op]


def evaluate_statement(stmt: Statement, ctx: EvalContext, rule_name: str) -> bool:
    kind = stmt.kind

    if kind == "byte_match_statement":
        s = stmt.byte_match_statement
        value = apply_transformations(ctx.request.field_value(s.field_to_match), s.text_transformations)
        return _positional_match(value, s.search_string, s.positional_constraint)

    if kind == "sqli_match_statement":
        s = stmt.sqli_match_statement
        value = apply_transformations(ctx.request.field_value(s.field_to_match), s.text_transformations)
        return looks_like_sqli(value)

    if kind == "xss_match_statement":
        s = stmt.xss_match_statement
        value = apply_transformations(ctx.request.field_value(s.field_to_match), s.text_transformations)
        return looks_like_xss(value)

    if kind == "size_constraint_statement":
        s: SizeConstraintStatement = stmt.size_constraint_statement
        value = apply_transformations(ctx.request.field_value(s.field_to_match), s.text_transformations)
        return _compare(len(value), s.comparison_operator, s.size)

    if kind == "geo_match_statement":
        s: GeoMatchStatement = stmt.geo_match_statement
        return ctx.request.country in s.country_codes

    if kind == "ip_set_reference_statement":
        s: IPSetReferenceStatement = stmt.ip_set_reference_statement
        return ctx.ip_sets.contains(s.ip_set_id, ctx.request.client_ip)

    if kind == "regex_pattern_set_reference_statement":
        s: RegexPatternSetReferenceStatement = stmt.regex_pattern_set_reference_statement
        value = apply_transformations(ctx.request.field_value(s.field_to_match), s.text_transformations)
        return ctx.regex_sets.matches(s.regex_set_id, value)

    if kind == "label_match_statement":
        s: LabelMatchStatement = stmt.label_match_statement
        if s.scope == LabelMatchScope.LABEL:
            return s.key in ctx.labels_so_far
        return any(label.startswith(s.key) for label in ctx.labels_so_far)

    if kind == "rate_based_statement":
        s: RateBasedStatement = stmt.rate_based_statement
        if s.scope_down_statement is not None and not evaluate_statement(
            s.scope_down_statement, ctx, rule_name
        ):
            return False
        return ctx.rate_limiter.record_and_check(
            rule_name, ctx.request.client_ip, s.limit, s.evaluation_window_sec
        )

    if kind == "and_statement":
        s: AndStatement = stmt.and_statement
        return all(evaluate_statement(child, ctx, rule_name) for child in s.statements)

    if kind == "or_statement":
        s: OrStatement = stmt.or_statement
        return any(evaluate_statement(child, ctx, rule_name) for child in s.statements)

    if kind == "not_statement":
        s: NotStatement = stmt.not_statement
        return not evaluate_statement(s.statement, ctx, rule_name)

    raise ValueError(f"Unhandled statement kind: {kind}")
