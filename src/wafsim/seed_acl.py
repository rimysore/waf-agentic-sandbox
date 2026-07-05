"""The starting WebACL for a demo run.

Deliberately imperfect (not empty), so the attacker/defender loop has a
legible arc instead of hoping one emerges from nothing:

- generic-sqli-basic / generic-xss-basic: match on QUERY_STRING and BODY,
  but with TextTransformations=[NONE] -- missing URL_DECODE. A URL-encoded
  payload sails through untouched. The defender's fix (round 1's hero
  moment) is adding URL_DECODE to the transformation list.
- No RateBasedStatement at all: credential-stuffing/burst detection has to
  be authored by the defender from scratch, purely from observed metrics --
  the genuinely emergent part of the demo.
"""
from __future__ import annotations

from .schema import (
    Action,
    FieldToMatch,
    FieldToMatchType,
    OrStatement,
    Rule,
    SqliMatchStatement,
    Statement,
    TextTransformation,
    VisibilityConfig,
    WebACL,
    XssMatchStatement,
)


def _sqli_or_query_and_body() -> Statement:
    return Statement(
        or_statement=OrStatement(
            statements=[
                Statement(
                    sqli_match_statement=SqliMatchStatement(
                        field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
                        text_transformations=[TextTransformation.NONE],
                    )
                ),
                Statement(
                    sqli_match_statement=SqliMatchStatement(
                        field_to_match=FieldToMatch(type=FieldToMatchType.BODY),
                        text_transformations=[TextTransformation.NONE],
                    )
                ),
            ]
        )
    )


def _xss_or_query_and_body() -> Statement:
    return Statement(
        or_statement=OrStatement(
            statements=[
                Statement(
                    xss_match_statement=XssMatchStatement(
                        field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
                        text_transformations=[TextTransformation.NONE],
                    )
                ),
                Statement(
                    xss_match_statement=XssMatchStatement(
                        field_to_match=FieldToMatch(type=FieldToMatchType.BODY),
                        text_transformations=[TextTransformation.NONE],
                    )
                ),
            ]
        )
    )


def build_seed_web_acl(max_capacity_wcu: int = 250) -> WebACL:
    return WebACL(
        name="demo-web-acl",
        default_action=Action.ALLOW,
        max_capacity_wcu=max_capacity_wcu,
        rules=[
            Rule(
                name="generic-sqli-basic",
                priority=10,
                statement=_sqli_or_query_and_body(),
                action=Action.BLOCK,
                rule_labels=["seed:sqli-basic"],
                visibility_config=VisibilityConfig(metric_name="genericSqliBasic"),
            ),
            Rule(
                name="generic-xss-basic",
                priority=20,
                statement=_xss_or_query_and_body(),
                action=Action.BLOCK,
                rule_labels=["seed:xss-basic"],
                visibility_config=VisibilityConfig(metric_name="genericXssBasic"),
            ),
        ],
    )
