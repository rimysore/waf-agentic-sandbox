"""Translates our internal WebACL/Rule schema into real AWS WAFv2 API JSON
(PascalCase, boto3 wafv2 client shapes) and optionally calls update_web_acl.

Defaults to dry-run: prints the exact kwargs that *would* be sent to
`wafv2.update_web_acl` and returns them, without importing boto3 or touching
any credentials. Pass live=True with an explicit AWS profile to actually
deploy -- this is the only place in the project that touches real AWS.
"""
from __future__ import annotations

import json

from src.wafsim.schema import (
    Action,
    FieldToMatch,
    FieldToMatchType,
    Rule,
    Statement,
    WebACL,
)

_FIELD_TO_MATCH_MAP = {
    FieldToMatchType.URI_PATH: lambda f: {"UriPath": {}},
    FieldToMatchType.QUERY_STRING: lambda f: {"QueryString": {}},
    FieldToMatchType.BODY: lambda f: {"Body": {"OversizeHandling": "CONTINUE"}},
    FieldToMatchType.METHOD: lambda f: {"Method": {}},
    FieldToMatchType.ALL_QUERY_ARGUMENTS: lambda f: {"AllQueryArguments": {}},
    FieldToMatchType.SINGLE_HEADER: lambda f: {"SingleHeader": {"Name": f.name}},
}

_ACTION_MAP = {
    Action.BLOCK: {"Block": {}},
    Action.ALLOW: {"Allow": {}},
    Action.COUNT: {"Count": {}},
}


def to_aws_field_to_match(field: FieldToMatch) -> dict:
    return _FIELD_TO_MATCH_MAP[field.type](field)


def to_aws_text_transformations(transformations: list) -> list[dict]:
    return [{"Priority": i, "Type": t.value} for i, t in enumerate(transformations)]


def to_aws_statement(stmt: Statement) -> dict:
    kind = stmt.kind

    if kind == "byte_match_statement":
        s = stmt.byte_match_statement
        return {
            "ByteMatchStatement": {
                "SearchString": s.search_string,
                "FieldToMatch": to_aws_field_to_match(s.field_to_match),
                "TextTransformations": to_aws_text_transformations(s.text_transformations),
                "PositionalConstraint": s.positional_constraint.value,
            }
        }
    if kind == "sqli_match_statement":
        s = stmt.sqli_match_statement
        return {
            "SqliMatchStatement": {
                "FieldToMatch": to_aws_field_to_match(s.field_to_match),
                "TextTransformations": to_aws_text_transformations(s.text_transformations),
                "SensitivityLevel": s.sensitivity_level.value,
            }
        }
    if kind == "xss_match_statement":
        s = stmt.xss_match_statement
        return {
            "XssMatchStatement": {
                "FieldToMatch": to_aws_field_to_match(s.field_to_match),
                "TextTransformations": to_aws_text_transformations(s.text_transformations),
            }
        }
    if kind == "size_constraint_statement":
        s = stmt.size_constraint_statement
        return {
            "SizeConstraintStatement": {
                "FieldToMatch": to_aws_field_to_match(s.field_to_match),
                "ComparisonOperator": s.comparison_operator.value,
                "Size": s.size,
                "TextTransformations": to_aws_text_transformations(s.text_transformations),
            }
        }
    if kind == "geo_match_statement":
        s = stmt.geo_match_statement
        return {"GeoMatchStatement": {"CountryCodes": list(s.country_codes)}}
    if kind == "ip_set_reference_statement":
        s = stmt.ip_set_reference_statement
        # Placeholder ARN -- a real deploy needs a real IPSet created via
        # wafv2.create_ip_set first; this sandbox only models the reference.
        return {"IPSetReferenceStatement": {"ARN": f"arn:aws:wafv2:REGION:ACCOUNT:SCOPE/ipset/{s.ip_set_id}/PLACEHOLDER"}}
    if kind == "regex_pattern_set_reference_statement":
        s = stmt.regex_pattern_set_reference_statement
        return {
            "RegexPatternSetReferenceStatement": {
                "ARN": f"arn:aws:wafv2:REGION:ACCOUNT:SCOPE/regexpatternset/{s.regex_set_id}/PLACEHOLDER",
                "FieldToMatch": to_aws_field_to_match(s.field_to_match),
                "TextTransformations": to_aws_text_transformations(s.text_transformations),
            }
        }
    if kind == "label_match_statement":
        s = stmt.label_match_statement
        return {"LabelMatchStatement": {"Scope": s.scope.value, "Key": s.key}}
    if kind == "rate_based_statement":
        s = stmt.rate_based_statement
        out = {
            "Limit": s.limit,
            "EvaluationWindowSec": s.evaluation_window_sec,
            "AggregateKeyType": s.aggregate_key_type,
        }
        if s.scope_down_statement is not None:
            out["ScopeDownStatement"] = to_aws_statement(s.scope_down_statement)
        return {"RateBasedStatement": out}
    if kind == "and_statement":
        return {"AndStatement": {"Statements": [to_aws_statement(c) for c in stmt.and_statement.statements]}}
    if kind == "or_statement":
        return {"OrStatement": {"Statements": [to_aws_statement(c) for c in stmt.or_statement.statements]}}
    if kind == "not_statement":
        return {"NotStatement": {"Statement": to_aws_statement(stmt.not_statement.statement)}}

    raise ValueError(f"Unhandled statement kind for AWS translation: {kind}")


def to_aws_rule(rule: Rule) -> dict:
    aws_rule = {
        "Name": rule.name,
        "Priority": rule.priority,
        "Statement": to_aws_statement(rule.statement),
        "Action": _ACTION_MAP[rule.action],
        "VisibilityConfig": {
            "SampledRequestsEnabled": rule.visibility_config.sampled_requests_enabled,
            "CloudWatchMetricsEnabled": True,
            "MetricName": rule.visibility_config.metric_name,
        },
    }
    if rule.rule_labels:
        aws_rule["RuleLabels"] = [{"Name": lbl} for lbl in rule.rule_labels]
    return aws_rule


def build_update_web_acl_kwargs(
    web_acl: WebACL,
    *,
    name: str,
    scope: str,
    web_acl_id: str,
    lock_token: str,
) -> dict:
    """Shape matches boto3's wafv2 Client.update_web_acl(**kwargs) exactly."""
    return {
        "Name": name,
        "Scope": scope,
        "Id": web_acl_id,
        "LockToken": lock_token,
        "DefaultAction": _ACTION_MAP[web_acl.default_action],
        "Rules": [to_aws_rule(r) for r in web_acl.sorted_rules()],
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name,
        },
    }


def deploy_to_aws(
    web_acl: WebACL,
    *,
    name: str,
    web_acl_id: str,
    lock_token: str,
    scope: str = "REGIONAL",
    region: str | None = None,
    profile: str | None = None,
    live: bool = False,
) -> dict:
    """Dry-run by default: prints and returns the exact update_web_acl kwargs
    with no AWS SDK import and no credential access. Only when live=True do
    we import boto3, build a session (optionally against `profile`), and
    actually call update_web_acl -- the one path in this project that
    touches a real AWS account."""
    kwargs = build_update_web_acl_kwargs(web_acl, name=name, scope=scope, web_acl_id=web_acl_id, lock_token=lock_token)

    if not live:
        print("[dry-run] Would call wafv2.update_web_acl with:")
        print(json.dumps(kwargs, indent=2))
        return {"dry_run": True, "kwargs": kwargs}

    import boto3  # imported lazily so dry-run never requires boto3 credentials/config

    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client("wafv2")
    return client.update_web_acl(**kwargs)
