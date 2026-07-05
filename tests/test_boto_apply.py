from src.live_deploy.boto_apply import build_update_web_acl_kwargs, deploy_to_aws, to_aws_rule, to_aws_statement
from src.wafsim.schema import (
    Action,
    FieldToMatch,
    FieldToMatchType,
    PositionalConstraint,
    RateBasedStatement,
    Rule,
    SqliMatchStatement,
    Statement,
    TextTransformation,
    VisibilityConfig,
    WebACL,
)
from src.wafsim.seed_acl import build_seed_web_acl


def test_sqli_statement_translates_to_pascal_case_aws_shape():
    stmt = Statement(
        sqli_match_statement=SqliMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.QUERY_STRING),
            text_transformations=[TextTransformation.URL_DECODE, TextTransformation.LOWERCASE],
        )
    )
    aws = to_aws_statement(stmt)
    assert aws == {
        "SqliMatchStatement": {
            "FieldToMatch": {"QueryString": {}},
            "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}, {"Priority": 1, "Type": "LOWERCASE"}],
            "SensitivityLevel": "LOW",
        }
    }


def test_rate_based_statement_translation():
    stmt = Statement(rate_based_statement=RateBasedStatement(limit=20, evaluation_window_sec=60))
    aws = to_aws_statement(stmt)
    assert aws == {
        "RateBasedStatement": {"Limit": 20, "EvaluationWindowSec": 60, "AggregateKeyType": "IP"}
    }


def test_rule_translation_includes_action_and_visibility_config():
    rule = Rule(
        name="block-sqli",
        priority=1,
        statement=Statement(
            sqli_match_statement=SqliMatchStatement(field_to_match=FieldToMatch(type=FieldToMatchType.BODY))
        ),
        action=Action.BLOCK,
        rule_labels=["custom:sqli"],
        visibility_config=VisibilityConfig(metric_name="blockSqli"),
    )
    aws = to_aws_rule(rule)
    assert aws["Name"] == "block-sqli"
    assert aws["Priority"] == 1
    assert aws["Action"] == {"Block": {}}
    assert aws["RuleLabels"] == [{"Name": "custom:sqli"}]
    assert aws["VisibilityConfig"] == {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": "blockSqli",
    }


def test_positional_constraint_and_byte_match_translation():
    from src.wafsim.schema import ByteMatchStatement

    stmt = Statement(
        byte_match_statement=ByteMatchStatement(
            field_to_match=FieldToMatch(type=FieldToMatchType.URI_PATH),
            search_string="/admin",
            positional_constraint=PositionalConstraint.STARTS_WITH,
        )
    )
    aws = to_aws_statement(stmt)
    assert aws["ByteMatchStatement"]["PositionalConstraint"] == "STARTS_WITH"
    assert aws["ByteMatchStatement"]["SearchString"] == "/admin"
    assert aws["ByteMatchStatement"]["FieldToMatch"] == {"UriPath": {}}


def test_build_update_web_acl_kwargs_matches_boto3_signature_shape():
    acl = build_seed_web_acl()
    kwargs = build_update_web_acl_kwargs(acl, name="demo-web-acl", scope="REGIONAL", web_acl_id="abc-123", lock_token="tok-1")

    assert set(kwargs.keys()) == {"Name", "Scope", "Id", "LockToken", "DefaultAction", "Rules", "VisibilityConfig"}
    assert kwargs["Id"] == "abc-123"
    assert kwargs["LockToken"] == "tok-1"
    assert len(kwargs["Rules"]) == len(acl.rules)
    assert kwargs["DefaultAction"] == {"Allow": {}}


def test_dry_run_deploy_never_imports_boto3_or_touches_credentials(monkeypatch):
    acl = WebACL(name="acl", rules=[])
    result = deploy_to_aws(acl, name="demo", web_acl_id="id-1", lock_token="tok-1", live=False)
    assert result["dry_run"] is True
    assert result["kwargs"]["Id"] == "id-1"
