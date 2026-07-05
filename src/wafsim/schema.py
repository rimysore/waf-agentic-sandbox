"""Pydantic models mirroring the real AWS WAFv2 API shape.

Statements are modeled as AWS does it: a JSON object where exactly one
field (e.g. ``ByteMatchStatement``) is populated. This is the same
"one-of" shape you'd see from ``aws wafv2 get-web-acl`` or in a
CloudFormation template, which is what makes rules produced here
plausible as real WAFv2 rule JSON (see src/live_deploy/boto_apply.py).

Deliberately out of scope (documented, not implemented): Managed Rule
Groups, CAPTCHA/Challenge actions, JA3/JA4 fingerprint statements, ASN
match statements.
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class Action(str, Enum):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    COUNT = "COUNT"


class TextTransformation(str, Enum):
    NONE = "NONE"
    LOWERCASE = "LOWERCASE"
    URL_DECODE = "URL_DECODE"
    HTML_ENTITY_DECODE = "HTML_ENTITY_DECODE"
    COMPRESS_WHITE_SPACE = "COMPRESS_WHITE_SPACE"
    CMD_LINE = "CMD_LINE"


class PositionalConstraint(str, Enum):
    EXACTLY = "EXACTLY"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    CONTAINS = "CONTAINS"
    CONTAINS_WORD = "CONTAINS_WORD"


class ComparisonOperator(str, Enum):
    EQ = "EQ"
    NE = "NE"
    LE = "LE"
    LT = "LT"
    GE = "GE"
    GT = "GT"


class FieldToMatchType(str, Enum):
    URI_PATH = "URI_PATH"
    QUERY_STRING = "QUERY_STRING"
    BODY = "BODY"
    METHOD = "METHOD"
    SINGLE_HEADER = "SINGLE_HEADER"
    ALL_QUERY_ARGUMENTS = "ALL_QUERY_ARGUMENTS"


class FieldToMatch(BaseModel):
    type: FieldToMatchType
    name: Optional[str] = None  # header name, only used when type == SINGLE_HEADER

    @model_validator(mode="after")
    def _header_needs_name(self):
        if self.type == FieldToMatchType.SINGLE_HEADER and not self.name:
            raise ValueError("SINGLE_HEADER field_to_match requires 'name'")
        return self


class SensitivityLevel(str, Enum):
    LOW = "LOW"
    HIGH = "HIGH"


class ByteMatchStatement(BaseModel):
    field_to_match: FieldToMatch
    search_string: str
    positional_constraint: PositionalConstraint
    text_transformations: list[TextTransformation] = Field(default_factory=lambda: [TextTransformation.NONE])


class SqliMatchStatement(BaseModel):
    field_to_match: FieldToMatch
    text_transformations: list[TextTransformation] = Field(default_factory=lambda: [TextTransformation.NONE])
    sensitivity_level: SensitivityLevel = SensitivityLevel.LOW


class XssMatchStatement(BaseModel):
    field_to_match: FieldToMatch
    text_transformations: list[TextTransformation] = Field(default_factory=lambda: [TextTransformation.NONE])


class SizeConstraintStatement(BaseModel):
    field_to_match: FieldToMatch
    comparison_operator: ComparisonOperator
    size: int
    text_transformations: list[TextTransformation] = Field(default_factory=lambda: [TextTransformation.NONE])


class GeoMatchStatement(BaseModel):
    country_codes: list[str]


class IPSetReferenceStatement(BaseModel):
    ip_set_id: str


class RegexPatternSetReferenceStatement(BaseModel):
    regex_set_id: str
    field_to_match: FieldToMatch
    text_transformations: list[TextTransformation] = Field(default_factory=lambda: [TextTransformation.NONE])


class LabelMatchScope(str, Enum):
    LABEL = "LABEL"
    NAMESPACE = "NAMESPACE"


class LabelMatchStatement(BaseModel):
    scope: LabelMatchScope
    key: str


class RateBasedStatement(BaseModel):
    limit: int
    evaluation_window_sec: int = 300  # AWS supports 60/120/300/600
    aggregate_key_type: str = "IP"
    scope_down_statement: Optional["Statement"] = None


class AndStatement(BaseModel):
    statements: list["Statement"]


class OrStatement(BaseModel):
    statements: list["Statement"]


class NotStatement(BaseModel):
    statement: "Statement"


class Statement(BaseModel):
    """One-of wrapper matching AWS WAFv2's Statement JSON shape."""

    byte_match_statement: Optional[ByteMatchStatement] = None
    sqli_match_statement: Optional[SqliMatchStatement] = None
    xss_match_statement: Optional[XssMatchStatement] = None
    size_constraint_statement: Optional[SizeConstraintStatement] = None
    geo_match_statement: Optional[GeoMatchStatement] = None
    ip_set_reference_statement: Optional[IPSetReferenceStatement] = None
    regex_pattern_set_reference_statement: Optional[RegexPatternSetReferenceStatement] = None
    label_match_statement: Optional[LabelMatchStatement] = None
    rate_based_statement: Optional[RateBasedStatement] = None
    and_statement: Optional[AndStatement] = None
    or_statement: Optional[OrStatement] = None
    not_statement: Optional[NotStatement] = None

    @model_validator(mode="after")
    def _exactly_one(self):
        set_fields = [v for v in self.model_dump(exclude_none=True).keys()]
        if len(set_fields) != 1:
            raise ValueError(
                f"Statement must set exactly one statement type, got: {set_fields}"
            )
        return self

    @property
    def kind(self) -> str:
        return next(iter(self.model_dump(exclude_none=True).keys()))


RateBasedStatement.model_rebuild()
AndStatement.model_rebuild()
OrStatement.model_rebuild()
NotStatement.model_rebuild()
Statement.model_rebuild()


class VisibilityConfig(BaseModel):
    sampled_requests_enabled: bool = True
    metric_name: str


class Rule(BaseModel):
    name: str
    priority: int
    statement: Statement
    action: Action
    rule_labels: list[str] = Field(default_factory=list)
    visibility_config: VisibilityConfig


class HttpRequest(BaseModel):
    """Normalized request shape the evaluator operates on -- mirrors the fields
    AWS WAF actually inspects (and later logs) for a request."""

    client_ip: str
    country: str = "US"
    method: str = "GET"
    uri_path: str = "/"
    query_string: str = ""
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)

    def field_value(self, field: "FieldToMatch") -> str:
        if field.type == FieldToMatchType.URI_PATH:
            return self.uri_path
        if field.type == FieldToMatchType.QUERY_STRING:
            return self.query_string
        if field.type == FieldToMatchType.BODY:
            return self.body
        if field.type == FieldToMatchType.METHOD:
            return self.method
        if field.type == FieldToMatchType.ALL_QUERY_ARGUMENTS:
            return self.query_string
        if field.type == FieldToMatchType.SINGLE_HEADER:
            return self.headers.get((field.name or "").lower(), "")
        raise ValueError(f"Unsupported field_to_match type: {field.type}")


class WebACL(BaseModel):
    name: str
    default_action: Action = Action.ALLOW
    rules: list[Rule] = Field(default_factory=list)
    max_capacity_wcu: int = 250

    def sorted_rules(self) -> list[Rule]:
        return sorted(self.rules, key=lambda r: r.priority)
