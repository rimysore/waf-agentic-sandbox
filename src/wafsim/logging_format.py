"""Builds AWS WAFv2 sampled-request-shaped log entries (the same JSON shape
you'd get from GetSampledRequests or a log-delivery destination), so logs
produced by this sandbox are structurally the real thing."""
from __future__ import annotations

import time
import uuid

from .evaluator import EvaluationResult
from .schema import HttpRequest


def build_sampled_log(
    web_acl_name: str,
    request: HttpRequest,
    result: EvaluationResult,
    request_id: str | None = None,
) -> dict:
    non_terminating = [
        {"ruleId": hit.rule_name, "action": hit.action.value} for hit in result.rule_hits if not hit.terminating
    ]
    return {
        "timestamp": int(time.time() * 1000),
        "formatVersion": 1,
        "webaclId": web_acl_name,
        "terminatingRuleId": result.terminating_rule_id,
        "terminatingRuleType": result.terminating_rule_type,
        "action": result.action.value,
        "nonTerminatingMatchingRules": non_terminating,
        "labels": [{"name": lbl} for lbl in result.labels],
        "httpRequest": {
            "clientIp": request.client_ip,
            "country": request.country,
            "headers": [{"name": k, "value": v} for k, v in request.headers.items()],
            "uri": request.uri_path,
            "args": request.query_string,
            "httpMethod": request.method,
            "requestId": request_id or str(uuid.uuid4()),
        },
    }
