"""End-to-end orchestrator smoke test using deterministic scripted backends
(no LLM, no network) -- proves the round mechanics, promotion guardrails,
and convergence behavior work before ever pointing this at a real model."""
from __future__ import annotations

import json
import re

from src.config import ScenarioConfig
from src.llm.base import ChatResult, ToolCall
from src.llm.fake_backend import ScriptedBackend
from src.orchestrator.loop import OrchestratorLoop

CRED_IP = "203.0.113.50"

_ATTACK_CALLS = [
    ToolCall(name="send_request", arguments={"category": "sqli", "method": "GET", "path": "/search", "query": "q=' OR 1=1--"}),
    ToolCall(
        name="send_request",
        arguments={
            "category": "sqli",
            "method": "POST",
            "path": "/login",
            "body": "username=admin%27--&password=x",
            "content_type": "application/x-www-form-urlencoded",
        },
    ),
    ToolCall(
        name="send_request",
        arguments={
            "category": "xss",
            "method": "POST",
            "path": "/comments",
            "body": json.dumps({"comment": "<script>alert(1)</script>"}),
            "content_type": "application/json",
        },
    ),
    ToolCall(name="send_request", arguments={"category": "xss", "method": "GET", "path": "/search", "query": "q=<script>alert(1)</script>"}),
    ToolCall(
        name="send_request",
        arguments={
            "category": "credential_stuffing",
            "method": "POST",
            "path": "/login",
            "body": json.dumps({"username": "alice", "password": "wrong"}),
            "content_type": "application/json",
            "source_ip": CRED_IP,
        },
    ),
    ToolCall(
        name="send_request",
        arguments={
            "category": "credential_stuffing",
            "method": "POST",
            "path": "/login",
            "body": json.dumps({"username": "alice", "password": "wrong2"}),
            "content_type": "application/json",
            "source_ip": CRED_IP,
        },
    ),
]

# Rounds 4+: drop credential_stuffing (accepted as a dead end) and just retry
# the now-fixed sqli/xss payloads -- demonstrates a clean converged round.
_ATTACK_CALLS_CONVERGED = _ATTACK_CALLS[:4]

SQLI_FIX_RULE = {
    "name": "generic-sqli-basic-fixed",
    "priority": 11,
    "statement": {
        "or_statement": {
            "statements": [
                {"sqli_match_statement": {"field_to_match": {"type": "QUERY_STRING"}, "text_transformations": ["URL_DECODE"]}},
                {"sqli_match_statement": {"field_to_match": {"type": "BODY"}, "text_transformations": ["URL_DECODE"]}},
            ]
        }
    },
    "action": "BLOCK",
    "rule_labels": [],
    "visibility_config": {"metric_name": "sqliFixed"},
}

XSS_FIX_RULE = {
    "name": "generic-xss-basic-fixed",
    "priority": 12,
    "statement": {
        "or_statement": {
            "statements": [
                {"xss_match_statement": {"field_to_match": {"type": "QUERY_STRING"}, "text_transformations": ["URL_DECODE"]}},
                {"xss_match_statement": {"field_to_match": {"type": "BODY"}, "text_transformations": ["URL_DECODE"]}},
            ]
        }
    },
    "action": "BLOCK",
    "rule_labels": [],
    "visibility_config": {"metric_name": "xssFixed"},
}

RATE_LIMIT_RULE = {
    "name": "rate-limit-login",
    "priority": 5,
    # limit=3 (not 1) so an incidental repeat IP among the legit corpus's
    # randomized draws doesn't itself look like a false positive.
    "statement": {"rate_based_statement": {"limit": 3, "evaluation_window_sec": 3600}},
    "action": "BLOCK",
    "rule_labels": [],
    "visibility_config": {"metric_name": "rateLimitLogin"},
}


def _round_num_from_messages(messages: list[dict]) -> int:
    user_msg = next(m["content"] for m in messages if m["role"] == "user")
    match = re.search(r"Round (\d+)", user_msg)
    return int(match.group(1))


def make_attacker_backend():
    step = {"round": None, "i": 0}

    def decide(messages, tools):
        round_num = _round_num_from_messages(messages)
        if step["round"] != round_num:
            step["round"] = round_num
            step["i"] = 0

        calls = _ATTACK_CALLS if round_num <= 3 else _ATTACK_CALLS_CONVERGED
        if step["i"] < len(calls):
            call = calls[step["i"]]
            step["i"] += 1
            return ChatResult(content="", tool_calls=[call])
        return ChatResult(content="done attacking this round", tool_calls=[])

    return ScriptedBackend(decide)


def make_defender_backend():
    # Round -> ordered plan of tool calls to run once metrics/logs are pulled.
    plans = {
        1: [
            ToolCall(name="get_metrics_summary", arguments={}),
            ToolCall(name="propose_rule", arguments={"rule_json": json.dumps(SQLI_FIX_RULE)}),
            ToolCall(name="replay_against_legit_corpus", arguments={"rule_name": "generic-sqli-basic-fixed"}),
            ToolCall(name="promote_rule", arguments={"rule_name": "generic-sqli-basic-fixed"}),
        ],
        2: [
            ToolCall(name="get_metrics_summary", arguments={}),
            ToolCall(name="propose_rule", arguments={"rule_json": json.dumps(XSS_FIX_RULE)}),
            ToolCall(name="replay_against_legit_corpus", arguments={"rule_name": "generic-xss-basic-fixed"}),
            ToolCall(name="promote_rule", arguments={"rule_name": "generic-xss-basic-fixed"}),
        ],
        3: [
            ToolCall(name="get_metrics_summary", arguments={}),
            ToolCall(name="propose_rule", arguments={"rule_json": json.dumps(RATE_LIMIT_RULE)}),
            ToolCall(name="replay_against_legit_corpus", arguments={"rule_name": "rate-limit-login"}),
            ToolCall(name="promote_rule", arguments={"rule_name": "rate-limit-login"}),
        ],
    }
    step = {"round": None, "i": 0}

    def decide(messages, tools):
        round_num = _round_num_from_messages(messages)
        if step["round"] != round_num:
            step["round"] = round_num
            step["i"] = 0

        plan = plans.get(round_num, [])
        if step["i"] < len(plan):
            call = plan[step["i"]]
            step["i"] += 1
            return ChatResult(content="", tool_calls=[call])
        return ChatResult(content=f"round {round_num}: no further action needed", tool_calls=[])

    return ScriptedBackend(decide)


def test_full_scripted_run_converges_and_respects_guardrails(tmp_path):
    config = ScenarioConfig()
    config.rounds.max_rounds = 8
    config.rounds.convergence_rounds_required = 2
    config.traffic.attacker_requests_per_round = 6
    config.traffic.legit_requests_per_round = 50
    config.budget.wcu_max_capacity = 250

    loop = OrchestratorLoop(
        config,
        attacker_backend=make_attacker_backend(),
        defender_backend=make_defender_backend(),
        db_path=str(tmp_path / "run.db"),
    )
    summaries = loop.run()

    first_round = summaries[0]
    last_round = summaries[-1]

    assert first_round["attack_success_rate"] > 0
    assert last_round["attack_success_rate"] == 0.0
    assert last_round["attack_success_rate"] < first_round["attack_success_rate"]

    promoted_events = [s for round_summary in summaries for s in round_summary["defender_actions"] if s.startswith("promoted:")]
    assert len(promoted_events) >= 3  # sqli fix, xss fix, rate limit

    assert all(s["fp_rate"] <= 0.05 for s in summaries)  # promoted rules never meaningfully hurt legit traffic
    assert all(s["wcu_used"] <= config.budget.wcu_max_capacity for s in summaries)

    from src.orchestrator.persistence import RunStore

    store = RunStore(str(tmp_path / "run.db"))
    rule_changes = store.fetch_rule_changes()
    assert any(c["event_type"] == "promoted" for c in rule_changes)
    store.close()
