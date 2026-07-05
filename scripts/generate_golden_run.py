"""Generates data/golden_run.db: a deterministic, scripted (no LLM) run of
the full attacker/defender loop, used so the dashboard has something
reliable to demo without depending on a live Ollama call at demo time.

Run with: python -m scripts.generate_golden_run
"""
from __future__ import annotations

import json
import re

from src.config import ScenarioConfig
from src.llm.base import ChatResult, ToolCall
from src.llm.fake_backend import ScriptedBackend
from src.orchestrator.loop import OrchestratorLoop

CRED_IP = "203.0.113.50"

_ATTACK_CALLS = [
    ToolCall(name="send_request", arguments={"category": "sqli", "method": "POST", "path": "/comments",
                                              "body": json.dumps({"comment": "' OR 1=1--"}), "content_type": "application/json"}),
    ToolCall(name="send_request", arguments={"category": "sqli", "method": "POST", "path": "/login",
                                              "body": "username=admin%27--&password=x", "content_type": "application/x-www-form-urlencoded"}),
    ToolCall(name="send_request", arguments={"category": "xss", "method": "POST", "path": "/comments",
                                              "body": json.dumps({"comment": "<script>alert(1)</script>"}), "content_type": "application/json"}),
    ToolCall(name="send_request", arguments={"category": "xss", "method": "GET", "path": "/search", "query": "q=<script>alert(1)</script>"}),
    ToolCall(name="send_request", arguments={"category": "credential_stuffing", "method": "POST", "path": "/login",
                                              "body": json.dumps({"username": "alice", "password": "wrong"}),
                                              "content_type": "application/json", "source_ip": CRED_IP}),
    ToolCall(name="send_request", arguments={"category": "credential_stuffing", "method": "POST", "path": "/login",
                                              "body": json.dumps({"username": "alice", "password": "wrong2"}),
                                              "content_type": "application/json", "source_ip": CRED_IP}),
]
_ATTACK_CALLS_CONVERGED = _ATTACK_CALLS[:4]

SQLI_FIX_RULE = {
    "name": "generic-sqli-basic-fixed", "priority": 11,
    "statement": {"or_statement": {"statements": [
        {"sqli_match_statement": {"field_to_match": {"type": "QUERY_STRING"}, "text_transformations": ["URL_DECODE"]}},
        {"sqli_match_statement": {"field_to_match": {"type": "BODY"}, "text_transformations": ["URL_DECODE"]}},
    ]}},
    "action": "BLOCK", "rule_labels": [], "visibility_config": {"metric_name": "sqliFixed"},
}
XSS_FIX_RULE = {
    "name": "generic-xss-basic-fixed", "priority": 12,
    "statement": {"or_statement": {"statements": [
        {"xss_match_statement": {"field_to_match": {"type": "QUERY_STRING"}, "text_transformations": ["URL_DECODE"]}},
        {"xss_match_statement": {"field_to_match": {"type": "BODY"}, "text_transformations": ["URL_DECODE"]}},
    ]}},
    "action": "BLOCK", "rule_labels": [], "visibility_config": {"metric_name": "xssFixed"},
}
RATE_LIMIT_RULE = {
    "name": "rate-limit-login", "priority": 5,
    "statement": {"rate_based_statement": {"limit": 3, "evaluation_window_sec": 3600}},
    "action": "BLOCK", "rule_labels": [], "visibility_config": {"metric_name": "rateLimitLogin"},
}


def _round_num_from_messages(messages: list[dict]) -> int:
    user_msg = next(m["content"] for m in messages if m["role"] == "user")
    return int(re.search(r"Round (\d+)", user_msg).group(1))


def make_attacker_backend():
    step = {"round": None, "i": 0}

    def decide(messages, tools):
        round_num = _round_num_from_messages(messages)
        if step["round"] != round_num:
            step["round"], step["i"] = round_num, 0
        calls = _ATTACK_CALLS if round_num <= 3 else _ATTACK_CALLS_CONVERGED
        if step["i"] < len(calls):
            call = calls[step["i"]]
            step["i"] += 1
            return ChatResult(content="", tool_calls=[call])
        return ChatResult(content="done attacking this round", tool_calls=[])

    return ScriptedBackend(decide)


def make_defender_backend():
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
            step["round"], step["i"] = round_num, 0
        plan = plans.get(round_num, [])
        if step["i"] < len(plan):
            call = plan[step["i"]]
            step["i"] += 1
            return ChatResult(content="", tool_calls=[call])
        return ChatResult(content=f"round {round_num}: no further action needed", tool_calls=[])

    return ScriptedBackend(decide)


def main() -> None:
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
        db_path="data/golden_run.db",
    )
    summaries = loop.run()

    print(f"golden run written to data/golden_run.db ({len(summaries)} rounds)")
    for s in summaries:
        print(f"  round {s['round']}: attack_success={s['attack_success_rate']:.2f} fp_rate={s['fp_rate']:.3f} "
              f"wcu={s['wcu_used']} actions={s['defender_actions']}")


if __name__ == "__main__":
    main()
