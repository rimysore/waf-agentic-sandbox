import json

from starlette.testclient import TestClient

from src.attacker.agent import AttackerAgent
from src.attacker.tools import AttackerTools
from src.llm.base import ChatResult, ToolCall
from src.llm.fake_backend import ScriptedBackend
from src.wired_app import build_wired_app


def make_client():
    app, state = build_wired_app()
    return TestClient(app), state


def test_attacker_round_calls_tools_and_produces_parseable_report():
    client, _ = make_client()
    tools = AttackerTools(client, budget=3, source_ip_pool=["203.0.113.9"])

    calls = [
        ToolCall(
            name="send_request",
            arguments={
                "category": "sqli",
                "method": "POST",
                "path": "/comments",
                "body": '{"comment": "\' OR 1=1--"}',
                "content_type": "application/json",
            },
        ),
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
            arguments={"category": "xss", "method": "GET", "path": "/search", "query": "q=<script>alert(1)</script>"},
        ),
    ]
    step = {"i": 0}

    def decide(messages, tools_specs):
        if step["i"] < len(calls):
            call = calls[step["i"]]
            step["i"] += 1
            return ChatResult(content="", tool_calls=[call])
        return ChatResult(
            content=json.dumps({"success_rate": 0.67, "top_blocked_patterns": ["raw sqli"], "next_round_hypothesis": "try encoding"}),
            tool_calls=[],
        )

    backend = ScriptedBackend(decide)
    agent = AttackerAgent(backend, tools)

    report = agent.run_round(1)

    assert report["success_rate"] == 0.67
    assert len(tools.outcomes) == 3
    assert tools.outcomes[0].blocked is True  # raw sqli query hits the seed rule
    assert tools.outcomes[1].exploited is True  # encoded tautology bypasses + exploits login
    assert agent.memory == [report]


def test_attacker_budget_enforced_even_if_model_keeps_calling():
    client, _ = make_client()
    tools = AttackerTools(client, budget=1, source_ip_pool=["203.0.113.9"])

    def decide(messages, tools_specs):
        # Always tries to send another request, ignoring its own budget.
        return ChatResult(
            content="",
            tool_calls=[
                ToolCall(name="send_request", arguments={"category": "xss", "method": "GET", "path": "/search", "query": "q=x"})
            ],
        )

    agent = AttackerAgent(ScriptedBackend(decide), tools)
    agent.run_round(1)  # should terminate via max_iterations, not hang

    assert tools.used == 1  # only the first call actually consumed budget


def test_attacker_falls_back_to_derived_report_when_model_gives_no_json():
    client, _ = make_client()
    tools = AttackerTools(client, budget=1, source_ip_pool=["203.0.113.9"])

    def decide(messages, tools_specs):
        return ChatResult(content="I attacked the app but forgot the format sorry", tool_calls=[])

    agent = AttackerAgent(ScriptedBackend(decide), tools)
    report = agent.run_round(1)

    assert report["success_rate"] == 0.0  # no tool calls made -> no outcomes -> 0.0
    assert "no parseable report" in report["next_round_hypothesis"]
