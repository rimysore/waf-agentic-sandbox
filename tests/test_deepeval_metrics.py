"""Scripted, CI-safe DeepEval regression tests: prove the deterministic
metrics themselves score known-good and known-bad transcripts correctly,
without any network/model dependency (mirrors tests/test_attacker_agent.py's
ScriptedBackend pattern). For a live evaluation of the real agents against
an actual LLM, see scripts/run_deepeval.py."""
import json

from starlette.testclient import TestClient

from src.attacker.tools import AttackerTools
from src.defender.tools import DefenderTools
from src.evals.metrics import (
    AttackerReportFaithfulnessMetric,
    AttackerReportFormatMetric,
    DefenderReplayBeforePromoteMetric,
    RunConvergenceMetric,
)
from src.evals.test_cases import attacker_test_case, defender_test_case, run_convergence_test_case
from src.evals.transcripts import run_attacker_round, run_defender_round
from src.llm.base import ChatResult, ToolCall
from src.llm.fake_backend import ScriptedBackend
from src.wafsim.metrics import MetricsStore
from src.wafsim.middleware import WAFEngineState
from src.wafsim.seed_acl import build_seed_web_acl
from src.wired_app import build_wired_app
from src.evals.schemas import AttackerRoundReport


def make_client():
    app, _ = build_wired_app()
    return TestClient(app)


def scripted(*calls_then_final_content: object):
    """Builds a ScriptedBackend that issues the given ToolCalls one per
    turn, then returns a final plain-text turn with no tool calls."""
    *calls, final_content = calls_then_final_content
    step = {"i": 0}

    def decide(messages, tools_specs):
        if step["i"] < len(calls):
            call = calls[step["i"]]
            step["i"] += 1
            return ChatResult(content="", tool_calls=[call])
        return ChatResult(content=final_content, tool_calls=[])

    return ScriptedBackend(decide)


# ---------------------------------------------------------------------------
# Attacker: report faithfulness + JSON format compliance
# ---------------------------------------------------------------------------


def test_attacker_faithful_report_scores_high():
    tools = AttackerTools(make_client(), budget=1, source_ip_pool=["203.0.113.9"])
    call = ToolCall(
        name="send_request",
        arguments={"category": "xss", "method": "GET", "path": "/search", "query": "q=<script>alert(1)</script>"},
    )
    honest_report = json.dumps({"success_rate": 1.0, "top_blocked_patterns": [], "next_round_hypothesis": "keep going"})
    backend = scripted(call, honest_report)

    transcript = run_attacker_round(backend, tools, round_num=1)
    test_case = attacker_test_case(1, transcript)

    faithfulness = AttackerReportFaithfulnessMetric()
    faithfulness.measure(test_case)
    assert faithfulness.score == 1.0
    assert faithfulness.success

    fmt = AttackerReportFormatMetric(expected_schema=AttackerRoundReport)
    fmt.measure(test_case)
    assert fmt.score == 1.0


def test_attacker_lying_report_scores_low():
    tools = AttackerTools(make_client(), budget=1, source_ip_pool=["203.0.113.9"])
    # Plain (non-bypassing) login creds: ground truth is "not exploited".
    call = ToolCall(
        name="send_request",
        arguments={"category": "sqli", "method": "POST", "path": "/login", "body": "username=admin&password=x"},
    )
    lying_report = json.dumps({"success_rate": 1.0, "top_blocked_patterns": [], "next_round_hypothesis": "lying"})
    backend = scripted(call, lying_report)

    transcript = run_attacker_round(backend, tools, round_num=1)
    assert transcript.ground_truth_success_rate == 0.0  # plain creds don't bypass login

    test_case = attacker_test_case(1, transcript)
    faithfulness = AttackerReportFaithfulnessMetric(threshold=0.85)
    faithfulness.measure(test_case)
    assert faithfulness.score == 0.0
    assert not faithfulness.success


def test_attacker_unparseable_report_fails_format_and_faithfulness():
    tools = AttackerTools(make_client(), budget=1, source_ip_pool=["203.0.113.9"])
    call = ToolCall(name="send_request", arguments={"category": "xss", "method": "GET", "path": "/search", "query": "q=x"})
    backend = scripted(call, "I attacked the app but forgot the format sorry")

    transcript = run_attacker_round(backend, tools, round_num=1)
    test_case = attacker_test_case(1, transcript)

    faithfulness = AttackerReportFaithfulnessMetric()
    faithfulness.measure(test_case)
    assert faithfulness.score == 0.0

    fmt = AttackerReportFormatMetric(expected_schema=AttackerRoundReport)
    fmt.measure(test_case)
    assert fmt.score == 0.0


# ---------------------------------------------------------------------------
# Defender: replay-before-promote workflow discipline
# ---------------------------------------------------------------------------


def make_defender_tools():
    engine_state = WAFEngineState(web_acl=build_seed_web_acl(max_capacity_wcu=250))
    rule_json = json.dumps(
        {
            "name": "rate-limit-login-bursts",
            "priority": 5,
            "statement": {"rate_based_statement": {"limit": 20, "evaluation_window_sec": 60}},
            "action": "BLOCK",
            "rule_labels": [],
            "visibility_config": {"metric_name": "rateLimitLoginBursts"},
        }
    )
    tools = DefenderTools(
        engine_state, MetricsStore(), sampled_logs=[], legit_requests=[], fp_threshold=0.02
    )
    return tools, rule_json


def test_defender_replays_before_promoting_scores_full_marks():
    tools, rule_json = make_defender_tools()
    calls = [
        ToolCall(name="propose_rule", arguments={"rule_json": rule_json}),
        ToolCall(name="replay_against_legit_corpus", arguments={"rule_name": "rate-limit-login-bursts"}),
        ToolCall(name="promote_rule", arguments={"rule_name": "rate-limit-login-bursts"}),
    ]
    backend = scripted(*calls, "staged, replayed, and promoted the login rate limit rule.")

    transcript = run_defender_round(backend, tools, round_num=1)
    test_case = defender_test_case(1, transcript)

    metric = DefenderReplayBeforePromoteMetric()
    metric.measure(test_case)
    assert metric.score == 1.0
    assert metric.success


def test_defender_promotes_without_replay_scores_zero():
    tools, rule_json = make_defender_tools()
    calls = [
        ToolCall(name="propose_rule", arguments={"rule_json": rule_json}),
        ToolCall(name="promote_rule", arguments={"rule_name": "rate-limit-login-bursts"}),
    ]
    backend = scripted(*calls, "staged and promoted without checking false positives.")

    transcript = run_defender_round(backend, tools, round_num=1)
    test_case = defender_test_case(1, transcript)

    metric = DefenderReplayBeforePromoteMetric()
    metric.measure(test_case)
    assert metric.score == 0.0
    assert not metric.success


def test_defender_no_promotions_is_vacuously_compliant():
    tools, rule_json = make_defender_tools()
    calls = [ToolCall(name="propose_rule", arguments={"rule_json": rule_json})]
    backend = scripted(*calls, "staged a rule, will replay next round.")

    transcript = run_defender_round(backend, tools, round_num=1)
    test_case = defender_test_case(1, transcript)

    metric = DefenderReplayBeforePromoteMetric()
    metric.measure(test_case)
    assert metric.score == 1.0


# ---------------------------------------------------------------------------
# Run-level convergence
# ---------------------------------------------------------------------------


def test_run_convergence_full_streak_scores_one():
    summaries = [
        {"attack_success_rate": 0.5, "fp_rate": 0.0},
        {"attack_success_rate": 0.0, "fp_rate": 0.0},
        {"attack_success_rate": 0.0, "fp_rate": 0.01},
    ]
    test_case = run_convergence_test_case(summaries, convergence_rounds_required=2, fp_threshold=0.02)
    metric = RunConvergenceMetric()
    metric.measure(test_case)
    assert metric.score == 1.0


def test_run_convergence_never_converges_scores_partial():
    summaries = [
        {"attack_success_rate": 0.5, "fp_rate": 0.0},
        {"attack_success_rate": 0.0, "fp_rate": 0.0},
        {"attack_success_rate": 0.3, "fp_rate": 0.0},
    ]
    test_case = run_convergence_test_case(summaries, convergence_rounds_required=3, fp_threshold=0.02)
    metric = RunConvergenceMetric()
    metric.measure(test_case)
    assert metric.score == 1 / 3
    assert not metric.success
