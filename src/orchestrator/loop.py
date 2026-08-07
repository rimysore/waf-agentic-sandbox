"""Ties the attacker, defender, WAF engine, and persistence together into a
round-based demo run.

Per round: (1) attacker spends its request budget, (2) a legit-traffic batch
is replayed through the current ACL, (3) an automatic regression check
rolls back any promoted rule whose FP rate just spiked (independent of
whether the defender notices), (4) the defender agent runs and may
stage/replay/promote/rollback/retire rules, (5) everything is persisted and
a versioned WebACL snapshot is saved. Stops on convergence (0% attack
success + FP under threshold for N consecutive rounds) or max_rounds.
"""
from __future__ import annotations

import random

from starlette.testclient import TestClient

from src.attacker.agent import AttackerAgent
from src.attacker.tools import AttackerTools
from src.config import ScenarioConfig
from src.corpus.legit_traffic import generate_round_traffic
from src.defender.agent import DefenderAgent
from src.defender.promotion import run_regression_check
from src.defender.tools import DefenderTools
from src.llm.base import LLMBackend
from src.wafsim.logging_format import build_sampled_log
from src.wafsim.metrics import MetricsStore
from src.wafsim.middleware import WAFEngineState
from src.wafsim.schema import HttpRequest
from src.wafsim.seed_acl import build_seed_web_acl
from src.wafsim.wcu import web_acl_capacity
from src.wired_app import build_wired_app

from .persistence import RunStore

# TEST-NET-3 (RFC 5737) -- deliberately disjoint from the legit-traffic pool
# (TEST-NET-2, 198.51.100.0/24) so logs can be triaged by IP range.
ATTACKER_IP_POOL = [f"203.0.113.{i}" for i in range(2, 60)]

WEB_ACL_NAME = "demo-web-acl"


class RoundRecorder:
    """Bridges WAFMiddleware's on_evaluated hook to the metrics store and a
    per-round sampled-log buffer, for both attacker and legit traffic alike
    (a real WAF sees both in the same log stream too)."""

    def __init__(self, web_acl_name: str):
        self.web_acl_name = web_acl_name
        self.metrics = MetricsStore()
        self.sampled_logs: list[dict] = []

    def on_evaluated(self, request: HttpRequest, result) -> None:
        self.metrics.record(result)
        self.sampled_logs.append(build_sampled_log(self.web_acl_name, request, result))

    def drain_round_logs(self) -> list[dict]:
        logs, self.sampled_logs = self.sampled_logs, []
        return logs


class OrchestratorLoop:
    def __init__(
        self,
        config: ScenarioConfig,
        attacker_backend: LLMBackend,
        defender_backend: LLMBackend,
        db_path: str | None = None,
    ):
        self.config = config
        self.defender_backend = defender_backend
        self.rng = random.Random(config.traffic.rng_seed)
        self.store = RunStore(db_path or config.persistence.db_path)

        self.recorder = RoundRecorder(WEB_ACL_NAME)
        self.engine_state = WAFEngineState(web_acl=build_seed_web_acl(config.budget.wcu_max_capacity))
        self.app, _ = build_wired_app(state=self.engine_state, on_evaluated=self.recorder.on_evaluated)
        self.client = TestClient(self.app)

        self.attacker = AttackerAgent(
            attacker_backend,
            AttackerTools(self.client, budget=config.traffic.attacker_requests_per_round, source_ip_pool=ATTACKER_IP_POOL),
        )

        self.converged_rounds = 0
        self.rounds_run = 0

    def _run_legit_traffic(self) -> tuple[list[HttpRequest], float]:
        legit_requests = generate_round_traffic(self.config.traffic.legit_requests_per_round, self.rng)
        blocked = 0
        for req in legit_requests:
            headers = dict(req.headers)
            headers["x-demo-source-ip"] = req.client_ip
            url = req.uri_path + (f"?{req.query_string}" if req.query_string else "")
            resp = self.client.request(req.method, url, content=req.body.encode() if req.body else None, headers=headers)
            if resp.status_code == 403:
                blocked += 1
        fp_rate = blocked / len(legit_requests) if legit_requests else 0.0
        return legit_requests, fp_rate

    def run_round(self, round_num: int) -> dict:
        self.store.start_round(round_num)

        self.attacker.tools.used = 0
        self.attacker.tools.outcomes = []
        attacker_report = self.attacker.run_round(round_num)

        legit_requests, fp_rate = self._run_legit_traffic()

        rolled_back = run_regression_check(
            self.engine_state.web_acl,
            legit_requests,
            self.config.thresholds.false_positive_rate_max,
            self.engine_state.ip_sets,
            self.engine_state.regex_sets,
        )
        for rb in rolled_back:
            self.store.record_rule_change(
                round_num, "auto_rollback", rb.rule_name, {"fp_rate": rb.fp_rate}, "automatic regression check"
            )

        defender_tools = DefenderTools(
            self.engine_state,
            self.recorder.metrics,
            self.recorder.sampled_logs,
            legit_requests,
            self.config.thresholds.false_positive_rate_max,
        )
        defender = DefenderAgent(self.defender_backend, defender_tools)
        defender_report = defender.run_round(round_num)
        for action in defender_tools.actions_taken:
            self.store.record_rule_change(
                round_num, action["event"], action["rule_name"], action["detail"], defender_report.get("notes", "")
            )

        outcomes = self.attacker.tools.outcomes
        attack_success_rate = (sum(1 for o in outcomes if o.exploited) / len(outcomes)) if outcomes else 0.0
        wcu_used = web_acl_capacity(self.engine_state.web_acl)

        self.store.save_web_acl_snapshot(round_num, self.engine_state.web_acl)
        self.store.record_sampled_logs_batch(round_num, self.recorder.drain_round_logs())
        self.store.record_metrics(round_num, self.recorder.metrics.snapshot_and_reset_round())
        self.store.save_attacker_memory(round_num, attacker_report)
        self.store.save_defender_memory(round_num, defender_report)
        self.store.end_round(round_num, attack_success_rate, fp_rate, wcu_used)

        summary = {
            "round": round_num,
            "attack_success_rate": attack_success_rate,
            "fp_rate": fp_rate,
            "wcu_used": wcu_used,
            "defender_actions": [a["event"] + ":" + a["rule_name"] for a in defender_tools.actions_taken],
            "defender_actions_detail": list(defender_tools.actions_taken),
            "auto_rollbacks": [rb.rule_name for rb in rolled_back],
        }
        return summary

    def run(self) -> list[dict]:
        summaries = []
        for round_num in range(1, self.config.rounds.max_rounds + 1):
            summary = self.run_round(round_num)
            summaries.append(summary)
            self.rounds_run = round_num

            converged_this_round = (
                summary["attack_success_rate"] == 0.0
                and summary["fp_rate"] <= self.config.thresholds.false_positive_rate_max
            )
            if converged_this_round:
                self.converged_rounds += 1
                if self.converged_rounds >= self.config.rounds.convergence_rounds_required:
                    break
            else:
                self.converged_rounds = 0

        self.store.close()
        return summaries
