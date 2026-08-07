"""Tool implementations bound to the live WAF state for the defender agent.
Guardrails are enforced here in code (budget check on stage, FP-rate check
on promote) -- rejections come back as tool-call errors the agent must
react to, they are never left to the model's judgment alone."""
from __future__ import annotations

import json

from src.wafsim.middleware import WAFEngineState
from src.wafsim.metrics import MetricsStore
from src.wafsim.schema import HttpRequest, Rule
from src.wafsim.wcu import WCUBudgetExceeded

from . import promotion


class DefenderTools:
    def __init__(
        self,
        engine_state: WAFEngineState,
        metrics: MetricsStore,
        sampled_logs: list[dict],
        legit_requests: list[HttpRequest],
        fp_threshold: float,
    ):
        self.engine_state = engine_state
        self.metrics = metrics
        self.sampled_logs = sampled_logs
        self.legit_requests = legit_requests
        self.fp_threshold = fp_threshold
        self.actions_taken: list[dict] = []  # audit trail for this round, drained by the orchestrator

    def get_metrics_summary(self) -> dict:
        return self.metrics.totals()

    def get_recent_sampled_logs(self, n: int = 20) -> list[dict]:
        return self.sampled_logs[-n:]

    def get_current_web_acl(self) -> dict:
        return json.loads(self.engine_state.web_acl.model_dump_json())

    def propose_rule(self, rule_json: str) -> dict:
        try:
            parsed = json.loads(rule_json) if isinstance(rule_json, str) else rule_json
            rule = Rule.model_validate(parsed)
        except Exception as e:  # noqa: BLE001 -- surfaced to the model, not a crash
            return {"error": f"invalid rule JSON/schema: {e}"}

        try:
            staged = promotion.stage_rule(self.engine_state.web_acl, rule)
        except WCUBudgetExceeded as e:
            return {"error": str(e)}

        self.actions_taken.append({"event": "staged", "rule_name": staged.name, "detail": {}})
        return {"status": "staged", "rule_name": staged.name, "action": staged.action.value}

    def replay_against_legit_corpus(self, rule_name: str) -> dict:
        try:
            rule = promotion.find_rule(self.engine_state.web_acl, rule_name)
        except KeyError as e:
            return {"error": str(e)}
        fp_rate = promotion.compute_fp_rate(
            rule, self.legit_requests, self.engine_state.ip_sets, self.engine_state.regex_sets
        )
        self.actions_taken.append({"event": "replayed", "rule_name": rule_name, "detail": {"fp_rate": fp_rate}})
        return {"rule_name": rule_name, "fp_rate": fp_rate, "threshold": self.fp_threshold}

    def promote_rule(self, rule_name: str) -> dict:
        try:
            fp_rate = promotion.promote_rule(
                self.engine_state.web_acl,
                rule_name,
                self.legit_requests,
                self.fp_threshold,
                self.engine_state.ip_sets,
                self.engine_state.regex_sets,
            )
        except promotion.PromotionRejected as e:
            return {"error": str(e), "fp_rate": e.fp_rate, "threshold": e.threshold}
        except KeyError as e:
            return {"error": str(e)}

        self.actions_taken.append({"event": "promoted", "rule_name": rule_name, "detail": {"fp_rate": fp_rate}})
        return {"status": "promoted", "rule_name": rule_name, "fp_rate": fp_rate}

    def rollback_rule(self, rule_name: str, reason: str = "") -> dict:
        try:
            promotion.rollback_rule(self.engine_state.web_acl, rule_name)
        except KeyError as e:
            return {"error": str(e)}
        self.actions_taken.append({"event": "rolled_back", "rule_name": rule_name, "detail": {"reason": reason}})
        return {"status": "rolled_back", "rule_name": rule_name}

    def retire_rule(self, rule_name: str) -> dict:
        try:
            promotion.retire_rule(self.engine_state.web_acl, rule_name)
        except KeyError as e:
            return {"error": str(e)}
        self.actions_taken.append({"event": "retired", "rule_name": rule_name, "detail": {}})
        return {"status": "retired", "rule_name": rule_name}
