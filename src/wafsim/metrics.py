"""CloudWatch-analogue per-rule metrics: AllowedRequests/BlockedRequests/
CountedRequests counters, matching what a real WebACL emits per rule
(only rules that actually matched produce a metric increment -- non-matching
rules are silent, same as real AWS)."""
from __future__ import annotations

from collections import defaultdict

from .evaluator import DEFAULT_ACTION_RULE_ID, EvaluationResult
from .schema import Action

_BUCKETS = ("ALLOWED", "BLOCKED", "COUNTED")


def _bucket_for(action: Action) -> str:
    return {"BLOCK": "BLOCKED", "ALLOW": "ALLOWED", "COUNT": "COUNTED"}[action.value]


class MetricsStore:
    def __init__(self):
        self._round: dict[str, dict[str, int]] = defaultdict(lambda: {b: 0 for b in _BUCKETS})
        self._totals: dict[str, dict[str, int]] = defaultdict(lambda: {b: 0 for b in _BUCKETS})

    def record(self, result: EvaluationResult) -> None:
        for hit in result.rule_hits:
            bucket = _bucket_for(hit.action)
            self._round[hit.rule_name][bucket] += 1
            self._totals[hit.rule_name][bucket] += 1

        if result.terminating_rule_id == DEFAULT_ACTION_RULE_ID:
            bucket = _bucket_for(result.action)
            self._round[DEFAULT_ACTION_RULE_ID][bucket] += 1
            self._totals[DEFAULT_ACTION_RULE_ID][bucket] += 1

    def snapshot_and_reset_round(self) -> dict[str, dict[str, int]]:
        snap = {rule: dict(counts) for rule, counts in self._round.items()}
        self._round.clear()
        return snap

    def totals(self) -> dict[str, dict[str, int]]:
        return {rule: dict(counts) for rule, counts in self._totals.items()}
