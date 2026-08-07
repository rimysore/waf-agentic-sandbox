"""Drives the real attacker/defender agents (against a live Ollama model by
default) through a normal multi-round OrchestratorLoop run, scoring every
round with DeepEval's deterministic metrics (no LLM judge, no API key
needed) and printing a report.

Run with: python -m scripts.run_deepeval [--rounds N] [--model NAME] [--config PATH]
"""
from __future__ import annotations

import argparse

from deepeval import evaluate
from deepeval.evaluate.configs import AsyncConfig, DisplayConfig

from src.config import load_config
from src.evals.metrics import (
    AttackerReportFaithfulnessMetric,
    AttackerReportFormatMetric,
    DefenderReplayBeforePromoteMetric,
    RunConvergenceMetric,
)
from src.evals.schemas import AttackerRoundReport
from src.evals.test_cases import (
    attacker_test_case_from_slice,
    defender_test_case_from_slice,
    run_convergence_test_case,
)
from src.evals.transcripts import RecordingBackend
from src.llm.ollama_backend import OllamaBackend
from src.orchestrator.loop import OrchestratorLoop


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=None, help="Override config.rounds.max_rounds")
    parser.add_argument("--model", default=None, help="Override config.llm.ollama_model")
    parser.add_argument("--config", default=None, help="Path to scenario.yaml")
    parser.add_argument("--db", default=":memory:", help="Run-store DB path (default: throwaway in-memory)")
    parser.add_argument(
        "--attacker-requests", type=int, default=None, help="Override config.traffic.attacker_requests_per_round"
    )
    parser.add_argument(
        "--legit-requests", type=int, default=None, help="Override config.traffic.legit_requests_per_round"
    )
    args = parser.parse_args()

    config = load_config(args.config)
    if args.rounds:
        config.rounds.max_rounds = args.rounds
    if args.model:
        config.llm.ollama_model = args.model
    if args.attacker_requests:
        config.traffic.attacker_requests_per_round = args.attacker_requests
    if args.legit_requests:
        config.traffic.legit_requests_per_round = args.legit_requests

    attacker_backend = RecordingBackend(OllamaBackend(model=config.llm.ollama_model, host=config.llm.ollama_host))
    defender_backend = RecordingBackend(OllamaBackend(model=config.llm.ollama_model, host=config.llm.ollama_host))

    loop = OrchestratorLoop(config, attacker_backend=attacker_backend, defender_backend=defender_backend, db_path=args.db)

    attacker_cases = []
    defender_cases = []
    summaries = []

    print(f"Running up to {config.rounds.max_rounds} rounds against model={config.llm.ollama_model!r}...\n")
    for round_num in range(1, config.rounds.max_rounds + 1):
        a_mark, d_mark = attacker_backend.mark(), defender_backend.mark()
        summary = loop.run_round(round_num)
        summaries.append(summary)

        attacker_cases.append(
            attacker_test_case_from_slice(round_num, attacker_backend.since(a_mark), summary["attack_success_rate"])
        )
        defender_cases.append(
            defender_test_case_from_slice(
                round_num, defender_backend.since(d_mark), summary.get("defender_actions_detail")
            )
        )

        print(
            f"round {round_num:>2}: attack_success_rate={summary['attack_success_rate']:.2f} "
            f"fp_rate={summary['fp_rate']:.3f} wcu={summary['wcu_used']} "
            f"actions={summary['defender_actions'] or '-'}"
        )

        converged = (
            summary["attack_success_rate"] == 0.0 and summary["fp_rate"] <= config.thresholds.false_positive_rate_max
        )
        if converged:
            loop.converged_rounds += 1
            if loop.converged_rounds >= config.rounds.convergence_rounds_required:
                break
        else:
            loop.converged_rounds = 0

    loop.store.close()

    convergence_case = run_convergence_test_case(
        summaries, config.rounds.convergence_rounds_required, config.thresholds.false_positive_rate_max
    )

    print("\n--- Attacker report quality ---")
    evaluate(
        attacker_cases,
        metrics=[AttackerReportFaithfulnessMetric(), AttackerReportFormatMetric(expected_schema=AttackerRoundReport)],
        async_config=AsyncConfig(run_async=False),
        display_config=DisplayConfig(show_indicator=False),
    )

    print("\n--- Defender workflow discipline ---")
    evaluate(
        defender_cases,
        metrics=[DefenderReplayBeforePromoteMetric()],
        async_config=AsyncConfig(run_async=False),
        display_config=DisplayConfig(show_indicator=False),
    )

    print("\n--- Run convergence ---")
    evaluate(
        [convergence_case],
        metrics=[RunConvergenceMetric()],
        async_config=AsyncConfig(run_async=False),
        display_config=DisplayConfig(show_indicator=False),
    )


if __name__ == "__main__":
    main()
