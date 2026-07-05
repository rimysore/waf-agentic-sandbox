"""Entrypoints:
  python -m src.cli demo   [--rounds N] [--config PATH] [--db PATH]
  python -m src.cli deploy --db PATH --round N --web-acl-id ID --lock-token TOK
                           [--name NAME] [--scope REGIONAL|CLOUDFRONT] [--region R]
                           [--profile PROFILE] [--live]
"""
from __future__ import annotations

import argparse
import sys

from src.config import load_config
from src.live_deploy.boto_apply import deploy_to_aws
from src.llm.ollama_backend import OllamaBackend
from src.orchestrator.loop import OrchestratorLoop
from src.orchestrator.persistence import RunStore
from src.wafsim.schema import WebACL


def _run_demo(args) -> None:
    config = load_config(args.config)
    if args.rounds:
        config.rounds.max_rounds = args.rounds

    backend = OllamaBackend(model=config.llm.ollama_model, host=config.llm.ollama_host)
    loop = OrchestratorLoop(config, attacker_backend=backend, defender_backend=backend, db_path=args.db)
    summaries = loop.run()

    print(f"\n{'round':>5}  {'attack_success':>14}  {'fp_rate':>8}  {'wcu':>4}  actions")
    for s in summaries:
        actions = ", ".join(s["defender_actions"]) or "-"
        rollbacks = f" rollbacks={s['auto_rollbacks']}" if s["auto_rollbacks"] else ""
        print(f"{s['round']:>5}  {s['attack_success_rate']:>14.2f}  {s['fp_rate']:>8.3f}  {s['wcu_used']:>4}  {actions}{rollbacks}")


def _run_deploy(args) -> None:
    store = RunStore(args.db)
    round_num = args.round or store.max_round()
    snapshot = store.fetch_web_acl_snapshot(round_num)
    store.close()

    if snapshot is None:
        print(f"error: no WebACL snapshot found for round {round_num} in {args.db}", file=sys.stderr)
        sys.exit(1)

    web_acl = WebACL.model_validate(snapshot)

    if args.live and not args.profile:
        print("error: --live requires an explicit --profile (refusing to guess AWS credentials)", file=sys.stderr)
        sys.exit(1)

    deploy_to_aws(
        web_acl,
        name=args.name,
        web_acl_id=args.web_acl_id,
        lock_token=args.lock_token,
        scope=args.scope,
        region=args.region,
        profile=args.profile,
        live=args.live,
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="waf-sandbox")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Run the attacker/defender sandbox")
    demo.add_argument("--rounds", type=int, default=None)
    demo.add_argument("--config", type=str, default=None)
    demo.add_argument("--db", type=str, default=None)

    deploy = sub.add_parser("deploy", help="Translate a run's WebACL snapshot into a real AWS WAFv2 update_web_acl call")
    deploy.add_argument("--db", required=True, help="Path to a run.db produced by `demo`")
    deploy.add_argument("--round", type=int, default=None, help="Round to deploy (defaults to the last round)")
    deploy.add_argument("--name", default="demo-web-acl")
    deploy.add_argument("--scope", default="REGIONAL", choices=["REGIONAL", "CLOUDFRONT"])
    deploy.add_argument("--web-acl-id", required=True, help="The target WebACL's Id in AWS")
    deploy.add_argument("--lock-token", required=True, help="The target WebACL's current LockToken in AWS")
    deploy.add_argument("--region", default=None)
    deploy.add_argument("--profile", default=None, help="AWS named profile; required if --live is set")
    deploy.add_argument("--live", action="store_true", help="Actually call AWS instead of dry-run (default: dry-run)")

    args = parser.parse_args()

    if args.command == "demo":
        _run_demo(args)
    elif args.command == "deploy":
        _run_deploy(args)


if __name__ == "__main__":
    main()
