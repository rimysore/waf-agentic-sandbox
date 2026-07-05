# WAF Red-Team / Blue-Team Agentic Sandbox

A multi-agent sandbox where an **attacker** LLM agent evolves HTTP-level attacks (SQLi, XSS,
credential stuffing, encoding-based evasion) against a small sample app, and a **defender** LLM
agent watches AWS-WAF-realistic sampled logs and metrics and authors real **AWS WAFv2-schema**
rules to stop them -- staging in `COUNT`, checking false-positive rate against a legitimate-traffic
corpus, promoting to `BLOCK`, and auto-rolling-back on regression.

Everything runs **locally and for free**: no AWS account, no Anthropic API key. The agent loop runs
against a local [Ollama](https://ollama.com) model by default.

What makes this more than "an LLM firewall demo": the WAF engine implements a realistic subset of
**real AWS WAFv2 rule statement types** (with the same JSON one-of shape AWS itself uses), **WCU
capacity accounting** against a deliberately tight budget, a **sliding-window rate limiter** with
real window semantics, and **AWS-shaped sampled-request logs**. A rule this sandbox promotes is
structurally close enough to a real WAFv2 rule that `src/live_deploy/boto_apply.py` can translate
it straight into a real `wafv2.update_web_acl` call (dry-run by default).

## Architecture

```
                    ┌─────────────────┐        ┌──────────────────┐
                    │  Attacker agent │        │  Defender agent  │
                    │  (blackbox: only│        │  (sees metrics,  │
                    │  sees status    │        │  sampled logs,   │
                    │  codes/bodies)  │        │  authors rules)  │
                    └────────┬────────┘        └────────┬─────────┘
                             │ send_request                │ propose/replay/
                             │                              │ promote/rollback
                             ▼                              ▼
                    ┌──────────────────────────────────────────────┐
                    │        WAFMiddleware (src/wafsim)             │
                    │  priority-ordered evaluation, WCU budget,     │
                    │  sliding-window rate limit, label chaining    │
                    └───────────────────┬────────────────────────────┘
                                        │ allow/block
                                        ▼
                    ┌──────────────────────────────────────────────┐
                    │   Sample app (src/sampleapp): /login /search  │
                    │   /comments -- naive, has real exploit paths  │
                    └────────────────────────────────────────────────┘

  Orchestrator loop (src/orchestrator/loop.py) ties rounds together:
  attacker round -> legit traffic replay -> auto regression check ->
  defender round -> persist everything to SQLite (run.db)

  Dashboard (src/dashboard) reads run.db      Live deploy (src/live_deploy)
  live or as a replay -- same code path       translates a WebACL snapshot into
                                               real AWS WAFv2 JSON, dry-run by default
```

## The demo narrative

The starting ("seed") WebACL is deliberately imperfect, not empty:

1. **Round 1** -- `generic-sqli-basic` and `generic-xss-basic` rules exist but only have
   `TextTransformations=[NONE]` -- they never URL-decode. A URL-encoded payload (e.g. `admin%27--`
   in a login POST body) sails straight through and triggers a real SQL-injection auth bypass in
   the sample app. The defender sees this in the sampled logs and metrics, stages a fixed rule with
   `URL_DECODE` added, replays it against the legit-traffic corpus (0% false positives), and
   promotes it.
2. **Round 2** -- same story for XSS.
3. **Round 3** -- there's no rate-based rule at all in the seed ACL. The defender has to notice
   credential-stuffing volume from a single IP purely from metrics and author a `RateBasedStatement`
   rule from scratch -- the genuinely emergent part of the demo (not seeded).
4. **Rounds 4+** -- attack success rate converges to 0%, false-positive rate stays ~0%, and the run
   stops automatically.

Every rule promotion is guardrailed **in code, not trusted to the model**: `propose_rule` rejects a
rule that would exceed the WCU capacity budget, `promote_rule` rejects a rule whose false-positive
rate against the legit corpus exceeds the threshold (default 1%), and every round the orchestrator
independently re-checks every currently-promoted rule and auto-rolls-back anything whose FP rate has
crept up -- a safety net that runs whether or not the defender agent notices.

## Quickstart

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# unit + integration tests (no LLM required, ~1s)
python -m pytest tests/ -v

# pull a tool-calling-capable local model (one-time)
ollama pull llama3.2

# run the real thing against your local Ollama
python -m src.cli demo --rounds 8

# or generate a fast, deterministic "golden run" with no LLM at all
python -m scripts.generate_golden_run

# view either run in the dashboard
python -m src.dashboard.server --db data/golden_run.db
# -> http://127.0.0.1:8050
```

`src/dev_server.py` also runs the wired sample-app+WAF stack standalone (`python -m src.dev_server`,
serves on `:8000`) if you just want to poke at the app+WAF with curl.

### Optional: Docker

Not required for anything above, but there's a `docker-compose.yml` for a fully containerized path
(verified working end-to-end: image builds, `ollama` service pulls/serves the model, `sandbox` runs
a real round-trip against it, `dashboard` serves the result via the mapped port):

```bash
docker compose up -d ollama
docker compose exec ollama ollama pull llama3.2
docker compose run --rm sandbox python -m src.cli demo --rounds 15 --db data/run.db
docker compose up -d dashboard   # -> http://127.0.0.1:8050
```

## Project layout

| Path | What |
|---|---|
| `src/wafsim/` | Pure-logic WAF engine: schema, statement evaluation, WCU costing, rate limiting, AWS-shaped logging/metrics. Zero I/O, zero LLM -- the credibility core. |
| `src/sampleapp/` | The naive target app (`/login` SQLi bypass, `/search` + `/comments` unescaped XSS). |
| `src/llm/` | Backend-agnostic tool-calling loop; Ollama backend (real) and a scripted backend (tests/golden run). |
| `src/attacker/`, `src/defender/` | The two agents and their tools. `defender/promotion.py` is the stage/promote/rollback/retire state machine. |
| `src/orchestrator/` | The round loop and SQLite persistence. |
| `src/corpus/` | The legitimate-traffic seed corpus (includes deliberate false-positive bait) and per-round generator. |
| `src/dashboard/` | Read-only FastAPI + single-page UI over a `run.db`. |
| `src/live_deploy/` | Translates our schema into real AWS WAFv2 JSON; optional `--live` boto3 call. |
| `scripts/generate_golden_run.py` | Deterministic scripted run for a reliable, LLM-free demo/dashboard fixture. |

## Scope / known limitations

- Implements a realistic **subset** of WAFv2 statement types (byte/SQLi/XSS/size-constraint/geo/
  IP-set/regex-set/rate-based/label-match/and/or/not). Deliberately **not** implemented: Managed
  Rule Groups, CAPTCHA/Challenge actions, JA3/JA4 fingerprint statements, ASN match.
- SQLi/XSS detection is a documented heuristic (regex-based), not AWS's proprietary detection --
  good enough to demonstrate encoding-evasion/detection-gap dynamics, not a real WAF's ML-assisted
  matching.
- WCU costs are a snapshot of AWS's published per-statement costs and should be re-verified against
  current AWS pricing docs before being treated as authoritative.
- `llama3.2:3b` (the default free local model) is small; a short run may only get partway through
  the fix/promote workflow. The mechanism itself is proven correct independent of model quality by
  `tests/test_smoke_run.py`, which runs the full loop with a deterministic scripted agent.
- `--live` deploy is real and untested against an actual AWS account in this project (no AWS access
  was available) -- the JSON translation is unit-tested for shape correctness, but treat it as a
  starting point for a real deploy, not a certified integration.

## Testing

```bash
python -m pytest tests/ -v
```

All tests are fast and free (no network, no LLM) -- including `test_smoke_run.py`, which drives the
entire attacker/defender/orchestrator loop with deterministic scripted backends and asserts
convergence, promotion, and guardrail behavior end-to-end.
