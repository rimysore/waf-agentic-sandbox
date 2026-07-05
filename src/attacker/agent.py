"""The attacker agent: reasons about what got blocked/allowed last round and
adapts its strategy. The concrete adaptation mechanism is a structured JSON
after-action report at the end of every round, persisted and fed back into
the next round's prompt -- not hand-waved."""
from __future__ import annotations

import json

from src.llm.base import LLMBackend, ToolSpec, run_agent_loop

from .tools import AttackerTools

SYSTEM_PROMPT = """You are a red-team agent attacking a small web app that sits behind an AWS-style WAF.

You are blackbox: you only see HTTP status codes and response bodies -- never WAF rule IDs or internals,
exactly like a real external attacker would.

Goals:
- /login: find a SQL-injection authentication bypass. Classic tautologies like admin'-- or ' OR '1'='1
  sometimes work if sent raw, but a WAF may catch the raw payload -- try URL-encoding it instead
  (e.g. %27 for the quote) since some WAF rules forget to URL-decode before inspecting.
- /search and /comments: get an XSS payload (e.g. <script>alert(1)</script>) accepted -- they reflect
  input with no sanitization, so success just means the request wasn't blocked.
- Also probe /login with a rapid burst of plain login attempts (category "credential_stuffing") to test
  whether there's any rate limiting at all.
- If a category gets blocked, try encoding/case/whitespace variations of the same idea before giving up
  on it, and prefer categories that got through last round.

Use the send_request tool repeatedly -- you have a limited budget this round, shown in the prompt.
When your budget is spent (or you've learned what you need), respond with ONLY a JSON object, no other
text, exactly shaped like:
{"success_rate": <number 0..1>, "top_blocked_patterns": ["..."], "next_round_hypothesis": "<1-2 sentences>"}
"""


class AttackerAgent:
    def __init__(self, backend: LLMBackend, tools: AttackerTools):
        self.backend = backend
        self.tools = tools
        self.memory: list[dict] = []

    def _tool_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="send_request",
                description="Send one HTTP request through the WAF at the target app and observe the outcome.",
                parameters={
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "enum": ["sqli", "xss", "credential_stuffing", "encoding_evasion"],
                        },
                        "method": {"type": "string", "enum": ["GET", "POST"]},
                        "path": {"type": "string", "enum": ["/login", "/search", "/comments"]},
                        "query": {"type": "string", "description": "raw query string, e.g. q=..."},
                        "body": {"type": "string", "description": "raw request body"},
                        "content_type": {"type": "string"},
                        "source_ip": {"type": "string", "description": "optional spoofed source IP"},
                    },
                    "required": ["category", "method", "path"],
                },
                handler=self.tools.send_request,
            ),
            ToolSpec(
                name="get_recent_outcomes",
                description="Get your last N request outcomes this round.",
                parameters={"type": "object", "properties": {"n": {"type": "integer"}}},
                handler=self.tools.get_recent_outcomes,
            ),
            ToolSpec(
                name="list_attack_categories",
                description="List the attack categories available to you.",
                parameters={"type": "object", "properties": {}},
                handler=self.tools.list_attack_categories,
            ),
        ]

    def run_round(self, round_num: int) -> dict:
        prior = self.memory[-1] if self.memory else None
        user_prompt = f"Round {round_num}. Your request budget this round is {self.tools.budget}.\n"
        if prior:
            user_prompt += (
                f"Last round's success rate: {prior.get('success_rate')}. "
                f"Your hypothesis going into this round: {prior.get('next_round_hypothesis')}\n"
            )
        else:
            user_prompt += "This is your first round -- try a mix of raw and encoded payloads across all endpoints.\n"

        messages = run_agent_loop(
            self.backend, SYSTEM_PROMPT, user_prompt, self._tool_specs(), max_iterations=self.tools.budget + 4
        )
        final_text = messages[-1]["content"] if messages else ""
        report = self._parse_report(final_text)
        self.memory.append(report)
        return report

    def _parse_report(self, text: str) -> dict:
        try:
            start = text.index("{")
            end = text.rindex("}") + 1
            parsed = json.loads(text[start:end])
            if "success_rate" in parsed:
                return parsed
        except Exception:
            pass
        # Fallback: derive ground truth directly from this round's tool outcomes
        # rather than trusting the model to have summarized itself correctly.
        outcomes = self.tools.outcomes
        success_rate = (sum(1 for o in outcomes if o.exploited) / len(outcomes)) if outcomes else 0.0
        return {
            "success_rate": success_rate,
            "top_blocked_patterns": [],
            "next_round_hypothesis": "(no parseable report from model; derived from raw outcomes)",
        }
