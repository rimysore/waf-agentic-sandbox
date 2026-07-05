"""The defender agent: watches metrics/sampled logs and authors real
WAFv2-shaped rules to stop what it sees, following AWS best practice --
stage in COUNT, replay against legit traffic, only promote if the
false-positive rate is acceptable, and consolidate rather than freely
stack rules given a tight WCU budget."""
from __future__ import annotations

from src.llm.base import LLMBackend, ToolSpec, run_agent_loop

from .tools import DefenderTools

SYSTEM_PROMPT = """You are the defending WAF engineer. You watch sampled request logs and per-rule metrics
for a small web app and author AWS WAFv2-style rules to stop attacks, without breaking legitimate traffic.

Follow this workflow every time you consider a change:
1. Call get_metrics_summary and get_recent_sampled_logs to see what's happening. Legitimate traffic comes
   from the 198.51.100.0/24 IP range; suspicious/attack traffic tends to come from 203.0.113.0/24.
2. If you see a gap (e.g. a rule with TextTransformations=["NONE"] that a URL-encoded payload is getting
   past, or login attempts with no rate limiting), call propose_rule with a new rule as a JSON string. This
   always stages the rule in COUNT mode first (it can never go straight to BLOCK), and is rejected if it
   would exceed the WCU capacity budget -- if rejected, simplify or retire something else first.
3. Call replay_against_legit_corpus(rule_name) to check the false-positive rate before promoting.
4. Only call promote_rule(rule_name) if the FP rate looks acceptable -- it will be rejected automatically
   if it's not, and you should NOT keep retrying the same rule unchanged.
5. If a previously-promoted rule turns out to have a high FP rate, call rollback_rule to demote it back to
   COUNT rather than leaving it blocking legitimate users.
6. Prefer fixing/consolidating existing rules over stacking many new ones -- the WCU budget is tight.

The Rule JSON schema (snake_case field names, exactly one key set inside "statement"):
{
  "name": "fix-sqli-url-decode",
  "priority": 11,
  "statement": {
    "or_statement": {
      "statements": [
        {"sqli_match_statement": {"field_to_match": {"type": "QUERY_STRING"}, "text_transformations": ["URL_DECODE"]}},
        {"sqli_match_statement": {"field_to_match": {"type": "BODY"}, "text_transformations": ["URL_DECODE"]}}
      ]
    }
  },
  "action": "BLOCK",
  "rule_labels": [],
  "visibility_config": {"metric_name": "fixSqliUrlDecode"}
}

A rate-limit rule for credential stuffing (no scope_down_statement needed to rate-limit everything by IP):
{
  "name": "rate-limit-login-bursts",
  "priority": 5,
  "statement": {"rate_based_statement": {"limit": 20, "evaluation_window_sec": 60}},
  "action": "BLOCK",
  "rule_labels": [],
  "visibility_config": {"metric_name": "rateLimitLoginBursts"}
}

Other statement types available: byte_match_statement, xss_match_statement, size_constraint_statement,
geo_match_statement, ip_set_reference_statement, regex_pattern_set_reference_statement,
label_match_statement, and_statement, not_statement. TextTransformations you can use: NONE, LOWERCASE,
URL_DECODE, HTML_ENTITY_DECODE, COMPRESS_WHITE_SPACE, CMD_LINE.

When you're done acting for this round, respond with a short one-sentence plain-text summary of what you
did and why (not JSON).
"""


class DefenderAgent:
    def __init__(self, backend: LLMBackend, tools: DefenderTools):
        self.backend = backend
        self.tools = tools

    def _tool_specs(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="get_metrics_summary",
                description="Get cumulative Allowed/Blocked/Counted counts per rule across the whole run so far.",
                parameters={"type": "object", "properties": {}},
                handler=self.tools.get_metrics_summary,
            ),
            ToolSpec(
                name="get_recent_sampled_logs",
                description="Get the last N AWS-WAF-shaped sampled request logs from this round.",
                parameters={"type": "object", "properties": {"n": {"type": "integer"}}},
                handler=self.tools.get_recent_sampled_logs,
            ),
            ToolSpec(
                name="get_current_web_acl",
                description="Get the full current WebACL (all rules, priorities, actions) as JSON.",
                parameters={"type": "object", "properties": {}},
                handler=self.tools.get_current_web_acl,
            ),
            ToolSpec(
                name="propose_rule",
                description="Stage a new rule (always starts in COUNT mode) as JSON text matching the Rule schema.",
                parameters={
                    "type": "object",
                    "properties": {"rule_json": {"type": "string", "description": "The Rule as JSON text."}},
                    "required": ["rule_json"],
                },
                handler=self.tools.propose_rule,
            ),
            ToolSpec(
                name="replay_against_legit_corpus",
                description="Compute the false-positive rate of a staged/promoted rule against this round's legit traffic.",
                parameters={"type": "object", "properties": {"rule_name": {"type": "string"}}, "required": ["rule_name"]},
                handler=self.tools.replay_against_legit_corpus,
            ),
            ToolSpec(
                name="promote_rule",
                description="Promote a staged rule from COUNT to BLOCK. Rejected automatically if FP rate is too high.",
                parameters={"type": "object", "properties": {"rule_name": {"type": "string"}}, "required": ["rule_name"]},
                handler=self.tools.promote_rule,
            ),
            ToolSpec(
                name="rollback_rule",
                description="Demote a rule from BLOCK back to COUNT.",
                parameters={
                    "type": "object",
                    "properties": {"rule_name": {"type": "string"}, "reason": {"type": "string"}},
                    "required": ["rule_name"],
                },
                handler=self.tools.rollback_rule,
            ),
            ToolSpec(
                name="retire_rule",
                description="Remove a rule entirely (e.g. to free WCU budget for a consolidated replacement).",
                parameters={"type": "object", "properties": {"rule_name": {"type": "string"}}, "required": ["rule_name"]},
                handler=self.tools.retire_rule,
            ),
        ]

    def run_round(self, round_num: int) -> dict:
        user_prompt = (
            f"Round {round_num}. Review this round's traffic and metrics, and make any rule changes you think "
            f"are warranted. Current WCU budget: {self.tools.engine_state.web_acl.max_capacity_wcu}."
        )
        messages = run_agent_loop(self.backend, SYSTEM_PROMPT, user_prompt, self._tool_specs(), max_iterations=12)
        final_text = messages[-1]["content"] if messages else ""
        return {"notes": final_text, "actions_taken": list(self.tools.actions_taken)}
