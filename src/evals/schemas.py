"""Pydantic schemas the attacker's round-end report is graded against.
Kept separate from src/attacker/agent.py's SYSTEM_PROMPT (the source of
truth for what the model is told to produce) so the eval schema can be
diffed against the prompt if they ever drift."""
from __future__ import annotations

from pydantic import BaseModel


class AttackerRoundReport(BaseModel):
    success_rate: float
    top_blocked_patterns: list[str]
    next_round_hypothesis: str
