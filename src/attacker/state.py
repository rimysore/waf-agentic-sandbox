"""Shared small data shapes for the attacker agent."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Outcome:
    category: str
    path: str
    status_code: int
    blocked: bool
    exploited: bool
