"""Tool implementations bound to a live client against the wired app. The
attacker is blackbox by design: it only sees HTTP status codes and response
bodies -- never WAF rule IDs -- exactly like a real external attacker."""
from __future__ import annotations

import random

from starlette.testclient import TestClient

from .state import Outcome

ATTACK_CATEGORIES = ["sqli", "xss", "credential_stuffing", "encoding_evasion"]


class AttackerTools:
    def __init__(self, client: TestClient, budget: int, source_ip_pool: list[str]):
        self.client = client
        self.budget = budget
        self.used = 0
        self.outcomes: list[Outcome] = []
        self.source_ip_pool = source_ip_pool
        self._rng = random.Random()

    def send_request(
        self,
        category: str,
        method: str,
        path: str,
        query: str = "",
        body: str = "",
        content_type: str = "application/json",
        source_ip: str | None = None,
    ) -> dict:
        if self.used >= self.budget:
            return {"error": "request budget exhausted for this round"}
        self.used += 1

        ip = source_ip or self._rng.choice(self.source_ip_pool)
        headers = {"x-demo-source-ip": ip}
        if content_type:
            headers["content-type"] = content_type
        url = path + (f"?{query}" if query else "")

        try:
            resp = self.client.request(method.upper(), url, content=body.encode() if body else None, headers=headers)
        except Exception as e:  # malformed request from the model -- surface as a normal outcome, don't crash the round
            outcome = Outcome(category=category, path=path, status_code=0, blocked=False, exploited=False)
            self.outcomes.append(outcome)
            return {"error": str(e)}

        blocked = resp.status_code == 403
        exploited = self._check_exploited(category, path, resp)
        outcome = Outcome(category=category, path=path, status_code=resp.status_code, blocked=blocked, exploited=exploited)
        self.outcomes.append(outcome)
        return {
            "status_code": resp.status_code,
            "blocked": blocked,
            "exploited": exploited,
            "body_snippet": resp.text[:200],
        }

    def _check_exploited(self, category: str, path: str, resp) -> bool:
        if resp.status_code == 403:
            return False
        if category == "sqli" and path.startswith("/login"):
            try:
                return resp.json().get("via") == "sqli-bypass"
            except Exception:
                return False
        # xss / encoding_evasion / credential_stuffing / other sqli probes:
        # "success" means the payload reached the naive app unfiltered.
        return True

    def get_recent_outcomes(self, n: int = 10) -> list[dict]:
        return [o.__dict__ for o in self.outcomes[-n:]]

    def list_attack_categories(self) -> list[str]:
        return list(ATTACK_CATEGORIES)
