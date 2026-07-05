"""Generates per-round legitimate traffic from the seed corpus, with
randomized (but reproducible, RNG-seeded) source IPs/user-agents drawn from
a pool disjoint from the attacker's, so logs can be triaged by IP range the
same way a real analyst would separate probe traffic from real users."""
from __future__ import annotations

import json
import random
from pathlib import Path

from src.wafsim.schema import HttpRequest

SEED_PATH = Path(__file__).parent / "legit_seed.json"

# TEST-NET-1 + TEST-NET-2 (RFC 5737) -- deliberately disjoint from the
# attacker's TEST-NET-3 pool (203.0.113.0/24) used in orchestrator/loop.py.
# A wide pool (~500 addresses) keeps incidental IP reuse across many rounds
# of legit traffic rare, so a rate-based rule doesn't mistake "the same
# handful of real users happened to share an IP" for a burst.
LEGIT_IP_POOL = [f"192.0.2.{i}" for i in range(2, 254)] + [f"198.51.100.{i}" for i in range(2, 254)]

LEGIT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]


def load_seed() -> list[dict]:
    return json.loads(SEED_PATH.read_text())


def generate_round_traffic(count: int, rng: random.Random) -> list[HttpRequest]:
    seed = load_seed()
    requests = []
    for _ in range(count):
        entry = rng.choice(seed)
        headers = {"user-agent": rng.choice(LEGIT_USER_AGENTS)}
        if entry.get("content_type"):
            headers["content-type"] = entry["content_type"]
        requests.append(
            HttpRequest(
                client_ip=rng.choice(LEGIT_IP_POOL),
                country="US",
                method=entry["method"],
                uri_path=entry["path"],
                query_string=entry.get("query", ""),
                body=entry.get("body", ""),
                headers=headers,
            )
        )
    return requests
