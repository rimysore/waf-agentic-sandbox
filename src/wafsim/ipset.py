"""In-memory IPSet / RegexPatternSet stores, referenced by id from statements
(mirrors AWS WAFv2's separate IPSet/RegexPatternSet resources referenced by ARN/id)."""
from __future__ import annotations

import ipaddress
import re


class IPSetStore:
    def __init__(self):
        self._sets: dict[str, list[str]] = {}

    def put(self, ip_set_id: str, addresses: list[str]) -> None:
        self._sets[ip_set_id] = list(addresses)

    def contains(self, ip_set_id: str, ip: str) -> bool:
        addresses = self._sets.get(ip_set_id, [])
        try:
            target = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in addresses:
            try:
                if target in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def get(self, ip_set_id: str) -> list[str]:
        return list(self._sets.get(ip_set_id, []))

    def ids(self) -> list[str]:
        return list(self._sets.keys())


class RegexPatternSetStore:
    def __init__(self):
        self._sets: dict[str, list[re.Pattern]] = {}

    def put(self, regex_set_id: str, patterns: list[str]) -> None:
        self._sets[regex_set_id] = [re.compile(p) for p in patterns]

    def matches(self, regex_set_id: str, value: str) -> bool:
        return any(p.search(value) for p in self._sets.get(regex_set_id, []))

    def ids(self) -> list[str]:
        return list(self._sets.keys())
