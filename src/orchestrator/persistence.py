"""SQLite persistence for a demo run: per-round metrics, rule-change audit
trail, WebACL version snapshots, and sampled logs. A single run.db file is
both the live-run write target and the artifact a dashboard/replay would
read from -- same schema either way."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from src.wafsim.schema import WebACL
from src.wafsim.wcu import web_acl_capacity

SCHEMA = """
CREATE TABLE IF NOT EXISTS rounds (
    round_num INTEGER PRIMARY KEY,
    started_at REAL,
    ended_at REAL,
    attack_success_rate REAL,
    fp_rate REAL,
    wcu_used INTEGER
);
CREATE TABLE IF NOT EXISTS web_acl_versions (
    round_num INTEGER,
    web_acl_json TEXT,
    capacity INTEGER
);
CREATE TABLE IF NOT EXISTS rule_change_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    round_num INTEGER,
    event_type TEXT,
    rule_name TEXT,
    detail_json TEXT,
    justification TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS sampled_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    round_num INTEGER,
    log_json TEXT
);
CREATE TABLE IF NOT EXISTS metrics_timeseries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    round_num INTEGER,
    rule_name TEXT,
    allowed INTEGER,
    blocked INTEGER,
    counted INTEGER
);
CREATE TABLE IF NOT EXISTS attacker_memory (
    round_num INTEGER PRIMARY KEY,
    report_json TEXT
);
CREATE TABLE IF NOT EXISTS defender_memory (
    round_num INTEGER PRIMARY KEY,
    notes_json TEXT
);
"""


class RunStore:
    def __init__(self, db_path: str):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def start_round(self, round_num: int) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO rounds (round_num, started_at) VALUES (?, ?)", (round_num, time.time())
        )
        self.conn.commit()

    def end_round(self, round_num: int, attack_success_rate: float, fp_rate: float, wcu_used: int) -> None:
        self.conn.execute(
            "UPDATE rounds SET ended_at=?, attack_success_rate=?, fp_rate=?, wcu_used=? WHERE round_num=?",
            (time.time(), attack_success_rate, fp_rate, wcu_used, round_num),
        )
        self.conn.commit()

    def save_web_acl_snapshot(self, round_num: int, web_acl: WebACL) -> None:
        self.conn.execute(
            "INSERT INTO web_acl_versions (round_num, web_acl_json, capacity) VALUES (?, ?, ?)",
            (round_num, web_acl.model_dump_json(), web_acl_capacity(web_acl)),
        )
        self.conn.commit()

    def record_rule_change(self, round_num: int, event_type: str, rule_name: str, detail: dict, justification: str = "") -> None:
        self.conn.execute(
            "INSERT INTO rule_change_events (round_num, event_type, rule_name, detail_json, justification, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (round_num, event_type, rule_name, json.dumps(detail), justification, time.time()),
        )
        self.conn.commit()

    def record_sampled_logs_batch(self, round_num: int, logs: list[dict]) -> None:
        if not logs:
            return
        self.conn.executemany(
            "INSERT INTO sampled_logs (round_num, log_json) VALUES (?, ?)",
            [(round_num, json.dumps(log)) for log in logs],
        )
        self.conn.commit()

    def record_metrics(self, round_num: int, metrics_by_rule: dict[str, dict[str, int]]) -> None:
        rows = [
            (round_num, rule, counts.get("ALLOWED", 0), counts.get("BLOCKED", 0), counts.get("COUNTED", 0))
            for rule, counts in metrics_by_rule.items()
        ]
        if not rows:
            return
        self.conn.executemany(
            "INSERT INTO metrics_timeseries (round_num, rule_name, allowed, blocked, counted) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        self.conn.commit()

    def save_attacker_memory(self, round_num: int, report: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO attacker_memory (round_num, report_json) VALUES (?, ?)",
            (round_num, json.dumps(report)),
        )
        self.conn.commit()

    def save_defender_memory(self, round_num: int, notes: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO defender_memory (round_num, notes_json) VALUES (?, ?)",
            (round_num, json.dumps(notes)),
        )
        self.conn.commit()

    def fetch_rounds(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT round_num, started_at, ended_at, attack_success_rate, fp_rate, wcu_used FROM rounds ORDER BY round_num"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def fetch_rule_changes(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT round_num, event_type, rule_name, detail_json, justification, created_at "
            "FROM rule_change_events ORDER BY id"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def fetch_metrics(self) -> list[dict]:
        cur = self.conn.execute(
            "SELECT round_num, rule_name, allowed, blocked, counted FROM metrics_timeseries ORDER BY round_num, id"
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def fetch_sampled_logs(self, round_num: int, limit: int = 50) -> list[dict]:
        cur = self.conn.execute(
            "SELECT log_json FROM sampled_logs WHERE round_num=? ORDER BY id DESC LIMIT ?",
            (round_num, limit),
        )
        return [json.loads(row[0]) for row in cur.fetchall()]

    def fetch_web_acl_snapshot(self, round_num: int) -> dict | None:
        cur = self.conn.execute(
            "SELECT web_acl_json FROM web_acl_versions WHERE round_num=? ORDER BY rowid DESC LIMIT 1",
            (round_num,),
        )
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def fetch_attacker_memory(self, round_num: int) -> dict | None:
        cur = self.conn.execute("SELECT report_json FROM attacker_memory WHERE round_num=?", (round_num,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def fetch_defender_memory(self, round_num: int) -> dict | None:
        cur = self.conn.execute("SELECT notes_json FROM defender_memory WHERE round_num=?", (round_num,))
        row = cur.fetchone()
        return json.loads(row[0]) if row else None

    def max_round(self) -> int:
        cur = self.conn.execute("SELECT MAX(round_num) FROM rounds")
        row = cur.fetchone()
        return row[0] or 0

    def close(self) -> None:
        self.conn.close()
