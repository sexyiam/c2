"""SQLite persistence for agents, tasks, and per-agent queues."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional


def default_db_path() -> Path:
    env = os.environ.get("C2_DB")
    if env:
        return Path(env)
    root = Path(__file__).resolve().parent / "data"
    root.mkdir(parents=True, exist_ok=True)
    return root / "c2.db"


class Database:
    """Thin SQLite wrapper used by State."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    os TEXT NOT NULL,
                    session_key BLOB NOT NULL,
                    registered_at REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    cmd TEXT NOT NULL,
                    args_json TEXT NOT NULL,
                    result TEXT,
                    created_at REAL NOT NULL,
                    completed_at REAL
                );
                CREATE TABLE IF NOT EXISTS queues (
                    agent_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    PRIMARY KEY (agent_id, task_id)
                );
                """
            )
            self._conn.commit()

    def load_agents(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute("SELECT * FROM agents")]

    def load_tasks(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute("SELECT * FROM tasks")]

    def load_queues(self) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT agent_id, task_id FROM queues ORDER BY agent_id, seq"
            )
            return [(r["agent_id"], r["task_id"]) for r in rows]

    def upsert_agent_row(
        self,
        agent_id: str,
        hostname: str,
        username: str,
        os_name: str,
        session_key: bytes,
        registered_at: float,
        last_seen: float,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO agents(agent_id, hostname, username, os, session_key,
                                   registered_at, last_seen)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    username=excluded.username,
                    os=excluded.os,
                    session_key=excluded.session_key,
                    registered_at=excluded.registered_at,
                    last_seen=excluded.last_seen
                """,
                (
                    agent_id,
                    hostname,
                    username,
                    os_name,
                    session_key,
                    registered_at,
                    last_seen,
                ),
            )
            self._conn.commit()

    def touch_agent(self, agent_id: str, last_seen: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE agents SET last_seen=? WHERE agent_id=?",
                (last_seen, agent_id),
            )
            self._conn.commit()

    def update_session_key(self, agent_id: str, session_key: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE agents SET session_key=? WHERE agent_id=?",
                (session_key, agent_id),
            )
            self._conn.commit()

    def remove_agent(self, agent_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM queues WHERE agent_id=?", (agent_id,))
            self._conn.execute("DELETE FROM tasks WHERE agent_id=?", (agent_id,))
            self._conn.execute("DELETE FROM agents WHERE agent_id=?", (agent_id,))
            self._conn.commit()

    def upsert_task_row(
        self,
        task_id: str,
        agent_id: str,
        cmd: str,
        args: list[str],
        result: Optional[str],
        created_at: float,
        completed_at: Optional[float],
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tasks(task_id, agent_id, cmd, args_json, result,
                                  created_at, completed_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(task_id) DO UPDATE SET
                    result=excluded.result,
                    completed_at=excluded.completed_at
                """,
                (
                    task_id,
                    agent_id,
                    cmd,
                    json.dumps(args),
                    result,
                    created_at,
                    completed_at,
                ),
            )
            self._conn.commit()

    def enqueue(self, agent_id: str, task_id: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM queues WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
            seq = int(row["n"]) if row else 0
            self._conn.execute(
                "INSERT OR REPLACE INTO queues(agent_id, task_id, seq) VALUES(?,?,?)",
                (agent_id, task_id, seq),
            )
            self._conn.commit()

    def dequeue(self, agent_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT task_id FROM queues WHERE agent_id=? ORDER BY seq LIMIT 1",
                (agent_id,),
            ).fetchone()
            if not row:
                return None
            tid = row["task_id"]
            self._conn.execute(
                "DELETE FROM queues WHERE agent_id=? AND task_id=?",
                (agent_id, tid),
            )
            self._conn.commit()
            return tid

    def close(self) -> None:
        with self._lock:
            self._conn.close()
