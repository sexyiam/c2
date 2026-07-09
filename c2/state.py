"""Agent registry and task store backed by SQLite (durable across restarts)."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .db import Database, default_db_path


@dataclass
class Task:
    task_id: str
    agent_id: str
    cmd: str
    args: list[str] = field(default_factory=list)
    result: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    @property
    def done(self) -> bool:
        return self.result is not None


@dataclass
class Agent:
    agent_id: str
    hostname: str
    username: str
    os: str
    session_key: bytes
    registered_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def touch(self) -> None:
        self.last_seen = time.time()

    @property
    def stale_seconds(self) -> float:
        return time.time() - self.last_seen


class State:
    """Thread-safe shared state for the listener and the operator CLI."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._lock = threading.RLock()
        self._db = Database(db_path or default_db_path())
        self.agents: dict[str, Agent] = {}
        self.tasks: dict[str, Task] = {}
        self.queues: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        for row in self._db.load_agents():
            self.agents[row["agent_id"]] = Agent(
                agent_id=row["agent_id"],
                hostname=row["hostname"],
                username=row["username"],
                os=row["os"],
                session_key=bytes(row["session_key"]),
                registered_at=row["registered_at"],
                last_seen=row["last_seen"],
            )
        for row in self._db.load_tasks():
            args = json.loads(row["args_json"] or "[]")
            self.tasks[row["task_id"]] = Task(
                task_id=row["task_id"],
                agent_id=row["agent_id"],
                cmd=row["cmd"],
                args=list(args),
                result=row["result"],
                created_at=row["created_at"],
                completed_at=row["completed_at"],
            )
        for agent_id, task_id in self._db.load_queues():
            self.queues.setdefault(agent_id, []).append(task_id)
        for aid in self.agents:
            self.queues.setdefault(aid, [])

    # ---- agents -----------------------------------------------------------
    def register_agent(self, agent: Agent) -> None:
        with self._lock:
            self.agents[agent.agent_id] = agent
            self.queues.setdefault(agent.agent_id, [])
            self._db.upsert_agent_row(
                agent.agent_id,
                agent.hostname,
                agent.username,
                agent.os,
                agent.session_key,
                agent.registered_at,
                agent.last_seen,
            )

    def get_agent(self, agent_id: str) -> Optional[Agent]:
        with self._lock:
            return self.agents.get(agent_id)

    def list_agents(self) -> list[Agent]:
        with self._lock:
            return list(self.agents.values())

    def remove_agent(self, agent_id: str) -> bool:
        with self._lock:
            if agent_id not in self.agents:
                return False
            self.agents.pop(agent_id, None)
            self.queues.pop(agent_id, None)
            drop = [tid for tid, t in self.tasks.items() if t.agent_id == agent_id]
            for tid in drop:
                self.tasks.pop(tid, None)
            self._db.remove_agent(agent_id)
            return True

    def touch_agent(self, agent: Agent) -> None:
        agent.touch()
        with self._lock:
            self._db.touch_agent(agent.agent_id, agent.last_seen)

    def set_session_key(self, agent: Agent, key: bytes) -> None:
        agent.session_key = key
        with self._lock:
            self._db.update_session_key(agent.agent_id, key)

    # ---- tasks ------------------------------------------------------------
    def enqueue(self, agent_id: str, task_id: str, cmd: str, args: list[str]) -> Task:
        task = Task(task_id=task_id, agent_id=agent_id, cmd=cmd, args=args)
        with self._lock:
            self.tasks[task_id] = task
            self.queues.setdefault(agent_id, []).append(task_id)
            self._db.upsert_task_row(
                task.task_id,
                task.agent_id,
                task.cmd,
                task.args,
                task.result,
                task.created_at,
                task.completed_at,
            )
            self._db.enqueue(agent_id, task_id)
        return task

    def pop_next_task(self, agent_id: str) -> Optional[Task]:
        with self._lock:
            q = self.queues.get(agent_id)
            if q:
                task_id = q.pop(0)
            else:
                task_id = self._db.dequeue(agent_id)
                if not task_id:
                    return None
                return self.tasks.get(task_id)
            # Keep SQLite queue aligned with the in-memory FIFO.
            db_tid = self._db.dequeue(agent_id)
            if db_tid and db_tid != task_id:
                # Rare desync: prefer the in-memory id already popped.
                pass
            return self.tasks.get(task_id)

    def submit_result(self, task_id: str, result: str) -> bool:
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False
            task.result = result
            task.completed_at = time.time()
            self._db.upsert_task_row(
                task.task_id,
                task.agent_id,
                task.cmd,
                task.args,
                task.result,
                task.created_at,
                task.completed_at,
            )
            return True

    def list_tasks(self, agent_id: Optional[str] = None) -> list[Task]:
        with self._lock:
            tasks = list(self.tasks.values())
        if agent_id:
            tasks = [t for t in tasks if t.agent_id == agent_id]
        return sorted(tasks, key=lambda t: t.created_at)
