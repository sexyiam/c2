from __future__ import annotations
import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional


class ChunkStore:
    def __init__(self, ttl: int = 300) -> None:
        self.ttl = ttl
        self._lock = Lock()
        self._data: Dict[str, Dict[int, bytes]] = defaultdict(dict)
        self._meta: Dict[str, Dict[int, int]] = defaultdict(dict)
        self._last: Dict[str, float] = {}

    def add(self, agent_id: str, chunk_id: str, seq: int, total: int, data: bytes) -> Optional[bytes]:
        with self._lock:
            self._last[(agent_id, chunk_id)] = time.time()
            self._meta[(agent_id, chunk_id)][seq] = total
            self._data[(agent_id, chunk_id)][seq] = data
            seen = self._data[(agent_id, chunk_id)]
            if len(seen) == total and len(seen) == len(self._meta[(agent_id, chunk_id)]):
                payload = b"".join(seen[i] for i in range(1, total + 1))
                del self._data[(agent_id, chunk_id)]
                del self._meta[(agent_id, chunk_id)]
                del self._last[(agent_id, chunk_id)]
                return payload
            return None

    def prune(self) -> None:
        now = time.time()
        with self._lock:
            for key in list(self._last.keys()):
                if now - self._last[key] > self.ttl:
                    self._data.pop(key, None)
                    self._meta.pop(key, None)
                    self._last.pop(key, None)
