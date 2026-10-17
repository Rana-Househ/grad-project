import json
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple


class DDoSEngine:
    def __init__(self, policy_path: str):
        policy_file = Path(policy_path)
        if not policy_file.exists():
            raise FileNotFoundError(f"DDoS policy not found: {policy_file}")

        data = json.loads(policy_file.read_text(encoding="utf-8"))

        self.window_seconds = int(data.get("window_seconds", 10))
        self.threshold_packets = int(data.get("threshold_packets", 60))
        self.block_seconds = int(data.get("block_seconds", 30))
        self.priority = int(data.get("priority", 260))

        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.threshold_packets <= 0:
            raise ValueError("threshold_packets must be > 0")
        if self.block_seconds <= 0:
            raise ValueError("block_seconds must be > 0")
        if self.priority <= 0:
            raise ValueError("priority must be > 0")

        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._blocked_until: Dict[str, float] = {}

    def _now(self) -> float:
        return time.monotonic()

    def is_blocked(self, src_ip: str) -> bool:
        return self._now() < self._blocked_until.get(src_ip, 0.0)

    def observe_and_decide(self, src_ip: str) -> Tuple[bool, Optional[int], Optional[int]]:
        now = self._now()

        blocked_until = self._blocked_until.get(src_ip, 0.0)
        if now < blocked_until:
            remaining = int(blocked_until - now)
            return True, self.priority, max(1, remaining)

        q = self._events[src_ip]
        q.append(now)

        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= self.threshold_packets:
            self._blocked_until[src_ip] = now + self.block_seconds
            q.clear()
            return True, self.priority, self.block_seconds

        return False, None, None
