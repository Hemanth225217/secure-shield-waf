import time
from typing import Dict, List, Tuple
from fastapi import Request, HTTPException

class SlidingWindowRateLimiter:
    def __init__(self, default_limit: int = 30, window_seconds: int = 10):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}
        self.strike_counts: Dict[str, int] = {}

    def is_allowed(self, client_ip: str, limit: int = None, window: int = None) -> Tuple[bool, int, int]:
        """
        Returns (allowed: bool, current_count: int, limit: int)
        """
        current_time = time.time()
        effective_limit = limit if limit is not None else self.default_limit
        effective_window = window if window is not None else self.window_seconds

        if client_ip not in self.requests:
            self.requests[client_ip] = []

        # Filter out timestamps outside the active window
        self.requests[client_ip] = [
            t for t in self.requests[client_ip]
            if current_time - t < effective_window
        ]

        if len(self.requests[client_ip]) >= effective_limit:
            self.strike_counts[client_ip] = self.strike_counts.get(client_ip, 0) + 1
            return False, len(self.requests[client_ip]), effective_limit

        self.requests[client_ip].append(current_time)
        return True, len(self.requests[client_ip]), effective_limit

    def get_strikes(self, client_ip: str) -> int:
        return self.strike_counts.get(client_ip, 0)

    def reset_ip(self, client_ip: str):
        self.requests.pop(client_ip, None)
        self.strike_counts.pop(client_ip, None)

rate_limiter = SlidingWindowRateLimiter()