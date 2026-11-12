"""
SPECTRE v13.0 — Rate-Limited & Circuit-Protected Concurrent HTTP Engine
=======================================================================
Provides per-host token-bucket pacing, fast circuit-breaking on unreachable
or firewall-tarpitted origins, and non-blocking parallel batch fetching.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
import urllib.parse
from typing import Any

import requests


class RateLimitedHttpEngine:
    """Thread-safe HTTP client pool with per-host RPS pacing and circuit-breaker."""

    def __init__(
        self,
        session: requests.Session | None = None,
        max_rps_per_host: float = 12.0,
        fail_threshold: int = 4,
    ) -> None:
        self.session = session or requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.max_rps_per_host = max(1.0, float(max_rps_per_host))
        self.min_interval = 1.0 / self.max_rps_per_host
        self.fail_threshold = max(2, int(fail_threshold))
        self._lock = threading.Lock()
        self._last_req_ts: dict[str, float] = {}
        self._fail_counts: dict[str, int] = {}
        self._dead_hosts: set[str] = set()

    def reset(self) -> None:
        with self._lock:
            self._last_req_ts.clear()
            self._fail_counts.clear()
            self._dead_hosts.clear()

    def is_host_dead(self, url_or_host: str) -> bool:
        host = (urllib.parse.urlparse(url_or_host).hostname or url_or_host).lower().strip()
        with self._lock:
            return host in self._dead_hosts

    def _pace_host(self, host: str) -> None:
        if not host:
            return
        sleep_needed = 0.0
        with self._lock:
            if host in self._dead_hosts:
                raise requests.exceptions.ConnectTimeout(f"Circuit-Breaker: {host} unreachable")
            now = time.monotonic()
            nxt = self._last_req_ts.get(host, 0.0) + self.min_interval
            if nxt > now:
                sleep_needed = nxt - now
                self._last_req_ts[host] = nxt
            else:
                self._last_req_ts[host] = now
        if sleep_needed > 0:
            time.sleep(min(sleep_needed, 0.5))

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        host = (urllib.parse.urlparse(str(url)).hostname or "").lower()
        self._pace_host(host)
        kwargs.setdefault("timeout", (3.0, 4.5))
        kwargs.setdefault("verify", False)
        try:
            resp = self.session.request(method.upper(), url, **kwargs)
            if host:
                with self._lock:
                    self._fail_counts[host] = 0
            return resp
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            if host:
                with self._lock:
                    cnt = self._fail_counts.get(host, 0) + 1
                    self._fail_counts[host] = cnt
                    if cnt >= self.fail_threshold:
                        self._dead_hosts.add(host)
            raise

    def fetch_many(
        self,
        urls: list[str],
        method: str = "GET",
        headers: dict[str, str] | None = None,
        allow_redirects: bool = False,
        max_workers: int = 8,
        overall_timeout: float = 16.0,
    ) -> dict[str, requests.Response]:
        results: dict[str, requests.Response] = {}
        res_lock = threading.Lock()

        def _one(u: str) -> None:
            try:
                r = self.request(method, u, headers=headers, allow_redirects=allow_redirects)
                with res_lock:
                    results[u] = r
            except Exception:
                pass

        if not urls:
            return results
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(urls))))
        futs = [ex.submit(_one, u) for u in urls]
        concurrent.futures.wait(futs, timeout=overall_timeout)
        ex.shutdown(wait=False, cancel_futures=True)
        return results
