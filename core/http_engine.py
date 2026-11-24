"""
SPECTRE — Rate-Limited & Circuit-Protected Concurrent HTTP Engine
=================================================================
Provides per-host token-bucket pacing, fast circuit-breaking on unreachable
or firewall-tarpitted origins, and non-blocking parallel batch fetching.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
from pathlib import Path
import threading
import time
import urllib.parse
from typing import Any

import requests


def fetch_cached_text(
    session: Any,
    project_id: int,
    url: str,
    timeout: float = 5.5,
    max_chars: int = 350000,
) -> str:
    """Fetches a JS/HTML asset once per project using disk + session LRU cache."""
    if not url:
        return ""
    url_hash = hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:20]
    cache_dir = Path(f"/tmp/spectre_js_cache_{int(project_id)}")
    cache_file = cache_dir / f"u_{url_hash}.cache"
    if project_id > 0 and cache_file.is_file():
        try:
            return cache_file.read_text(encoding="utf-8", errors="ignore")[:max_chars]
        except Exception:
            pass
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        if getattr(resp, "status_code", 0) != 200:
            return ""
        txt = (resp.text or "")[:max_chars]
        if project_id > 0 and txt:
            try:
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(txt, encoding="utf-8", errors="ignore")
            except Exception:
                pass
        return txt
    except Exception:
        return ""


class RateLimitedHttpEngine:
    """Thread-safe HTTP client pool with per-host RPS pacing and circuit-breaker."""

    def __init__(
        self,
        session: requests.Session | None = None,
        max_rps_per_host: float = 12.0,
        fail_threshold: int = 4,
        max_response_bytes: int = 524288,
    ) -> None:
        self.session = session or requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=32, pool_maxsize=32)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.max_rps_per_host = max(1.0, float(max_rps_per_host))
        self.min_interval = 1.0 / self.max_rps_per_host
        self.fail_threshold = max(2, int(fail_threshold))
        self.max_response_bytes = max(32768, int(max_response_bytes))
        self._lock = threading.Lock()
        self._last_req_ts: dict[str, float] = {}
        self._backoff_until: dict[str, float] = {}
        self._fail_counts: dict[str, int] = {}
        self._dead_origins: set[str] = set()
        self._dead_hosts: set[str] = set()

    def reset(self) -> None:
        with self._lock:
            self._last_req_ts.clear()
            self._backoff_until.clear()
            self._fail_counts.clear()
            self._dead_origins.clear()
            self._dead_hosts.clear()

    @staticmethod
    def _parse_keys(url_or_host: str) -> tuple[str, str]:
        s = str(url_or_host or "").strip()
        if "://" not in s:
            h = s.lower().split("/")[0].split(":")[0]
            return h, h
        p = urllib.parse.urlparse(s)
        h = (p.hostname or "").lower()
        orig = f"{p.scheme}://{p.netloc}".lower() if p.netloc else h
        return h, orig

    def is_host_dead(self, url_or_host: str) -> bool:
        h, orig = self._parse_keys(url_or_host)
        with self._lock:
            return h in self._dead_hosts or orig in self._dead_origins

    def _pace_origin(self, host: str, orig: str) -> None:
        if not orig:
            return
        sleep_needed = 0.0
        with self._lock:
            if host in self._dead_hosts or orig in self._dead_origins:
                raise requests.exceptions.ConnectTimeout(f"Circuit-Breaker: {orig} unreachable")
            now = time.monotonic()
            base_start = max(now, self._backoff_until.get(orig, 0.0))
            nxt = max(base_start, self._last_req_ts.get(orig, 0.0) + self.min_interval)
            if nxt > now:
                sleep_needed = nxt - now
                self._last_req_ts[orig] = nxt
            else:
                self._last_req_ts[orig] = now
        if sleep_needed > 0:
            time.sleep(min(sleep_needed, 2.5))

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        host, orig = self._parse_keys(str(url))
        self._pace_origin(host, orig)
        max_bytes = int(kwargs.pop("max_bytes", self.max_response_bytes))
        caller_stream = bool(kwargs.get("stream", False))
        kwargs.setdefault("timeout", (3.0, 4.5))
        kwargs.setdefault("verify", False)
        if not caller_stream:
            kwargs["stream"] = True
        try:
            resp = self.session.request(method.upper(), url, **kwargs)
            if not caller_stream:
                if resp.status_code in (204, 301, 302, 303, 304, 307, 308):
                    resp.close()
                    resp._content = b""
                else:
                    buf = bytearray()
                    t0 = time.monotonic()
                    try:
                        for chunk in resp.iter_content(chunk_size=16384):
                            if not chunk:
                                break
                            buf.extend(chunk)
                            if len(buf) >= max_bytes or (time.monotonic() - t0) > 7.5:
                                break
                    finally:
                        resp.close()
                    resp._content = bytes(buf[:max_bytes])
                if not resp.encoding or resp.encoding.lower() == "iso-8859-1":
                    resp.encoding = "utf-8"
            if orig:
                with self._lock:
                    self._fail_counts[orig] = 0
                    if resp.status_code in (429, 503):
                        ra = resp.headers.get("Retry-After", "")
                        self._backoff_until[orig] = time.monotonic() + min(float(ra) if ra.isdigit() else 1.5, 4.0)
            return resp
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as exc:
            if orig:
                err_s = str(exc)
                dns_dead = any(k in err_s for k in ("NameResolutionError", "Failed to resolve", "Errno -2", "Errno -3", "Errno -5"))
                with self._lock:
                    if dns_dead and host:
                        self._dead_hosts.add(host)
                    cnt = self.fail_threshold if dns_dead else (self._fail_counts.get(orig, 0) + 1)
                    self._fail_counts[orig] = cnt
                    if cnt >= self.fail_threshold:
                        self._dead_origins.add(orig)
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
