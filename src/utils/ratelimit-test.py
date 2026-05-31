#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import random
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

COMMON_ENDPOINTS = ["/", "/api", "/api/v1", "/graphql", "/login", "/auth", "/admin", "/health", "/status"]


def normalize_url(raw_url: str) -> str:
    parsed = urllib.parse.urlparse(raw_url.strip())
    if not parsed.scheme:
                parsed = urllib.parse.urlparse("https://" + raw_url.strip())
    if not parsed.netloc:
                raise ValueError("URL required")
    return parsed.geturl().rstrip("/")


def make_request(url: str, method: str = "GET", headers: dict[str, str] | None = None, timeout: int = 8):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(2048)
            elapsed = time.perf_counter() - started
            return {
                "ok": True,
                "status": resp.status,
                "headers": dict(resp.headers.items()),
                "elapsed": elapsed,
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - started
        return {
            "ok": False,
            "status": exc.code,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "elapsed": elapsed,
            "body": b"",
            "error": str(exc),
        }
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return {
            "ok": False,
            "status": 0,
            "headers": {},
            "elapsed": elapsed,
            "body": b"",
            "error": str(exc),
        }


def has_rate_headers(headers: dict[str, str]) -> bool:
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    return any(
        key in lowered
        for key in (
            "retry-after",
            "ratelimit-limit",
            "ratelimit-remaining",
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
        )
    )


def main() -> int:
    if len(sys.argv) < 2:
        print("URL required", file=sys.stderr)
        return 1

    try:
        base_url = normalize_url(sys.argv[1])
    except Exception as exc:
        print(f"Invalid URL: {exc}", file=sys.stderr)
        return 1

    print(f"[STRESS_TEST] Target: {base_url}")

    discovered = []
    header_signals = []
    for endpoint in COMMON_ENDPOINTS:
        probe_url = f"{base_url}{endpoint}"
        head = make_request(probe_url, "HEAD", {"User-Agent": random.choice(USER_AGENTS)}, timeout=5)
        get = make_request(probe_url, "GET", {"User-Agent": random.choice(USER_AGENTS)}, timeout=5)

        for result in (head, get):
            if result["status"] and result["status"] != 404:
                discovered.append((endpoint, result["status"]))
            if has_rate_headers(result["headers"]):
                header_signals.append((endpoint, result["status"], result["headers"]))

    if discovered:
        found_paths = ", ".join(sorted({endpoint for endpoint, _ in discovered}))
        print(f"RESULT: API_ACTIVE (Found {len(discovered)} endpoint responses: {found_paths})")
    else:
        print("RESULT: API_NOT_DETECTED (Standard API paths returned 404)")

    if header_signals:
        print("[HEADER_CHECK] Rate-limit style headers detected:")
        for endpoint, status, headers in header_signals[:10]:
            rate_bits = []
            for key in ("Retry-After", "RateLimit-Limit", "RateLimit-Remaining", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
                if key in headers:
                    rate_bits.append(f"{key}={headers.get(key)}")
            print(f"  {endpoint} -> {status} | {'; '.join(rate_bits)}")

    print("[BURST_TEST] Launching adaptive concurrent requests to test rate limiting...")

    request_count = 60
    burst_url = f"{base_url}/"
    request_headers = {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}

    def worker(index: int):
        local_headers = dict(request_headers)
        local_headers["X-Request-Id"] = f"webshield-{index}-{random.randint(1000, 9999)}"
        return make_request(burst_url, "GET", local_headers, timeout=8)

    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(worker, range(request_count)))
    duration = int((time.perf_counter() - start) * 1000)

    statuses = [result["status"] for result in results]
    response_times = [result["elapsed"] for result in results if result["elapsed"] > 0]
    count_429 = sum(1 for status in statuses if status == 429)
    count_403 = sum(1 for status in statuses if status == 403)
    count_503 = sum(1 for status in statuses if status == 503)
    count_success = sum(1 for status in statuses if 200 <= status < 300)

    avg_response = statistics.mean(response_times) if response_times else 0.0
    p95_response = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times, default=0.0)

    print(
        f"[STATS] Duration: {duration}ms | Success: {count_success} | RateLimited(429): {count_429} | Blocked(403): {count_403} | ServiceUnavailable(503): {count_503} | AvgRTT: {avg_response:.3f}s | P95RTT: {p95_response:.3f}s"
    )

    if count_429 > 0:
        print("RESULT: RATE_LIMIT_ACTIVE (Server returned 429 Too Many Requests)")
    elif count_403 > 10 or count_503 > 10:
        print("RESULT: REQUEST_LIMITER_ACTIVE (WAF/Firewall or reverse proxy blocked the burst)")
    elif header_signals:
        print("RESULT: REQUEST_LIMITER_ACTIVE (Rate-limit headers were present even without 429s)")
    elif count_success >= 50 and (p95_response == 0.0 or p95_response < max(avg_response * 3, 1.5)):
        print("RESULT: NO_LIMITER_DETECTED (Server accepted the adaptive burst traffic)")
    else:
        print("RESULT: INCONCLUSIVE (High error rate or inconsistent responses)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())