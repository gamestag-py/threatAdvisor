import requests
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
# -- User Agents --
MOBILE_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36"
DESKTOP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
CUSTOM_UA = "instagram Android FBAV FBAN instagram Instagram android Android FBAV FBAN"

RANDOM_UAS = [
    MOBILE_UA,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile Safari/604.1",
    DESKTOP_UA,
]

BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}

# Reuse a single session for connection pooling
_session = requests.Session()


def check_ua(url: str, ua: str, timeout: int = 10) -> dict:
    """Fire a single HEAD (falls back to GET) request and classify the result."""
    headers = {**BASE_HEADERS, "User-Agent": ua}
    try:
        # HEAD is faster; fall back to GET if the server doesn't support it
        r = _session.head(url, headers=headers, allow_redirects=True, timeout=timeout)
        if r.status_code == 405:
            r = _session.get(url, headers=headers, allow_redirects=True, timeout=timeout)
    except requests.RequestException as exc:
        return {"ok": False, "status": None, "type": "request_failed", "error": str(exc)}

    s = r.status_code
    if s == 200:
        kind = "accessible"
    elif s == 403:
        kind = "blocked"
    elif s == 401:
        kind = "unauthorized"
    elif s == 429:
        kind = "rate_limited"
    elif 300 <= s < 400:
        kind = "redirect"
    elif 500 <= s < 600:
        kind = "server_error"
    else:
        kind = "unknown"

    return {"ok": 200 <= s < 400, "status": s, "type": kind}


def analyze_ua_behavior(url: str, timeout: int = 10) -> dict:
    """
    Check the URL against three User-Agent profiles **in parallel** and
    return a scored analysis of how the server treats different clients.
    """
    profiles = {
        "mobile": MOBILE_UA,
        "desktop": DESKTOP_UA,
        "custom": CUSTOM_UA,
    }

    # Fire all three requests simultaneously
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(profiles)) as pool:
        futures = {pool.submit(check_ua, url, ua, timeout): name
                   for name, ua in profiles.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                results[name] = {"ok": False, "status": None, "type": "request_failed", "error": str(exc)}

    score = 0
    reasons = []

    # Only consider results that actually got a response (status is not None)
    responded = {name: r for name, r in results.items() if r["status"] is not None}
    failed = {name: r for name, r in results.items() if r["type"] == "request_failed"}

    if failed:
        names = ", ".join(failed.keys())
        reasons.append(f"Could not connect for: {names} (timeout or network error — results may be incomplete)")

    if len(responded) >= 2:
        statuses = {r["status"] for r in responded.values()}
        ok_uas = [name for name, r in responded.items() if r["ok"]]
        blocked_uas = [name for name, r in responded.items() if not r["ok"]]

        if ok_uas and blocked_uas:
            if set(ok_uas) == {"mobile"} or set(ok_uas) == {"mobile", "custom"}:
                score += 80
                reasons.append(f"Accessible only on {', '.join(ok_uas)} UA — possible cloaking")
            elif set(ok_uas) == {"desktop"}:
                score += 60
                reasons.append("Accessible only on desktop UA")
            elif len(statuses) > 1:
                score += 40
                reasons.append(
                    f"Different HTTP responses across UAs: "
                    + ", ".join(f"{n}={r['status']}" for n, r in responded.items())
                )
            elif not ok_uas:
                # All blocked equally = bot protection, NOT cloaking
                # Cloaking means SELECTIVE access, not blanket blocking
                score += 0   # was 30, change to 0
                reasons.append(
                    "All User-Agents blocked equally — likely bot/Cloudflare protection, not cloaking"
                )
    elif len(responded) == 0:
        reasons.append("No UAs received a response — site may be unreachable or all requests timed out")

    if any(r["type"] == "rate_limited" for r in results.values()):
        score += 25
        reasons.append("Rate limiting detected — bot protection active")

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "details": results,
    }



def cloaking_feature(url: str, timeout: int = 10) -> int:
    result = analyze_ua_behavior(url, timeout)
    score = result.get("score", 0)
    details = result.get("details", {})

    # All requests failed with DNS resolution error = dead/fake domain
    all_dns_failed = all(
        "NameResolutionError" in r.get("error", "") or "getaddrinfo failed" in r.get("error", "")
        for r in details.values()
        if r.get("type") == "request_failed"
    ) and all(r.get("type") == "request_failed" for r in details.values())

    if all_dns_failed:
        return 1  # Dead domain = suspicious, treat as phishing

    if score >= 40:
        return 1

    return 0