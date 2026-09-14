"""
PhishGuard AI — Live PhishTank Feed
Downloads PhishTank's live "online-valid" feed (verified, currently-online phishing URLs,
no API key required) on a background refresh loop and exposes a fast in-memory lookup that
/api/scan checks before the ML model — an exact/domain match here is authoritative (someone
already confirmed it's phishing), not a probabilistic guess.

This is deliberately separate from the trained model: PhishTank changes hour to hour, while
retraining the model is a periodic/manual step (see train_model.py). Treat this as a live
blocklist layered on top of the model, not a replacement for it.
"""
import csv
import io
import json
import os
import threading
import time
from datetime import datetime, timezone

import requests

from feature_extractor import registrable_domain

FEED_URL = "https://data.phishtank.com/data/online-valid.csv"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "data", "phishtank_cache.json")
REFRESH_INTERVAL_S = 6 * 60 * 60  # 6 hours — PhishTank's own feed doesn't update much faster than this
REQUEST_TIMEOUT_S = 30

_lock = threading.Lock()
_state = {
    "urls": set(),
    "domains": set(),
    "last_refreshed": None,   # ISO string, or None if never successfully refreshed
    "count": 0,
    "last_error": None,
}


def _save_cache():
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "urls": list(_state["urls"]),
                "domains": list(_state["domains"]),
                "last_refreshed": _state["last_refreshed"],
            }, f)
    except OSError:
        pass  # cache write failure isn't fatal — feed still works in-memory for this process


def _load_cache():
    """Warm the in-memory feed from disk at startup so a restart isn't defenseless until the
    first live refresh completes (which can take a while over a slow connection)."""
    try:
        with open(CACHE_PATH, encoding="utf-8") as f:
            data = json.load(f)
        _state["urls"] = set(data.get("urls", []))
        _state["domains"] = set(data.get("domains", []))
        _state["last_refreshed"] = data.get("last_refreshed")
        _state["count"] = len(_state["urls"])
    except (OSError, ValueError):
        pass  # no cache yet — fine, first refresh will populate it


def refresh_feed() -> bool:
    """Fetch the live feed and swap it in. Returns True on success. Never raises — a failed
    refresh just means the previous (still-decent) cache stays in place."""
    try:
        resp = requests.get(FEED_URL, timeout=REQUEST_TIMEOUT_S, headers={"User-Agent": "PhishGuardAI/1.0"})
        resp.raise_for_status()
        reader = csv.DictReader(io.StringIO(resp.text))
        urls, domains = set(), set()
        for row in reader:
            if row.get("verified") != "yes" or row.get("online") != "yes":
                continue
            url = (row.get("url") or "").strip()
            if not url:
                continue
            urls.add(url)
            d = registrable_domain(url)
            if d:
                domains.add(d)

        with _lock:
            _state["urls"] = urls
            _state["domains"] = domains
            _state["count"] = len(urls)
            _state["last_refreshed"] = datetime.now(timezone.utc).isoformat()
            _state["last_error"] = None
            _save_cache()
        return True
    except Exception as e:
        with _lock:
            _state["last_error"] = str(e)
        return False


def check(url: str) -> dict | None:
    """Returns a match dict if url (or its registrable domain) is on the live feed, else None."""
    with _lock:
        if url in _state["urls"]:
            return {"matched": "url", "value": url}
        domain = registrable_domain(url)
        if domain and domain in _state["domains"]:
            return {"matched": "domain", "value": domain}
    return None


def status() -> dict:
    with _lock:
        return {
            "count": _state["count"],
            "last_refreshed": _state["last_refreshed"],
            "last_error": _state["last_error"],
        }


def start_background_refresh():
    """Call once at app startup. Loads any on-disk cache immediately (non-blocking), then runs
    the download loop on a daemon thread so a slow/unreachable PhishTank never blocks Flask
    startup or a request — worst case, live-feed checks just find nothing until it succeeds."""
    _load_cache()

    def _loop():
        while True:
            refresh_feed()
            time.sleep(REFRESH_INTERVAL_S)

    threading.Thread(target=_loop, daemon=True).start()
