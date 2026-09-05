"""
cache.py — ThreatLens local result cache.

Purpose: avoid re-querying VirusTotal/WHOIS/Gemini for a target that was
already scanned recently, to conserve free-tier API quota (especially
Gemini's low daily limit).

Rules:
  1. No Streamlit imports — this is a plain data-persistence utility.
  2. Cache lives in a local JSON file (cache.json) next to this module.
  3. Entries expire after ttl_seconds; expired entries are treated as absent.
  4. Never imports app.py, sources.py, or scoring.py — pure utility.
     One-way dependency: app.py -> cache.py.
"""

import json
import time
from pathlib import Path

CACHE_FILE = Path(__file__).parent / "cache.json"
DEFAULT_TTL_SECONDS = 30 * 60  # 30 minutes


def _cache_key(target: str, target_type: str) -> str:
    return f"{target_type.strip().lower()}:{target.strip().lower()}"


def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, default=str)
    except OSError:
        pass  # A cache write failure should never crash the app


def get_cached_result(target: str, target_type: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
    """Returns the cached entry dict if fresh, else None."""
    cache = _load_cache()
    entry = cache.get(_cache_key(target, target_type))

    if not entry:
        return None

    age = time.time() - entry.get("cached_at", 0)
    if age > ttl_seconds:
        return None

    return entry


def set_cached_result(target: str, target_type: str, results: dict, assessment: dict, insight: dict) -> None:
    cache = _load_cache()
    cache[_cache_key(target, target_type)] = {
        "results": results,
        "assessment": assessment,
        "insight": insight,
        "cached_at": time.time(),
    }
    _save_cache(cache)


def cache_age_seconds(entry: dict) -> float:
    return time.time() - entry.get("cached_at", 0)