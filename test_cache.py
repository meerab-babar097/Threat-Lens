"""
test_cache.py — Tests for cache.py. Uses a temporary cache file per test
(via monkeypatch) so these tests never touch your real cache.json.

Run with: python -m pytest test_cache.py -v
"""

import time
import cache as cache_module
from cache import get_cached_result, set_cached_result, cache_age_seconds


def test_cache_miss_when_nothing_stored(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_FILE", tmp_path / "cache.json")
    result = get_cached_result("google.com", "Domain")
    assert result is None


def test_cache_hit_after_set(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_FILE", tmp_path / "cache.json")

    set_cached_result("google.com", "Domain", {"r": 1}, {"a": 2}, {"i": 3})
    result = get_cached_result("google.com", "Domain")

    assert result is not None
    assert result["results"] == {"r": 1}
    assert result["assessment"] == {"a": 2}
    assert result["insight"] == {"i": 3}


def test_cache_key_is_case_insensitive(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_FILE", tmp_path / "cache.json")

    set_cached_result("Google.com", "Domain", {"r": 1}, {"a": 2}, {"i": 3})
    result = get_cached_result("google.com", "DOMAIN")

    assert result is not None


def test_expired_entry_is_treated_as_miss(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_FILE", tmp_path / "cache.json")

    set_cached_result("google.com", "Domain", {"r": 1}, {"a": 2}, {"i": 3})
    # ttl_seconds=0 means anything not stored in the exact same instant is "expired"
    result = get_cached_result("google.com", "Domain", ttl_seconds=0)

    assert result is None


def test_different_targets_do_not_collide(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_FILE", tmp_path / "cache.json")

    set_cached_result("google.com", "Domain", {"r": "google"}, {}, {})
    set_cached_result("8.8.8.8", "IP", {"r": "dns"}, {}, {})

    google_result = get_cached_result("google.com", "Domain")
    ip_result = get_cached_result("8.8.8.8", "IP")

    assert google_result["results"]["r"] == "google"
    assert ip_result["results"]["r"] == "dns"


def test_cache_age_seconds_is_nonnegative():
    entry = {"cached_at": time.time()}
    assert cache_age_seconds(entry) >= 0