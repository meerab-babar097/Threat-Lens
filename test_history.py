"""
test_history.py — Tests for history.py. Uses a temporary DB file per test
(via monkeypatch) so these tests never touch your real threatlens_history.db.

Run with: python -m pytest test_history.py -v
"""

import history as history_module
from history import init_db, log_scan, get_recent_scans, get_scan_by_id, get_history_count


def _sample_assessment():
    return {
        "verdict": "SAFE", "score": 6, "risk_level": "LOW", "confidence": "HIGH",
        "reasons": ["test reason"],
        "evidence_quality": {"usable_sources": 2, "total_sources": 2, "demo_sources": [], "failed_sources": []},
    }


def test_init_db_creates_table(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()
    assert get_history_count() == 0


def test_log_and_retrieve_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()

    log_scan("google.com", "Domain", "Beginner", {"vt": "data"}, _sample_assessment(), {"SUMMARY": "test"})

    scans = get_recent_scans()
    assert len(scans) == 1
    assert scans[0]["target"] == "google.com"
    assert scans[0]["verdict"] == "SAFE"
    assert scans[0]["score"] == 6


def test_recent_scans_ordered_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()

    log_scan("first.com", "Domain", "Beginner", {}, _sample_assessment(), {})
    log_scan("second.com", "Domain", "Beginner", {}, _sample_assessment(), {})

    scans = get_recent_scans()
    assert scans[0]["target"] == "second.com"
    assert scans[1]["target"] == "first.com"


def test_recent_scans_respects_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()

    for i in range(5):
        log_scan(f"target{i}.com", "Domain", "Beginner", {}, _sample_assessment(), {})

    scans = get_recent_scans(limit=3)
    assert len(scans) == 3


def test_get_scan_by_id_returns_correct_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()

    log_scan("target.com", "Domain", "Beginner", {}, _sample_assessment(), {})
    scans = get_recent_scans()
    scan_id = scans[0]["id"]

    fetched = get_scan_by_id(scan_id)
    assert fetched is not None
    assert fetched["target"] == "target.com"


def test_get_scan_by_id_returns_none_for_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()

    result = get_scan_by_id(999999)
    assert result is None


def test_history_count_increases(tmp_path, monkeypatch):
    monkeypatch.setattr(history_module, "DB_FILE", tmp_path / "test.db")
    init_db()

    assert get_history_count() == 0
    log_scan("target.com", "Domain", "Beginner", {}, _sample_assessment(), {})
    assert get_history_count() == 1