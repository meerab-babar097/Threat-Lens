"""
test_scoring.py — Unit tests for scoring.py's deterministic scoring engine.

No network calls, no live API keys required. All evidence is synthetic,
built to match the exact shape sources.py produces, so these tests validate
scoring logic in complete isolation from VirusTotal/WHOIS availability.

Run with: python -m pytest test_scoring.py -v
"""

from scoring import score_evidence


# ---------------------------------------------------------------------------
# Helpers to build synthetic evidence matching sources.py's real shape
# ---------------------------------------------------------------------------

def vt_result(status="ok", malicious=0, suspicious=0, harmless=68, undetected=6,
              demo=False, found=True, error=None):
    if status == "error":
        return {"source": "virustotal", "status": "error", "data": None, "error": error or "simulated failure"}
    return {
        "source": "virustotal",
        "status": "ok",
        "data": {
            "found": found,
            "demo": demo,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": 0,
            "categories": {},
        },
        "error": None,
    }


def whois_result(status="ok", applicable=True, creation_date=None, error=None):
    if status == "error":
        return {"source": "whois", "status": "error", "data": None, "error": error or "simulated failure"}
    return {
        "source": "whois",
        "status": "ok",
        "data": {"applicable": applicable, "creation_date": creation_date},
        "error": None,
    }


# ---------------------------------------------------------------------------
# Verdict / risk-level thresholds
# ---------------------------------------------------------------------------

def test_clean_target_is_safe_with_high_confidence():
    results = {
        "virustotal": vt_result(malicious=0, suspicious=0),
        "whois": whois_result(creation_date="1997-09-15 04:00:00+00:00"),
    }
    result = score_evidence("google.com", "Domain", results)

    assert result["verdict"] == "SAFE"
    assert result["risk_level"] == "LOW"
    assert result["confidence"] == "HIGH"
    assert result["score"] < 25


def test_heavily_flagged_target_is_malicious():
    results = {
        "virustotal": vt_result(malicious=10, suspicious=5),
        "whois": whois_result(creation_date="2026-08-01 00:00:00+00:00"),  # very new
    }
    result = score_evidence("evil.example", "Domain", results)

    assert result["verdict"] == "MALICIOUS"
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["score"] >= 50


def test_lightly_flagged_target_is_suspicious():
    results = {
        "virustotal": vt_result(malicious=3, suspicious=3),
        "whois": whois_result(creation_date="1997-09-15 04:00:00+00:00"),
    }
    result = score_evidence("borderline.example", "Domain", results)

    assert result["verdict"] == "SUSPICIOUS"
    assert 25 <= result["score"] < 50


# ---------------------------------------------------------------------------
# Confidence rules — must reflect evidence availability, never be invented
# ---------------------------------------------------------------------------

def test_both_sources_failing_gives_low_confidence_and_unknown_verdict():
    results = {
        "virustotal": vt_result(status="error", error="rate limited"),
        "whois": whois_result(status="error", error="timeout"),
    }
    result = score_evidence("mystery.example", "Domain", results)

    assert result["confidence"] == "LOW"
    assert result["verdict"] == "UNKNOWN"


def test_one_source_failing_gives_medium_confidence():
    results = {
        "virustotal": vt_result(malicious=0, suspicious=0),
        "whois": whois_result(status="error", error="timeout"),
    }
    result = score_evidence("partial.example", "Domain", results)

    assert result["confidence"] == "MEDIUM"


def test_ip_target_with_inapplicable_whois_still_scores_from_virustotal():
    results = {
        "virustotal": vt_result(malicious=0, suspicious=0),
        "whois": whois_result(applicable=False),
    }
    result = score_evidence("8.8.8.8", "IP", results)

    # WHOIS not applicable to IPs -> only VT is usable -> MEDIUM, not HIGH
    assert result["confidence"] == "MEDIUM"
    assert result["verdict"] == "SAFE"


def test_demo_mode_virustotal_is_not_counted_as_usable_evidence():
    results = {
        "virustotal": vt_result(malicious=0, suspicious=0, demo=True),
        "whois": whois_result(status="error", error="timeout"),
    }
    result = score_evidence("demo-target.example", "Domain", results)

    # VT is demo (not real), WHOIS failed -> zero usable sources -> LOW confidence, UNKNOWN
    assert result["confidence"] == "LOW"
    assert result["verdict"] == "UNKNOWN"
    assert "virustotal" in result["evidence_quality"]["demo_sources"]


# ---------------------------------------------------------------------------
# Explainability — every score must come with reasons, never a bare number
# ---------------------------------------------------------------------------

def test_reasons_are_never_empty():
    results = {
        "virustotal": vt_result(malicious=3, suspicious=1),
        "whois": whois_result(creation_date="1997-09-15 04:00:00+00:00"),
    }
    result = score_evidence("some-target.example", "Domain", results)

    assert len(result["reasons"]) > 0
    assert all(isinstance(r, str) and len(r) > 0 for r in result["reasons"])


def test_score_is_always_within_bounds():
    results = {
        "virustotal": vt_result(malicious=999, suspicious=999),  # extreme input
        "whois": whois_result(creation_date="2026-09-01 00:00:00+00:00"),
    }
    result = score_evidence("extreme.example", "Domain", results)

    assert 0 <= result["score"] <= 100


# ---------------------------------------------------------------------------
# Malformed / unparseable data must not crash scoring
# ---------------------------------------------------------------------------

def test_unparseable_creation_date_does_not_crash():
    results = {
        "virustotal": vt_result(malicious=0, suspicious=0),
        "whois": whois_result(creation_date="not-a-real-date"),
    }
    # Should not raise — must degrade gracefully
    result = score_evidence("weird-date.example", "Domain", results)
    assert result["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN")


def test_missing_source_entirely_does_not_crash():
    # Simulates a source that was never run / registry misconfiguration
    results = {
        "virustotal": vt_result(malicious=0, suspicious=0),
    }
    result = score_evidence("missing-source.example", "Domain", results)
    assert result["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN")