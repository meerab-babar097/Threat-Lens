"""
test_report.py — Tests for report.py. No Streamlit, no real PDF viewer
needed — we only verify the function returns valid, non-empty PDF bytes
and never crashes on tricky input (unicode, empty fields, etc.).

Run with: python -m pytest test_report.py -v
"""

import time
from report import generate_report_pdf, _pdf_safe


def _sample_assessment():
    return {
        "verdict": "SAFE", "score": 6, "risk_level": "LOW", "confidence": "HIGH",
        "reasons": ["VirusTotal: clean", "WHOIS: established domain"],
    }


def _sample_insight():
    return {
        "SUMMARY": "This is safe.",
        "KEY_FINDINGS": "- Finding one\n- Finding two",
        "RECOMMENDATION": "No action needed.",
    }


def test_generates_nonempty_pdf_bytes():
    pdf_bytes = generate_report_pdf(
        "google.com", "Domain", "Beginner", time.time(),
        _sample_assessment(), _sample_insight(), {"virustotal": {"status": "ok"}},
    )
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_pdf_starts_with_valid_header():
    # Real PDF files always start with this magic byte sequence.
    pdf_bytes = generate_report_pdf(
        "google.com", "Domain", "Beginner", time.time(),
        _sample_assessment(), _sample_insight(), {"virustotal": {"status": "ok"}},
    )
    assert pdf_bytes[:5] == b"%PDF-"


def test_handles_em_dashes_and_smart_quotes_without_crashing():
    tricky_insight = {
        "SUMMARY": "This is \u201csafe\u201d \u2014 no real concerns \u2014 nothing more.",
        "KEY_FINDINGS": "- It's fine\u2026",
        "RECOMMENDATION": "Proceed \u2014 all clear.",
    }
    # Must not raise
    pdf_bytes = generate_report_pdf(
        "test.com", "Domain", "Expert", time.time(),
        _sample_assessment(), tricky_insight, {},
    )
    assert len(pdf_bytes) > 0


def test_handles_empty_reasons_and_results():
    minimal_assessment = {"verdict": "UNKNOWN", "score": 0, "risk_level": "LOW", "confidence": "LOW", "reasons": []}
    pdf_bytes = generate_report_pdf(
        "test.com", "Domain", "Beginner", time.time(),
        minimal_assessment, {"SUMMARY": "", "KEY_FINDINGS": "", "RECOMMENDATION": ""}, {},
    )
    assert len(pdf_bytes) > 0


def test_pdf_safe_strips_unsupported_characters():
    result = _pdf_safe("Hello \u2014 World \u201cquoted\u201d")
    assert "\u2014" not in result
    assert "\u201c" not in result
    # Encoding to latin-1 must succeed now
    result.encode("latin-1")


def test_pdf_safe_handles_empty_string():
    assert _pdf_safe("") == ""
    assert _pdf_safe(None) == ""