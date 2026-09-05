"""
test_sources.py — Mocked tests for sources.py (get_virustotal, get_whois).

No real network calls, no real API keys. requests.get and whois.whois are
replaced with controlled fakes via unittest.mock, so these tests are fast,
deterministic, and safe to run offline or in CI.

Run with: python -m pytest test_sources.py -v
"""

from unittest.mock import patch, MagicMock
import requests

from sources import get_virustotal, get_whois


# ---------------------------------------------------------------------------
# get_virustotal — demo mode (no API key)
# ---------------------------------------------------------------------------

def test_virustotal_demo_mode_when_no_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result = get_virustotal("example.com", "Domain")

    assert result["status"] == "ok"
    assert result["data"]["demo"] is True
    assert result["error"] is None


def test_virustotal_demo_mode_is_deterministic(monkeypatch):
    """Same target should always produce the same demo verdict, not random flakiness."""
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    result1 = get_virustotal("example.com", "Domain")
    result2 = get_virustotal("example.com", "Domain")

    assert result1["data"]["malicious"] == result2["data"]["malicious"]
    assert result1["data"]["suspicious"] == result2["data"]["suspicious"]


# ---------------------------------------------------------------------------
# get_virustotal — real API responses (mocked)
# ---------------------------------------------------------------------------

def test_virustotal_success_response(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60, "undetected": 5},
                "reputation": -10,
                "categories": {},
            }
        }
    }
    mock_response.raise_for_status = MagicMock()

    with patch("sources.requests.get", return_value=mock_response):
        result = get_virustotal("evil.example", "Domain")

    assert result["status"] == "ok"
    assert result["data"]["malicious"] == 3
    assert result["data"]["suspicious"] == 1
    assert result["data"].get("demo") is None  # must NOT be marked as demo — this is real data


def test_virustotal_404_means_not_found_not_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("sources.requests.get", return_value=mock_response):
        result = get_virustotal("neverseen.example", "Domain")

    assert result["status"] == "ok"
    assert result["data"]["found"] is False


def test_virustotal_invalid_api_key_gives_clear_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    mock_response = MagicMock()
    mock_response.status_code = 401

    with patch("sources.requests.get", return_value=mock_response):
        result = get_virustotal("example.com", "Domain")

    assert result["status"] == "error"
    assert "key" in result["error"].lower()


def test_virustotal_rate_limit_gives_clear_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch("sources.requests.get", return_value=mock_response):
        result = get_virustotal("example.com", "Domain")

    assert result["status"] == "error"
    assert "rate limit" in result["error"].lower()


def test_virustotal_timeout_gives_clear_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    with patch("sources.requests.get", side_effect=requests.exceptions.Timeout()):
        result = get_virustotal("example.com", "Domain")

    assert result["status"] == "error"
    assert "timed out" in result["error"].lower()


def test_virustotal_network_failure_does_not_crash(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    with patch("sources.requests.get", side_effect=requests.exceptions.ConnectionError("DNS failure")):
        result = get_virustotal("example.com", "Domain")

    assert result["status"] == "error"
    assert result["data"] is None


def test_virustotal_url_target_type_encodes_correctly(monkeypatch):
    """Confirms the base64 URL-id logic runs without error for URL targets."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-testing")

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 10, "undetected": 2}}}
    }
    mock_response.raise_for_status = MagicMock()

    with patch("sources.requests.get", return_value=mock_response) as mock_get:
        result = get_virustotal("https://example.com/page", "URL")

    assert result["status"] == "ok"
    # confirm it actually hit the /urls/ endpoint, not /domains/ or /ip_addresses/
    called_url = mock_get.call_args[0][0]
    assert "/urls/" in called_url


# ---------------------------------------------------------------------------
# get_whois
# ---------------------------------------------------------------------------

def test_whois_not_applicable_for_ip():
    result = get_whois("8.8.8.8", "IP")

    assert result["status"] == "ok"
    assert result["data"]["applicable"] is False


def test_whois_success_for_domain():
    mock_whois_obj = MagicMock()
    mock_whois_obj.domain_name = "EXAMPLE.COM"
    mock_whois_obj.registrar = "Fake Registrar Inc."
    mock_whois_obj.creation_date = None
    mock_whois_obj.name_servers = ["NS1.EXAMPLE.COM"]
    mock_whois_obj.country = "US"
    mock_whois_obj.org = "Example Org"
    mock_whois_obj.get = MagicMock(return_value="EXAMPLE.COM")  # for the `if not w.get(...)` check

    with patch("sources.whois_lib.whois", return_value=mock_whois_obj):
        result = get_whois("example.com", "Domain")

    assert result["status"] == "ok"
    assert result["data"]["applicable"] is True
    assert result["data"]["registrar"] == "Fake Registrar Inc."


def test_whois_lookup_failure_gives_clear_error():
    with patch("sources.whois_lib.whois", side_effect=Exception("WHOIS server unreachable")):
        result = get_whois("example.com", "Domain")

    assert result["status"] == "error"
    assert "failed" in result["error"].lower()


def test_whois_extracts_domain_from_url_target():
    mock_whois_obj = MagicMock()
    mock_whois_obj.domain_name = "EXAMPLE.COM"
    mock_whois_obj.registrar = "Fake Registrar Inc."
    mock_whois_obj.creation_date = None
    mock_whois_obj.name_servers = []
    mock_whois_obj.country = "US"
    mock_whois_obj.org = "Example Org"
    mock_whois_obj.get = MagicMock(return_value="EXAMPLE.COM")

    with patch("sources.whois_lib.whois", return_value=mock_whois_obj) as mock_whois_call:
        get_whois("https://example.com/some/path", "URL")

    # confirm it looked up just the domain, not the full URL with path
    called_target = mock_whois_call.call_args[0][0]
    assert called_target == "example.com"