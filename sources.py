"""
sources.py — ThreatLens data-fetching layer.

Rules for this file (do not break these when adding new sources):
  1. No Streamlit imports. No UI code. No Gemini calls. This file only fetches data.
  2. One function per source, signature: (target: str, target_type: str) -> dict
  3. Every function returns the SAME normalized shape:
       {
         "source": "<name>",
         "status": "ok" | "error",
         "data": {...} | None,
         "error": None | str,
         "target": target,
         "target_type": target_type,
       }
  4. Every new source must be registered in SOURCES at the bottom of this file.
     That is the ONLY other change required — app.py needs no edits.
"""

import os
import socket
import requests
import whois as whois_lib

# Prevent a hung WHOIS server from freezing the app indefinitely.
socket.setdefaulttimeout(10)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _demo_virustotal_result(target: str, target_type: str) -> dict:
    """Deterministic mock VirusTotal result, used only when VIRUSTOTAL_API_KEY is not set."""
    import hashlib

    bucket = int(hashlib.sha256(target.encode()).hexdigest(), 16) % 3
    stats_by_bucket = {
        0: {"malicious": 0, "suspicious": 0, "harmless": 68, "undetected": 6},
        1: {"malicious": 2, "suspicious": 5, "harmless": 55, "undetected": 12},
        2: {"malicious": 14, "suspicious": 6, "harmless": 30, "undetected": 24},
    }
    stats = stats_by_bucket[bucket]

    return {
        "source": "virustotal",
        "status": "ok",
        "data": {
            "found": True,
            "demo": True,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"],
            "reputation": 0,
            "categories": {},
            "last_analysis_stats": stats,
        },
        "error": None,
        "target": target,
        "target_type": target_type,
    }


def get_virustotal(target: str, target_type: str) -> dict:
    """
    Query VirusTotal for a verdict on an IP, domain, or URL.
    Requires VIRUSTOTAL_API_KEY; falls back to deterministic demo data if unset.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return _demo_virustotal_result(target, target_type)

    headers = {"x-apikey": api_key}

    try:
        if target_type == "IP":
            url = f"{VT_BASE_URL}/ip_addresses/{target}"
        elif target_type == "Domain":
            url = f"{VT_BASE_URL}/domains/{target}"
        elif target_type == "URL":
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"{VT_BASE_URL}/urls/{url_id}"
        else:
            return {
                "source": "virustotal", "status": "error", "data": None,
                "error": f"Unsupported target_type: {target_type}",
                "target": target, "target_type": target_type,
            }

        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code in (401, 403):
            return {
                "source": "virustotal", "status": "error", "data": None,
                "error": "VirusTotal rejected the API key (invalid or unauthorized). Check VIRUSTOTAL_API_KEY.",
                "target": target, "target_type": target_type,
            }
        if response.status_code == 429:
            return {
                "source": "virustotal", "status": "error", "data": None,
                "error": "VirusTotal rate limit exceeded (free tier: 4 requests/min). Wait and retry.",
                "target": target, "target_type": target_type,
            }
        if response.status_code == 404:
            return {
                "source": "virustotal", "status": "ok",
                "data": {"found": False},
                "error": None, "target": target, "target_type": target_type,
            }

        response.raise_for_status()
        payload = response.json().get("data", {})
        attributes = payload.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "source": "virustotal",
            "status": "ok",
            "data": {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation"),
                "categories": attributes.get("categories", {}),
                "last_analysis_stats": stats,
            },
            "error": None,
            "target": target, "target_type": target_type,
        }

    except requests.exceptions.Timeout:
        return {
            "source": "virustotal", "status": "error", "data": None,
            "error": "VirusTotal request timed out after 15s.",
            "target": target, "target_type": target_type,
        }
    except requests.exceptions.RequestException as exc:
        return {
            "source": "virustotal", "status": "error", "data": None,
            "error": f"VirusTotal request failed: {exc}",
            "target": target, "target_type": target_type,
        }
    except Exception as exc:
        return {
            "source": "virustotal", "status": "error", "data": None,
            "error": f"Unexpected VirusTotal error: {exc}",
            "target": target, "target_type": target_type,
        }


def get_whois(target: str, target_type: str) -> dict:
    """Query WHOIS registration data for a domain (or the domain portion of a URL)."""
    if target_type == "IP":
        return {
            "source": "whois", "status": "ok",
            "data": {"applicable": False, "reason": "WHOIS is domain-only; not applicable to IPs."},
            "error": None, "target": target, "target_type": target_type,
        }

    lookup_target = target
    if target_type == "URL":
        from urllib.parse import urlparse
        parsed = urlparse(target if "://" in target else f"http://{target}")
        lookup_target = parsed.netloc or parsed.path

    try:
        w = whois_lib.whois(lookup_target)

        if not w or not w.get("domain_name"):
            return {
                "source": "whois", "status": "ok",
                "data": {"applicable": True, "found": False},
                "error": None, "target": target, "target_type": target_type,
            }

        def _first(value):
            if isinstance(value, list):
                return value[0] if value else None
            return value

        return {
            "source": "whois",
            "status": "ok",
            "data": {
                "applicable": True,
                "found": True,
                "domain_name": _first(w.domain_name),
                "registrar": w.registrar,
                "creation_date": str(_first(w.creation_date)) if w.creation_date else None,
                "expiration_date": str(_first(w.expiration_date)) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "country": w.country,
                "org": w.org,
            },
            "error": None, "target": target, "target_type": target_type,
        }

    except socket.timeout:
        return {
            "source": "whois", "status": "error", "data": None,
            "error": "WHOIS lookup timed out after 10s.",
            "target": target, "target_type": target_type,
        }
    except Exception as exc:
        return {
            "source": "whois", "status": "error", "data": None,
            "error": f"WHOIS lookup failed: {exc}",
            "target": target, "target_type": target_type,
        }


SOURCES = {
    "virustotal": get_virustotal,
    "whois": get_whois,
}