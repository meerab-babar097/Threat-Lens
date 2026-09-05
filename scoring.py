"""
scoring.py — ThreatLens deterministic scoring engine.

Rules for this file:
  1. No Streamlit imports, no network calls, no AI calls. Pure logic only.
  2. Never imports app.py or sources.py — it only consumes the evidence dict
     shape sources.py produces, so it stays decoupled from both.
  3. Every point added or subtracted must have a human-readable reason attached
     in `reasons`. No unexplained numbers.
  4. If evidence is insufficient, return confidence=LOW and verdict=UNKNOWN —
     never invent certainty.
"""

from datetime import datetime, timezone


def score_evidence(target: str, target_type: str, results: dict) -> dict:
    """
    results: the dict of {source_name: normalized_result} produced by
             sources.collect via sources.SOURCES.

    Returns:
        {
          "score": int (0-100),
          "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
          "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",
          "confidence": "LOW" | "MEDIUM" | "HIGH",
          "reasons": [str, ...],
          "evidence_quality": {
              "usable_sources": int,
              "total_sources": int,
              "demo_sources": [str],
              "failed_sources": [str],
          },
        }
    """
    reasons = []
    score = 0
    usable_sources = []
    demo_sources = []
    failed_sources = []

    vt = results.get("virustotal")
    whois_result = results.get("whois")

    # --- VirusTotal ---------------------------------------------------------
    if vt and vt.get("status") == "ok" and vt.get("data"):
        vt_data = vt["data"]
        if vt_data.get("demo"):
            demo_sources.append("virustotal")
            reasons.append("VirusTotal is running in demo mode (no API key) — mock data, not counted as real evidence.")
        elif vt_data.get("found") is False:
            reasons.append("VirusTotal has no record of this target — no evidence either way.")
        else:
            usable_sources.append("virustotal")
            malicious = vt_data.get("malicious", 0)
            suspicious = vt_data.get("suspicious", 0)

            if malicious > 0:
                points = min(60, malicious * 6)
                score += points
                reasons.append(f"VirusTotal: {malicious} vendor(s) flagged this as malicious (+{points}).")
            if suspicious > 0:
                points = min(20, suspicious * 3)
                score += points
                reasons.append(f"VirusTotal: {suspicious} vendor(s) flagged this as suspicious (+{points}).")
            if malicious == 0 and suspicious == 0:
                reasons.append("VirusTotal: no vendors flagged this target (no negative signal found).")
    else:
        failed_sources.append("virustotal")
        err = vt.get("error") if vt else "not run"
        reasons.append(f"VirusTotal lookup unavailable ({err}) — treated as missing evidence, not as a negative signal.")

    # --- WHOIS ----------------------------------------------------------------
    if whois_result and whois_result.get("status") == "ok" and whois_result.get("data"):
        w_data = whois_result["data"]
        if not w_data.get("applicable", True):
            reasons.append("WHOIS is not applicable to this target type (IP address).")
        else:
            usable_sources.append("whois")
            creation_date_str = w_data.get("creation_date")
            if creation_date_str:
                try:
                    creation_date = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
                    if creation_date.tzinfo is None:
                        creation_date = creation_date.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - creation_date).days
                    if age_days < 30:
                        score += 15
                        reasons.append(f"WHOIS: domain registered only {age_days} day(s) ago — new domains are disproportionately used for abuse (+15).")
                    elif age_days < 180:
                        score += 5
                        reasons.append(f"WHOIS: domain registered {age_days} days ago — relatively young (+5).")
                    else:
                        reasons.append(f"WHOIS: domain has existed for {age_days} days — established age lowers likelihood of throwaway abuse registration.")
                except (ValueError, TypeError):
                    reasons.append("WHOIS: creation date present but unparseable — not used in scoring.")
            else:
                reasons.append("WHOIS: no creation date returned — domain age not factored into score.")
    else:
        failed_sources.append("whois")
        err = whois_result.get("error") if whois_result else "not run"
        reasons.append(f"WHOIS lookup unavailable ({err}) — treated as missing evidence, not as a negative signal.")

    score = max(0, min(100, score))

    # --- Risk level (purely from score) ----------------------------------------
    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # --- Confidence (purely from evidence availability) -------------------------
    total_sources = len(results)
    if len(usable_sources) == 0:
        confidence = "LOW"
    elif len(usable_sources) < total_sources:
        confidence = "MEDIUM"
    else:
        confidence = "HIGH"

    # --- Verdict: never claim certainty without usable evidence ------------------
    if confidence == "LOW":
        verdict = "UNKNOWN"
        reasons.append("Insufficient usable evidence for a confident verdict — marked UNKNOWN rather than guessed.")
    elif score >= 50:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons,
        "evidence_quality": {
            "usable_sources": len(usable_sources),
            "total_sources": total_sources,
            "demo_sources": demo_sources,
            "failed_sources": failed_sources,
        },
    }