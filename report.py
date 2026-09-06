"""
report.py — ThreatLens PDF report generation.

Rules:
  1. No Streamlit imports, no network calls. Pure function: data in, PDF
     bytes out.
  2. Never imports app.py, sources.py, scoring.py, cache.py, or history.py.
     One-way dependency: app.py -> report.py.
  3. Takes already-normalized Python dicts (not raw JSON strings) — app.py
     is responsible for parsing history rows before calling this.

Notes:
  - Uses fpdf2's modern new_x/new_y API rather than the deprecated ln=True
    parameter.
  - Explicitly calls pdf.set_x(pdf.l_margin) before every multi_cell() call.
    multi_cell() does not reliably reset the cursor to the left margin
    between consecutive calls (unlike cell()), so calling it repeatedly in
    a loop without this can leave very little horizontal space on a later
    call, raising "Not enough horizontal space to render a single character".
"""

import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos


def _pdf_safe(text: str) -> str:
    if not text:
        return ""
    replacements = {
        "\u2014": "-", "\u2013": "-",
        "\u2018": "'", "\u2019": "'",
        "\u201c": '"', "\u201d": '"',
        "\u2026": "...",
        "\u2022": "-",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text.encode("latin-1", "ignore").decode("latin-1")


def _safe_multi_cell(pdf: FPDF, h: float, text: str) -> None:
    """multi_cell wrapper that always starts at the left margin, avoiding a
    known cursor-drift issue when multi_cell is called repeatedly."""
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, h, text)


def generate_report_pdf(target: str, target_type: str, knowledge_level: str,
                         scanned_at: float, assessment: dict, insight: dict,
                         results: dict) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "ThreatLens Security Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "", 10)
    scanned_str = datetime.datetime.fromtimestamp(scanned_at).strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 8, f"Generated: {scanned_str}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Target", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    _safe_multi_cell(pdf, 7, _pdf_safe(f"{target} ({target_type})\nKnowledge level: {knowledge_level}"))
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Assessment", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    _safe_multi_cell(
        pdf, 7,
        _pdf_safe(
            f"Verdict: {assessment['verdict']}\n"
            f"Threat Score: {assessment['score']}/100\n"
            f"Risk Level: {assessment['risk_level']}\n"
            f"Confidence: {assessment['confidence']}"
        ),
    )
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Why This Score", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    for reason in assessment.get("reasons", []):
        _safe_multi_cell(pdf, 7, _pdf_safe(f"- {reason}"))
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "AI Interpretation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    _safe_multi_cell(pdf, 7, _pdf_safe(f"Summary: {insight.get('SUMMARY', '')}"))
    pdf.ln(1)
    _safe_multi_cell(pdf, 7, _pdf_safe(f"Key Findings:\n{insight.get('KEY_FINDINGS', '')}"))
    pdf.ln(1)
    _safe_multi_cell(pdf, 7, _pdf_safe(f"Recommendation: {insight.get('RECOMMENDATION', '')}"))
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 10, "Sources Checked", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    for name, result in results.items():
        status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
        pdf.cell(0, 7, _pdf_safe(f"{name}: {status}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    return bytes(pdf.output())