# 🔎 ThreatLens

A threat intelligence tool that checks whether an IP, domain, or URL is safe —
combining real evidence from VirusTotal and WHOIS with a **deterministic risk
score**, then using Gemini to *explain* that score in plain language rather
than deciding it.

## Why this exists

Most "AI security checker" demos just hand raw data to an LLM and ask "is this
safe?" — which means the AI is inventing a verdict with no accountable logic
behind it, and no way to explain *why* it decided what it decided.

ThreatLens is built the other way around:

1. **Real evidence is collected first** (VirusTotal detections, WHOIS domain age).
2. **A deterministic scoring engine** turns that evidence into a 0–100 threat
   score, a risk level, and a confidence rating — every point is traceable to
   a specific, human-readable reason.
3. **Gemini interprets the already-computed result** for the user, adapting
   its explanation to a Beginner/Intermediate/Expert knowledge level — it is
   explicitly instructed not to contradict the computed verdict or invent
   evidence that wasn't provided.

If Gemini's API is unavailable, the app still works — score, risk level, and
confidence are all computed independently of the AI layer.

## Screenshot

*(add a screenshot of the app here once you have one — drag an image into
this README.md file on GitHub's web editor, or reference a file you commit
under a `docs/` or `screenshots/` folder)*

## Features

- ✅ Supports IP address, domain, and URL targets, with real input validation
- ✅ VirusTotal + WHOIS evidence collection, with a registry pattern that
  makes adding a new source a two-line change (one function + one registry
  entry) — no other code needs to change
- ✅ Deterministic, explainable threat scoring (not just an AI opinion)
- ✅ AI interpretation via Gemini, adapted to three knowledge levels
- ✅ Defended against prompt injection via untrusted evidence fields
  (WHOIS/VirusTotal data is attacker-influenced — see `sanitize_evidence_for_prompt`
  in `app.py`)
- ✅ Local result caching (30-minute TTL) to conserve API quota
- ✅ Runs in a fully working demo mode with zero API keys — VirusTotal returns
  deterministic mock data, WHOIS is real (it needs no key), and the UI clearly
  labels demo-mode results
- ✅ 40 automated tests, all offline — no live API calls or keys required to
  run the test suite

## Architecture

```
app.py          → UI, orchestration, Gemini prompt + interpretation, caching
sources.py      → data-fetching layer (get_virustotal, get_whois), SOURCES registry
scoring.py      → pure deterministic scoring engine (no I/O, no network)
cache.py        → local JSON result cache (no I/O beyond the cache file itself)
```

Dependency direction is strictly one-way: `app.py` depends on `sources.py`,
`scoring.py`, and `cache.py` — none of those ever import `app.py` or each
other. This is what keeps `scoring.py` and `sources.py` independently
testable without mocking Streamlit or the UI.

### Adding a new intelligence source

1. Write one function in `sources.py`, matching the existing signature:
   `(target: str, target_type: str) -> dict`, returning the same normalized
   shape (`source`, `status`, `data`, `error`).
2. Add one line to the `SOURCES` dict at the bottom of `sources.py`.

`app.py`'s orchestration loop iterates `SOURCES` generically — no other code
needs to change.

## Tech stack

- Python 3.13
- Streamlit — UI
- Requests — VirusTotal API calls
- python-whois — domain registration lookups
- google-generativeai — Gemini API
- python-dotenv — local `.env` config loading
- pytest — test suite

## Setup

```bash
git clone https://github.com/meerab-babar097/Threat-Lens.git
cd Threat-Lens
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your real API keys:

```bash
cp .env.example .env
```

- Get a free VirusTotal key: https://www.virustotal.com (profile icon → API Key)
- Get a free Gemini key: https://aistudio.google.com/apikey

**Note:** the app runs without any keys at all, in demo mode (VirusTotal
returns deterministic mock data, WHOIS is real, AI interpretation shows a
clearly labeled placeholder). This is intentional — you can try the full UI
and scoring logic without signing up for anything first.

## Running

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`.

## Testing

```bash
python -m pytest -v
```

40 tests, fully offline — covers scoring logic, API error handling
(timeouts, rate limits, invalid keys, malformed responses), and the
prompt-injection sanitization layer. No live API calls or keys required.

## Known limitations

- Gemini's free tier caps at 20 requests/day per model — caching helps for
  repeated scans of the same target, but doesn't raise the underlying limit
- WHOIS domain-age scoring is a useful but imperfect signal — legitimate new
  domains exist, and some malicious infrastructure uses aged/compromised
  domains specifically to avoid this heuristic
- Investigation history is not yet persistent beyond the 30-minute cache —
  a full history feature (SQLite-backed) is a planned next step

## Roadmap

- [x] Reliable, distinguished API error handling
- [x] Normalized, extensible evidence architecture
- [x] Deterministic, explainable threat scoring
- [x] AI interpretation (not decision-making)
- [x] Professional dashboard UI
- [x] Prompt injection defense
- [x] Automated test suite (40 tests)
- [x] Local result caching
- [ ] Persistent investigation history (SQLite)
- [ ] Exportable PDF reports
- [ ] Production deployment

## License

*(add a license if you want one — MIT is a common, permissive default for
portfolio projects; GitHub can generate one for you under Settings → General
→ "Add a license" if you'd like)*
