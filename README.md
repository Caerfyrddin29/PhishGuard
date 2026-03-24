# PhishGuard

A local phishing email analyzer: FastAPI backend + Chrome extension.
Supports `.eml` and `.msg` files. No cloud dependency. No API key required.

---

## Quick start

```bash
pip install -r requirements.txt
uvicorn api:app --reload
```

Then load the `extension/` folder in Chrome (see Extension section).

---

## Requirements

```
pip install -r requirements.txt   # core dependencies
pip install -r requirements-hf.txt  # optional: Hugging Face ML model
```

New in this version: `python-whois` is required for domain-age checks.

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `POST` | `/analyze/file` | Upload `.eml` or `.msg` file (multipart) |
| `POST` | `/analyze/raw-eml` | Send raw EML as a string in JSON body |
| `POST` | `/analyze/base64-eml` | Send EML as base64-encoded JSON |
| `POST` | `/analyze/components` | Analyze subject + body text + URLs directly |
| `POST` | `/debug/parse` | Extract email fields without running analysis |

### Response shape (`/analyze/*`)

```json
{
  "extracted_email": { "subject": "...", "sender": "...", "urls": [], ... },
  "analysis_result": {
    "verdict": "phishing | suspicious | legit | inconclusive",
    "score": 0,
    "confidence": "low | medium | high",
    "analysis_status": "ok | inconclusive",
    "sub_scores": {
      "text": 0,
      "headers": 0,
      "url": 0,
      "attachments": 0,
      "ml": 0,
      "domain": 0,
      "reputation": 0
    },
    "reasons": ["[text] Suspicious keywords...", "..."],
    "indicators": {}
  },
  "extraction_warnings": [],
  "analysis_status": "ok",
  "confidence": "low"
}
```

### Verdict thresholds

| Score | Verdict |
|-------|---------|
| ≥ 70 | `phishing` (high confidence) |
| 40–69 | `suspicious` (medium confidence) |
| < 40 | `legit` |

---

## Analyzers

PhishGuard runs 7 analyzers in parallel and sums their scores (capped at 100).

### Text analyzer (max 35 pts)
- 200+ high-weight phishing phrases (3 pts each) in EN, FR, ES, DE, IT, PT, NL, TR, PL, RO, SV, ZH, JA
- 150+ medium-weight keywords (2 pts each)
- 40+ subject-line regex patterns (urgency, spoofed RE:/FWD:, brand names, prizes)
- Image-only body detection

### Header analyzer (max 40 pts)
- Missing From / To / Subject
- Free webmail sender (hotmail, gmail, yahoo, etc.) — +8 pts
- Display name brand spoofing (PayPal, Amazon, Apple, BNP, Ameli, CAF, La Poste…) — +15 pts
- Reply-To domain mismatch — +10 pts
- Return-Path registrable domain mismatch — +6 pts
- DKIM / SPF / DMARC failure parsing from `Authentication-Results`
- Hop count anomalies (0 hops, 1 hop, >10 hops, private IPs in Received chain)

### URL analyzer (max 40 pts)
- URL count with volume bonus (>10 URLs: +5, >20 URLs: +10)
- IP-based URLs — +10 pts
- URL shorteners (bit.ly, tinyurl, etc.) — +8 pts
- 35+ suspicious TLDs (.xyz, .tk, .ml, .top, .click, .loan…)
- Homoglyph / typosquat detection (paypa1, amaz0n, g00gle…)
- Brand impersonation in domain (whole-token matching, no false positives)
- Excessive subdomain depth (>3 levels)
- Non-HTTPS links
- Heavy URL encoding / obfuscated query strings

### Attachment analyzer (max 30 pts)
- Risky extensions: `.exe`, `.js`, `.vbs`, `.scr`, `.bat`, `.ps1`, `.hta`, `.msi`, `.docm`, `.xlsm`, `.jar`, `.iso`, `.lnk`, `.img`

### Domain analyzer (max 30 pts)
- WHOIS lookup for sender domain + up to 3 URL domains
- Domains < 30 days old: +20 pts (very recently registered = high risk)
- Domain age < 6 months: +10 pts
- Trusted domains (Google, Microsoft, French gov, etc.) are skipped
- Hard timeout: 5s per domain, 12s total budget

### Reputation analyzer (max 40 pts) — no API key needed
- **DNSBL**: Spamhaus DBL, SURBL, URIBL — DNS-based lookups, instant, no registration required
- **URLhaus** (abuse.ch): live URL lookup via POST, no key required
- **OpenPhish**: public phishing feed (~300KB), downloaded and cached in memory for 6h
- All sources fail silently — network errors never crash the analysis
- PhishTank is not included (their public JSON feed is 50-100MB; their URL-check API requires a key)

### ML analyzer (optional)
- Local scikit-learn model: place `phishing_model.joblib` in `models/`
- Hugging Face model (optional, requires GPU-friendly setup):
  ```bash
  pip install -r requirements-hf.txt
  PHISHGUARD_ENABLE_HF_ML=1 uvicorn api:app --reload
  ```

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PHISHGUARD_CORS_ORIGINS` | `*` (open) | Comma-separated allowed CORS origins. Defaults to `*` so the Chrome extension's `chrome-extension://` origin works. Set to specific origins to restrict access. |
| `PHISHGUARD_MODEL_PATH` | `models/phishing_model.joblib` | Path to local ML model |
| `PHISHGUARD_ENABLE_HF_ML` | `0` | Set to `1` to enable Hugging Face model |
| `PHISHGUARD_HF_MODEL` | `cybersectony/phishing-email-detection-distilbert_v2.4.1` | HF model ID |
| `PHISHGUARD_TEMP_DIR` | `./tmp` | Temp directory |
| `PHISHGUARD_ATTACHMENTS_DIR` | `./Attachments` | Where attachments are saved |

---

## Chrome Extension

See `extension/README.md` for setup instructions.

The extension adds a floating button on Gmail, Outlook, Yahoo Mail, ProtonMail and other webmail interfaces. You download an email as `.eml`, drop it in the panel, and the extension sends it to your local backend via `POST /analyze/file`.

---

## CLI

```bash
python cli.py path/to/email.eml           # human-readable output
python cli.py path/to/email.eml --json    # full JSON output
```

---

## Running tests

```bash
pytest tests/
```
