# PhishGuard

PhishGuard is a **local phishing email analyzer** built around a FastAPI backend and a small Chrome extension.
It analyzes exported **`.eml`** and **`.msg`** messages without requiring a cloud API or an external SaaS backend.

The current version is designed for **local triage and analyst assistance**:
- it extracts message content and metadata,
- runs several heuristic analyzers in parallel,
- computes a **risk vs trust** score,
- and returns a verdict with detailed reasons.

It is not a replacement for a full enterprise mail gateway, but it is practical for lab work, personal analysis, and analyst-guided review.

---

## Features

- FastAPI backend with JSON endpoints
- CLI for local `.eml` / `.msg` analysis
- Chrome extension UI for supported webmail pages
- `.eml` and `.msg` parsing
- HTML URL extraction (`href`, `form action`, `meta refresh`, image/script/frame URLs)
- Heuristic analyzers for text, headers, URLs, attachments, domains, reputation, ML, and benign signals
- Optional local ML model (`joblib`)
- Optional Hugging Face model
- Optional network reputation lookups (enabled by default)
- No API key required for the built-in reputation sources

---

## Repository layout

```text
.
├── api.py
├── cli.py
├── extension/
├── phishguard/
│   ├── analyzers/
│   ├── config.py
│   ├── domain_tools.py
│   ├── models.py
│   ├── parser.py
│   └── utils.py
├── tests/
├── pyproject.toml
├── requirements.txt
└── requirements-hf.txt
```

---

## Installation

### Recommended setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -e .
```

That installs the package in editable mode and is the cleanest way to run the API, CLI, and tests.

### Alternative setup

```bash
pip install -r requirements.txt
```

Use the editable install above if you intend to run tests or modify the code.

### Optional Hugging Face dependencies

```bash
pip install -r requirements-hf.txt
```

---

## Running the API

```bash
uvicorn api:app --reload
```

Default base URL:

```text
http://127.0.0.1:8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Interactive API documentation:

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

The interactive docs describe every endpoint, input model, response model, field, and common error condition.
They are the fastest way to explore the API in a browser and test requests live.

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check |
| `POST` | `/analyze/file` | Upload a `.eml` or `.msg` file |
| `POST` | `/analyze/raw-eml` | Analyze raw EML text sent as JSON |
| `POST` | `/analyze/base64-eml` | Analyze base64-encoded EML sent as JSON |
| `POST` | `/analyze/components` | Analyze subject/text/headers/URLs without a full file |
| `POST` | `/debug/parse` | Return extracted fields without scoring |

### `POST /analyze/file`

Accepts multipart upload with a `.eml` or `.msg` file.

Example:

```bash
curl -X POST \
  -F "file=@sample.eml" \
  http://127.0.0.1:8000/analyze/file
```

### `POST /analyze/raw-eml`

```json
{
  "raw_eml": "From: ...\r\nSubject: ...\r\n\r\nBody"
}
```

### `POST /analyze/base64-eml`

```json
{
  "base64_eml": "...",
  "filename": "message.eml"
}
```

### `POST /analyze/components`

Useful for testing or integrating with another pipeline.

```json
{
  "subject": "Action required",
  "text": "Please review the account notice",
  "raw_headers": "From: sender@example.com\nAuthentication-Results: ...",
  "urls": ["https://example.com/login"]
}
```

---

## Response format

Typical response shape:

```json
{
  "extracted_email": {
    "subject": "...",
    "sender": "...",
    "urls": [],
    "attachments": []
  },
  "analysis_result": {
    "verdict": "phishing",
    "score": 82,
    "confidence": "high",
    "analysis_status": "ok",
    "sub_scores": {
      "text": 12,
      "headers": 16,
      "url": 18,
      "attachments": 0,
      "ml": 6,
      "domain": 10,
      "reputation": 25,
      "benign": -8
    },
    "reasons": [
      "[header] ...",
      "[url] ...",
      "[reputation] ...",
      "[benign] ..."
    ],
    "indicators": {
      "ml_probability": 0.91,
      "urls": ["..."],
      "risk_total": 87,
      "trust_total": 8,
      "structural_flag": true
    }
  },
  "extraction_warnings": [],
  "analysis_status": "ok",
  "confidence": "high"
}
```

### Response fields

#### Top-level
- `extracted_email`: parsed message fields
- `analysis_result`: final scoring output
- `extraction_warnings`: parser fallbacks or decoding warnings
- `analysis_status`: mirrors the analyzer status
- `confidence`: mirrors the analyzer confidence

#### `analysis_result`
- `verdict`: `phishing`, `suspicious`, `legit`, or `inconclusive`
- `score`: final **net** score from `0` to `100`
- `confidence`: `low`, `medium`, or `high`
- `analysis_status`: `ok` or `inconclusive`
- `sub_scores`: module-level scores, with `benign` shown as a negative trust contribution
- `reasons`: human-readable reasons from the analyzers
- `indicators`: extra machine-facing details

#### `sub_scores`
Current keys:
- `text`
- `headers`
- `url`
- `attachments`
- `ml`
- `domain`
- `reputation`
- `benign`

`benign` is returned as a **negative** value in `sub_scores` because it reduces the final score.

---

## Scoring model

PhishGuard does **not** use the old “sum everything and threshold it” model anymore.

The current model is:

1. Run analyzers in parallel
2. Sum all **risk** analyzers
3. Compute a separate **trust** score from benign signals
4. Compute `net_score = clamp(risk_total - trust_total, 0..100)`
5. Decide the verdict using both:
   - the net score,
   - and whether a **structural flag** was found

### Risk analyzers
- text
- headers
- URLs
- attachments
- ML
- domain age / trust
- reputation

### Trust analyzer
The benign analyzer reduces the score when the message looks coherent and operationally normal.

Examples of trust signals:
- SPF pass
- DKIM pass
- DMARC pass
- all URLs use HTTPS
- unsubscribe link present
- sender domain aligns with the URL domains

### Structural flags
Some signals are treated as stronger than generic marketing noise.
Examples include:
- reputation hit
- young domain
- dangerous attachment
- brand impersonation
- homoglyph / typosquat behavior
- IP-based URLs
- forged reply-chain / threading mismatch

### Verdict logic
Current high-level behavior:
- `phishing` if a strong structural condition is met with enough net score
- `suspicious` for accumulated weak-to-medium signals
- `legit` when the net score remains low
- `inconclusive` when parsing/extraction failed badly enough that analysis would be unreliable

This is intentional: a noisy newsletter should not become `phishing` just because it has many links and urgent wording.

---

## Analyzer details

### 1) Text analyzer
Looks for phishing-oriented wording in the subject and body.

Examples:
- urgent wording
- account / payment / verification language
- suspicious subject patterns
- high-risk phrases
- medium-risk keywords
- image-heavy / low-text body patterns

Notes:
- the text analyzer is intentionally **not sufficient on its own** to label a message as `phishing`
- it is calibrated to avoid over-penalizing normal transactional and marketing mail

### 2) Header analyzer
Looks for structural inconsistencies in message headers.

Examples:
- missing key headers
- free webmail sender in suspicious contexts
- display-name brand spoofing
- `Reply-To` mismatch
- `Return-Path` mismatch
- SPF / DKIM / DMARC failures
- anomalous Received chain patterns
- **forged reply-chain / thread mismatch** against branded domains in threading headers

### 3) URL analyzer
Looks at the extracted URLs and their structure.

Examples:
- unusually high URL volume
- IP-based URLs
- URL shorteners
- suspicious TLDs
- homoglyph / typosquat patterns
- brand impersonation in domains
- deep subdomains
- non-HTTPS links
- heavy encoding / obfuscation

### 4) Attachment analyzer
Flags risky attachment extensions.

Examples:
- `.exe`, `.js`, `.vbs`, `.scr`, `.bat`, `.ps1`
- macro-enabled Office files
- archive / disk-image style payloads when covered by the rules

### 5) Domain analyzer
Checks sender and URL domains using RDAP-first domain-age signals (with a quiet RDAP/WHOIS CLI fallback) and a trusted-domain list.

Important notes:
- only a limited number of domains are checked per message
- timeouts are enforced to avoid hanging the analysis
- domain logic uses `phishguard/domain_tools.py` to handle many national and multi-level suffixes such as:
  - `.fr`
  - `.es`
  - `.uk`
  - `.co.uk`
  - `.com.br`
  - `.co.jp`

### 6) Reputation analyzer
Uses lightweight external sources with no API key requirement.

Current built-in sources:
- DNSBL zones:
  - Spamhaus DBL
  - SURBL
  - URIBL
- URLhaus (`abuse.ch`)
- OpenPhish feed

Important notes:
- network reputation is **enabled by default**
- reputation failures are soft failures: network problems do not crash the analysis
- the analyzer may contact external infrastructure during runtime when enabled

### 7) ML analyzer
Optional local model support:
- local `joblib` model
- optional Hugging Face model if explicitly enabled

If no model is configured, this analyzer simply contributes `0`.

### 8) Benign analyzer
This is the main tolerance / anti-false-positive module.
It reduces the final score when the message has coherent, routine, or authenticated characteristics.

---

## Parsing behavior

The parser:
- normalizes raw EML bytes,
- parses with `email` policies,
- falls back when needed,
- extracts plain text and HTML,
- extracts URLs from both text and HTML structure,
- extracts visible attachments and metadata.

### HTML extraction
The parser extracts URLs from:
- `<a href>`
- `<form action>`
- `<img src>`
- `<iframe src>`
- `<script src>`
- `meta refresh`

### Attachments and storage
By default:
- uploaded temporary `.msg` files are deleted after parsing,
- extracted attachments are **not** written to disk.

If you explicitly set `PHISHGUARD_SAVE_ATTACHMENTS=1`, extracted attachments can be saved to `PHISHGUARD_ATTACHMENTS_DIR`.

---

## CLI usage

```bash
python cli.py path/to/message.eml
python cli.py path/to/message.eml --json
```

Human-readable output includes:
- file
- subject
- sender
- verdict
- score
- confidence
- top reasons

---

## Chrome extension

See [`extension/README.md`](extension/README.md).

The extension is intentionally limited to a small set of supported webmail hosts in `manifest.json`.
It uploads `.eml` and `.msg` files to the **local** backend only.

Important nuance:
- the extension sends the selected file to your local PhishGuard backend,
- the backend may then perform **optional external reputation lookups** if that feature is enabled.

---

## Configuration

### Environment variables

| Variable | Default | Description |
|---|---:|---|
| `PHISHGUARD_CORS_ORIGINS` | `*` | Comma-separated allowed origins. `*` works with the Chrome extension because credentials are disabled. |
| `PHISHGUARD_MODEL_PATH` | auto-discovered `models/phishing_model.joblib` | Local joblib model path |
| `PHISHGUARD_ENABLE_HF_ML` | `0` | Set to `1` to enable the Hugging Face model |
| `PHISHGUARD_HF_MODEL` | `cybersectony/phishing-email-detection-distilbert_v2.4.1` | Hugging Face model ID |
| `PHISHGUARD_TEMP_DIR` | `./tmp` | Temporary file directory |
| `PHISHGUARD_ATTACHMENTS_DIR` | `./Attachments` | Attachment save directory when saving is enabled |
| `PHISHGUARD_SAVE_ATTACHMENTS` | `0` | Set to `1` to persist extracted attachments |
| `PHISHGUARD_MAX_UPLOAD_BYTES` | `10485760` | Max accepted upload size in bytes |
| `PHISHGUARD_ENABLE_REPUTATION_NET` | `1` | Set to `0` to disable DNSBL / URLhaus / OpenPhish network checks |

---

## Requirements

Core dependencies are listed in `requirements.txt` and mirrored in `pyproject.toml`.

Main runtime dependencies:
- `fastapi`
- `uvicorn`
- `python-multipart`
- `pydantic`
- `beautifulsoup4`
- `joblib`
- `scikit-learn`
- `extract-msg`
- RDAP (via built-in HTTPS requests)

Optional ML dependencies are in `requirements-hf.txt`.

---

## Running tests

Recommended command:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 pytest -q
```

This avoids interference from unrelated globally installed pytest plugins.

---

## Known limitations

- heuristic scoring is still heuristic scoring: it is not a fully trained production classifier
- reputation coverage depends on network availability and third-party feeds
- the extension is not tested here against every webmail UI variation
- domain parsing is more robust than a naive split, but it is still a lightweight in-project helper rather than a full public suffix database implementation
- a legitimate but unusual email can still be marked `suspicious`
- a fresh phishing campaign with very little infrastructure evidence can still look cleaner than it should

---

## Security and privacy notes

- the extension talks to your **local** backend
- PhishGuard does **not** require a cloud API key
- when reputation is enabled, the backend may query external reputation sources during analysis
- extracted attachments are not persisted unless you opt in
- temporary `.msg` files created for parsing are deleted after use

---

## Versioning note

This README documents the current calibrated scoring model with:
- benign trust signals
- structural flags
- network reputation enabled by default
- `.eml` and `.msg` support in the extension UI
