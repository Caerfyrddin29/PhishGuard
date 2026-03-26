#Projet : PhishGuard
#Auteurs : Myrddin Bellion, Ilyan Kassous

from __future__ import annotations

import base64
import os
import tempfile
from dataclasses import asdict, is_dataclass
from typing import Any, Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .phishguard.config import Settings
from .phishguard.parser import EmailFileExtractor
from .phishguard.analyzers.hybrid import HybridPhishingAnalyzer


settings = Settings()
extractor = EmailFileExtractor(settings=settings)
analyzer = HybridPhishingAnalyzer(settings=settings)

API_DESCRIPTION = """
PhishGuard exposes a local email-analysis API focused on `.eml` and `.msg` files.

## What this API does

- parses raw email content and extracts headers, bodies, URLs, attachments, and technical metadata
- runs multi-signal phishing analysis across text, headers, URLs, domain age, reputation, and benign trust signals
- returns a structured result with a final verdict, numeric score, reasons, and component sub-scores

## Main endpoints

- **`GET /health`**: lightweight health probe
- **`POST /analyze/file`**: preferred endpoint for uploaded `.eml` and `.msg` files
- **`POST /analyze/raw-eml`**: analyze a raw EML string
- **`POST /analyze/base64-eml`**: analyze a base64-encoded EML payload
- **`POST /analyze/components`**: analyze synthetic email parts when you already extracted content elsewhere
- **`POST /debug/parse`**: parsing/debug endpoint that returns extracted content without changing analyzer behavior

## Verdict model

- **`legit`**: no meaningful phishing evidence after risk/trust balancing
- **`suspicious`**: concerning signals exist, but evidence is not strong enough for a phishing verdict
- **`phishing`**: strong structural evidence or a high-confidence malicious combination was detected

## Score interpretation

The score is a bounded severity score from **0 to 100**. It is derived from risk signals and trust signals, not from a probability model.

- **0-39**: usually benign or weakly suspicious
- **40-69**: suspicious, worth manual review
- **70-100**: severe risk range

A message can still be classified as **`phishing`** below 70 when a strong structural phishing flag is present.

## File and payload limits

- uploads larger than the configured maximum are rejected with **HTTP 413**
- invalid base64 payloads are rejected with **HTTP 400**
- `.eml` and `.msg` are supported on the file endpoint

## Notes

- reputation checks can query external sources depending on runtime configuration
- temporary uploaded files are cleaned up after analysis
- attachment persistence is disabled by default unless explicitly enabled in configuration
""".strip()

app = FastAPI(
    title="PhishGuard API",
    version="3.2.0",
    summary="Local phishing-analysis API for .eml and .msg email messages.",
    description=API_DESCRIPTION,
    docs_url=None,
    redoc_url=None,
    openapi_tags=[
        {"name": "system", "description": "Operational endpoints such as health checks."},
        {"name": "analysis", "description": "Primary phishing-analysis endpoints returning extracted data and verdicts."},
        {"name": "debug", "description": "Inspection helpers intended for parser validation and troubleshooting."},
    ],
    contact={"name": "PhishGuard", "url": "https://example.invalid/phishguard-local"},
    license_info={"name": "Local project distribution"},
)
_CORS_ORIGINS_ENV = os.getenv("PHISHGUARD_CORS_ORIGINS", "")
_CORS_ORIGINS: list[str] = [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip()] if _CORS_ORIGINS_ENV else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


DOCS_HEAD = """
<style>
:root {
  --phg-bg: #0f172a;
  --phg-bg-soft: #111827;
  --phg-surface: #ffffff;
  --phg-surface-soft: #f8fafc;
  --phg-border: #dbe4f0;
  --phg-text: #0f172a;
  --phg-muted: #475569;
  --phg-accent: #7c3aed;
  --phg-accent-2: #4f46e5;
  --phg-code: #0f172a;
}
body, .swagger-ui {
  background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%) !important;
  color: var(--phg-text) !important;
}
.swagger-ui .topbar {
  background: linear-gradient(135deg, var(--phg-accent), var(--phg-accent-2)) !important;
  box-shadow: 0 16px 38px rgba(79, 70, 229, 0.22);
}
.swagger-ui .topbar .download-url-wrapper { display: none !important; }
.swagger-ui .topbar-wrapper img { content: url('https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png'); max-height: 34px; }
.swagger-ui .information-container.wrapper,
.swagger-ui .scheme-container,
.swagger-ui .wrapper {
  max-width: 1240px !important;
}
.swagger-ui .information-container { padding-top: 26px !important; }
.swagger-ui .info { margin: 0 0 30px 0 !important; }
.swagger-ui .info .title {
  font-size: 38px !important;
  font-weight: 800 !important;
  letter-spacing: -0.03em;
  color: var(--phg-text) !important;
}
.swagger-ui .info .base-url {
  background: rgba(124, 58, 237, 0.08) !important;
  color: var(--phg-accent) !important;
  border: 1px solid rgba(124, 58, 237, 0.12) !important;
  border-radius: 999px !important;
  padding: 6px 12px !important;
}
.swagger-ui .info p, .swagger-ui .info li, .swagger-ui .renderedMarkdown p, .swagger-ui .renderedMarkdown li {
  color: var(--phg-muted) !important;
  line-height: 1.75 !important;
  font-size: 15px !important;
}
.swagger-ui .scheme-container {
  background: rgba(255,255,255,0.82) !important;
  border: 1px solid var(--phg-border);
  border-radius: 20px;
  box-shadow: 0 16px 40px rgba(15, 23, 42, 0.08);
  padding: 18px 24px !important;
  margin: 16px auto 28px !important;
}
.swagger-ui .opblock-tag {
  border-bottom: 1px solid rgba(148,163,184,0.18) !important;
  padding: 20px 0 14px !important;
  color: var(--phg-text) !important;
  font-size: 24px !important;
  font-weight: 800 !important;
}
.swagger-ui .opblock {
  border-radius: 20px !important;
  border-width: 1px !important;
  box-shadow: 0 14px 32px rgba(15, 23, 42, 0.06);
  margin-bottom: 18px !important;
  overflow: hidden;
}
.swagger-ui .opblock .opblock-summary {
  padding: 18px 20px !important;
}
.swagger-ui .opblock .opblock-summary-method {
  border-radius: 999px !important;
  min-width: 80px !important;
  text-align: center;
  font-weight: 800 !important;
}
.swagger-ui .opblock .opblock-summary-path,
.swagger-ui .opblock .opblock-summary-description {
  font-size: 15px !important;
}
.swagger-ui .opblock-body { padding: 0 20px 20px !important; }
.swagger-ui section.models {
  border: 1px solid var(--phg-border);
  border-radius: 24px;
  background: rgba(255,255,255,0.9);
  box-shadow: 0 16px 40px rgba(15, 23, 42, 0.07);
  padding: 10px 16px 16px !important;
}
.swagger-ui .model-box, .swagger-ui .highlight-code, .swagger-ui .microlight, .swagger-ui pre {
  border-radius: 16px !important;
}
.swagger-ui .btn {
  border-radius: 12px !important;
  font-weight: 700 !important;
}
.swagger-ui input[type=text], .swagger-ui textarea, .swagger-ui select {
  border-radius: 12px !important;
  border: 1px solid var(--phg-border) !important;
}
.swagger-ui .response-col_status { font-weight: 700 !important; }
.swagger-ui .responses-inner h4, .swagger-ui .responses-inner h5, .swagger-ui .opblock-section-header h4 {
  color: var(--phg-text) !important;
}
.redoc-wrap { background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%) !important; }
.menu-content {
  background: rgba(255,255,255,0.94) !important;
  border-right: 1px solid var(--phg-border) !important;
}
.menu-content label, .menu-content span, .menu-content a, .menu-content div { color: var(--phg-text) !important; }
.api-info {
  background: transparent !important;
}
.api-info h1, .api-info h2, .api-info h3 {
  color: var(--phg-text) !important;
  letter-spacing: -0.02em;
}
.api-info p, .api-info li, .api-content p, .api-content li {
  color: var(--phg-muted) !important;
  line-height: 1.75 !important;
}
.api-content pre, .api-content code { border-radius: 16px !important; }
@media (max-width: 900px) {
  .swagger-ui .info .title { font-size: 30px !important; }
  .swagger-ui .opblock .opblock-summary { padding: 16px !important; }
}
</style>
<script>
window.addEventListener('load', () => {
  const interval = setInterval(() => {
    const title = document.querySelector('.swagger-ui .info .title');
    if (title && !document.getElementById('phg-docs-intro')) {
      const intro = document.createElement('div');
      intro.id = 'phg-docs-intro';
      intro.style.cssText = 'margin:16px 0 28px;padding:18px 20px;border-radius:18px;background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.12);color:#334155;line-height:1.7;font-size:15px;';
      intro.innerHTML = '<strong style="display:block;color:#0f172a;font-size:16px;margin-bottom:8px;">Guide rapide</strong>Utilise <code style="background:#fff;padding:2px 6px;border-radius:8px;border:1px solid #e2e8f0;">POST /analyze/file</code> pour un fichier <code style="background:#fff;padding:2px 6px;border-radius:8px;border:1px solid #e2e8f0;">.eml</code> ou <code style="background:#fff;padding:2px 6px;border-radius:8px;border:1px solid #e2e8f0;">.msg</code>. <code style="background:#fff;padding:2px 6px;border-radius:8px;border:1px solid #e2e8f0;">/analyze/base64-eml</code> est pratique pour une extension navigateur. Le résultat contient le verdict, le score, la confiance et les raisons détaillées.';
      title.parentElement.appendChild(intro);
    }
    const redocTitle = document.querySelector('.api-info');
    if (redocTitle && !document.getElementById('phg-redoc-intro')) {
      const intro = document.createElement('div');
      intro.id = 'phg-redoc-intro';
      intro.style.cssText = 'margin:18px 0 26px;padding:18px 20px;border-radius:18px;background:rgba(124,58,237,0.08);border:1px solid rgba(124,58,237,0.12);color:#334155;line-height:1.75;font-size:15px;';
      intro.innerHTML = '<strong style="display:block;color:#0f172a;font-size:16px;margin-bottom:8px;">Comment utiliser cette API</strong>Commence par <code style="background:#fff;padding:2px 6px;border-radius:8px;border:1px solid #e2e8f0;">GET /health</code>, puis utilise <code style="background:#fff;padding:2px 6px;border-radius:8px;border:1px solid #e2e8f0;">POST /analyze/file</code> pour un message réel. Les autres endpoints servent aux intégrations plus spécialisées.';
      redocTitle.appendChild(intro);
    }
    if (document.querySelector('.swagger-ui') || document.querySelector('.redoc-wrap')) clearInterval(interval);
  }, 120);
});
</script>
"""



def _to_jsonable(obj: Any):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


def _enforce_size(data: bytes) -> None:
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"File too large ({len(data)} bytes > {settings.max_upload_bytes})")


class ComponentsRequest(BaseModel):
    """Synthetic email components for callers that already extracted the message content."""

    subject: str = Field(default="", description="Message subject line.")
    text: str = Field(default="", description="Plain-text message body used by the text analyzer.")
    raw_headers: str = Field(default="", description="Complete raw RFC 822 header block as a single string.")
    urls: list[str] = Field(default_factory=list, description="URLs already extracted from the message.")


class RawEmailRequest(BaseModel):
    """Raw EML payload as a UTF-8 string."""

    raw_eml: str = Field(..., description="Full RFC 822 message content serialized as text.")


class Base64EmailRequest(BaseModel):
    """Base64-encoded EML payload."""

    base64_eml: str = Field(..., description="Base64 representation of the full EML file.")
    filename: str = Field(default="message.eml", description="Optional filename used for reporting and extension checks.")


class AttachmentInfoModel(BaseModel):
    filename: str = Field(description="Attachment filename as parsed from the email.")
    saved_path: str = Field(description="Filesystem path when persistence is enabled, otherwise empty or transient.")
    size_bytes: int = Field(description="Attachment size in bytes.")
    content_type: str = Field(default="", description="Declared MIME content type.")


class ExtractedEmailDataModel(BaseModel):
    file_path: str
    file_type: str
    subject: str
    sender: str
    to: list[str]
    cc: list[str]
    bcc: list[str]
    date: str
    raw_headers: str
    body_text: str
    body_html: str
    urls: list[str]
    emails_found_in_body: list[str]
    ips_found_in_body: list[str]
    attachments: list[AttachmentInfoModel] = Field(default_factory=list)
    technical_details: dict[str, Any] = Field(default_factory=dict)
    parse_warnings: list[str] = Field(default_factory=list)


class AnalysisResultModel(BaseModel):
    verdict: Literal["legit", "suspicious", "phishing"] = Field(description="Final phishing verdict.")
    score: int = Field(ge=0, le=100, description="Bounded final severity score.")
    confidence: Literal["low", "medium", "high"] = Field(description="Analyzer confidence band.")
    analysis_status: str = Field(description="Operational status string returned by the analyzer.")
    sub_scores: dict[str, int] = Field(default_factory=dict, description="Per-module scores such as text, headers, urls, reputation, and benign trust signals.")
    reasons: list[str] = Field(default_factory=list, description="Human-readable reason strings explaining why the score moved.")
    indicators: dict[str, Any] = Field(default_factory=dict, description="Structured indicators such as reputation hits, domain facts, or structural flags.")


class AnalysisEnvelope(BaseModel):
    extracted_email: ExtractedEmailDataModel
    analysis_result: AnalysisResultModel
    extraction_warnings: list[str] = Field(default_factory=list)
    analysis_status: str
    confidence: str


class ParseEnvelope(BaseModel):
    extracted_email: ExtractedEmailDataModel


class HealthResponse(BaseModel):
    status: str = Field(description="Service health state.")


ANALYSIS_RESPONSE_EXAMPLE = {
    "extracted_email": {
        "file_path": "message.eml",
        "file_type": ".eml",
        "subject": "RE: Last Chance 🎯",
        "sender": "charlesrosskwic@hotmail.com",
        "to": ["victim@example.com"],
        "cc": [],
        "bcc": [],
        "date": "Tue, 19 Mar 2026 10:15:00 +0000",
        "raw_headers": "From: ...\nSubject: ...",
        "body_text": "Claim your Lidl gift now...",
        "body_html": "<html>...</html>",
        "urls": ["https://tracking.example/path", "http://promo.example/claim"],
        "emails_found_in_body": [],
        "ips_found_in_body": [],
        "attachments": [],
        "technical_details": {"source": "eml", "received_hops": 3},
        "parse_warnings": [],
    },
    "analysis_result": {
        "verdict": "phishing",
        "score": 84,
        "confidence": "high",
        "analysis_status": "completed",
        "sub_scores": {"text": 18, "headers": 22, "urls": 24, "reputation": 20, "benign": -8},
        "reasons": [
            "[header] Forged reply-chain / thread mismatch detected",
            "[url] Multiple suspicious tracking URLs found",
            "[reputation] URL hit on external reputation source",
        ],
        "indicators": {"structural_flag": True, "reputation_hits": ["openphish"]},
    },
    "extraction_warnings": [],
    "analysis_status": "completed",
    "confidence": "high",
}


@app.get(
    "/health",
    tags=["system"],
    summary="Health check",
    description="Returns a minimal status payload so local callers, reverse proxies, and tests can verify that the API process is alive.",
    response_model=HealthResponse,
)
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/debug/parse",
    tags=["debug"],
    summary="Parse an uploaded email without focusing on the final verdict",
    description="Accepts `.eml` or `.msg`, runs the parser, and returns the extracted email structure. This is useful when validating headers, URLs, HTML parsing, attachment extraction, and parser warnings independently from phishing scoring.",
    response_model=ParseEnvelope,
)
async def debug_parse(file: UploadFile = File(..., description="Email file to parse. Supported formats: `.eml`, `.msg`.")):
    filename = file.filename or "message.eml"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".eml", ".msg"}:
        raise HTTPException(status_code=400, detail="Only .eml and .msg files are supported")
    data = await file.read()
    _enforce_size(data)

    if ext == ".eml":
        extracted = extractor.extract_raw_eml_bytes(data, filename)
        return {"extracted_email": _to_jsonable(extracted)}

    with tempfile.NamedTemporaryFile(prefix="phg_dbg_", suffix=ext, dir=settings.temp_dir, delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        extracted = extractor.extract(tmp_path)
        return {"extracted_email": _to_jsonable(extracted)}
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


@app.post(
    "/analyze/file",
    tags=["analysis"],
    summary="Analyze an uploaded .eml or .msg file",
    description="Preferred endpoint for real message files. The API parses the uploaded email, extracts technical artifacts, runs the phishing analyzers, and returns both the extracted message and the final analysis envelope.",
    response_model=AnalysisEnvelope,
    responses={400: {"description": "Unsupported file extension or malformed request."}, 413: {"description": "Upload exceeded the configured maximum size."}},
    openapi_extra={"requestBody": {"content": {"multipart/form-data": {"example": {"file": "sample.eml"}}}}, "x-codeSamples": [{"lang": "bash", "label": "curl", "source": "curl -X POST http://127.0.0.1:8000/analyze/file -F file=@message.eml"}]},
)
async def analyze_file(file: UploadFile = File(..., description="Email file to analyze. Supported formats: `.eml`, `.msg`.")):
    filename = file.filename or "message.eml"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".eml", ".msg"}:
        raise HTTPException(status_code=400, detail="Only .eml and .msg files are supported")

    data = await file.read()
    _enforce_size(data)

    if ext == ".eml":
        extracted = extractor.extract_raw_eml_bytes(data, filename)
    else:
        os.makedirs(settings.temp_dir, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="phg_api_", suffix=ext, dir=settings.temp_dir, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            extracted = extractor.extract(tmp_path)
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "extraction_warnings": extracted.parse_warnings,
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }


@app.post(
    "/analyze/raw-eml",
    tags=["analysis"],
    summary="Analyze a raw EML string",
    description="Accepts a full RFC 822 message as text. This is useful for local tooling that already has the EML content in memory and does not want to upload a file.",
    response_model=AnalysisEnvelope,
    responses={413: {"description": "Payload exceeded the configured maximum size."}},
)
def analyze_raw_eml(payload: RawEmailRequest):
    raw_bytes = payload.raw_eml.encode("utf-8", errors="replace")
    _enforce_size(raw_bytes)
    extracted = extractor.extract_raw_eml_bytes(raw_bytes, "raw_input.eml")
    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "extraction_warnings": extracted.parse_warnings,
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }


@app.post(
    "/analyze/base64-eml",
    tags=["analysis"],
    summary="Analyze a base64-encoded EML payload",
    description="Accepts an EML file encoded as base64. This is useful for browser extensions and clients that prefer binary-safe JSON transport.",
    response_model=AnalysisEnvelope,
    responses={400: {"description": "Invalid base64 payload."}, 413: {"description": "Decoded payload exceeded the configured maximum size."}},
)
def analyze_base64_eml(payload: Base64EmailRequest):
    try:
        raw_bytes = base64.b64decode(payload.base64_eml, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {exc}")
    _enforce_size(raw_bytes)
    extracted = extractor.extract_raw_eml_bytes(raw_bytes, payload.filename)
    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "extraction_warnings": extracted.parse_warnings,
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }


@app.post(
    "/analyze/components",
    tags=["analysis"],
    summary="Analyze pre-extracted email components",
    description="Runs the phishing engine on synthetic or externally extracted message parts. Use this when another parser already produced headers, text, and URLs and you only need PhishGuard scoring.",
    response_model=AnalysisEnvelope,
)
def analyze_components(payload: ComponentsRequest):
    from .phishguard.models import ExtractedEmailData

    extracted = ExtractedEmailData(
        file_path="components",
        file_type="virtual",
        subject=payload.subject,
        sender="",
        to=[],
        cc=[],
        bcc=[],
        date="",
        raw_headers=payload.raw_headers,
        body_text=payload.text,
        body_html="",
        urls=payload.urls,
        emails_found_in_body=[],
        ips_found_in_body=[],
        attachments=[],
        technical_details={"source": "components_endpoint", "received_hops": -1},
        parse_warnings=[],
    )
    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "extraction_warnings": [],
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }


app.openapi_schema = None
_original_openapi = app.openapi


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = _original_openapi()
    schema.setdefault("info", {})["x-logo"] = {"url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"}
    schema["info"]["description"] = API_DESCRIPTION
    analysis_schema = schema.get("components", {}).get("schemas", {}).get("AnalysisEnvelope", {})
    if analysis_schema is not None:
        analysis_schema.setdefault("example", ANALYSIS_RESPONSE_EXAMPLE)
    for path in ("/analyze/file", "/analyze/raw-eml", "/analyze/base64-eml", "/analyze/components"):
        try:
            schema["paths"][path]["post"]["responses"]["200"]["content"]["application/json"]["example"] = ANALYSIS_RESPONSE_EXAMPLE
        except KeyError:
            pass
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _custom_openapi


@app.get("/docs", include_in_schema=False)
def overridden_swagger() -> HTMLResponse:
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Swagger UI",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        swagger_ui_parameters={
            "persistAuthorization": True,
            "defaultModelsExpandDepth": 1,
            "defaultModelExpandDepth": 2,
            "displayRequestDuration": True,
            "filter": True,
            "syntaxHighlight.theme": "obsidian",
            "docExpansion": "list",
            "tryItOutEnabled": True,
        },
    )
    body = html.body.decode("utf-8").replace("</head>", DOCS_HEAD + "</head>")
    safe_headers = {k: v for k, v in dict(html.headers).items() if k.lower() != "content-length"}
    return HTMLResponse(body, status_code=html.status_code, headers=safe_headers)


@app.get("/redoc", include_in_schema=False)
def overridden_redoc() -> HTMLResponse:
    html = get_redoc_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - ReDoc",
        redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        with_google_fonts=True,
    )
    body = html.body.decode("utf-8").replace("</head>", DOCS_HEAD + "</head>")
    safe_headers = {k: v for k, v in dict(html.headers).items() if k.lower() != "content-length"}
    return HTMLResponse(body, status_code=html.status_code, headers=safe_headers)
