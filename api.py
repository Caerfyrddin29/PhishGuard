from __future__ import annotations

import base64
import os
import tempfile
from dataclasses import asdict, is_dataclass
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from phishguard.config import Settings
from phishguard.parser import EmailFileExtractor
from phishguard.analyzers.hybrid import HybridPhishingAnalyzer


settings = Settings()
extractor = EmailFileExtractor(settings=settings)
analyzer = HybridPhishingAnalyzer(settings=settings)

app = FastAPI(title="PhishGuard API", version="3.0.0")
_CORS_ORIGINS = [
    o.strip()
    for o in os.getenv("PHISHGUARD_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _to_jsonable(obj: Any):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


class ComponentsRequest(BaseModel):
    subject: str = ""
    text: str = ""
    raw_headers: str = ""
    urls: list[str] = Field(default_factory=list)


class RawEmailRequest(BaseModel):
    raw_eml: str


class Base64EmailRequest(BaseModel):
    base64_eml: str
    filename: str = "message.eml"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/debug/parse")
async def debug_parse(file: UploadFile = File(...)):
    filename = file.filename or "message.eml"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".eml", ".msg"}:
        raise HTTPException(status_code=400, detail="Only .eml and .msg files are supported")
    data = await file.read()

    if ext == ".eml":
        extracted = extractor.extract_raw_eml_bytes(data, filename)
        return {"extracted_email": _to_jsonable(extracted)}

    with tempfile.NamedTemporaryFile(prefix="phg_dbg_", suffix=ext, delete=False) as tmp:
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


@app.post("/analyze/file")
async def analyze_file(file: UploadFile = File(...)):
    filename = file.filename or "message.eml"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".eml", ".msg"}:
        raise HTTPException(status_code=400, detail="Only .eml and .msg files are supported")

    data = await file.read()

    if ext == ".eml":
        extracted = extractor.extract_raw_eml_bytes(data, filename)
    else:
        with tempfile.NamedTemporaryFile(prefix="phg_api_", suffix=ext, delete=False) as tmp:
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


@app.post("/analyze/raw-eml")
def analyze_raw_eml(payload: RawEmailRequest):
    raw_bytes = payload.raw_eml.encode("utf-8", errors="replace")
    extracted = extractor.extract_raw_eml_bytes(raw_bytes, "raw_input.eml")
    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "extraction_warnings": extracted.parse_warnings,
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }


@app.post("/analyze/base64-eml")
def analyze_base64_eml(payload: Base64EmailRequest):
    try:
        raw_bytes = base64.b64decode(payload.base64_eml)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64 payload: {exc}")
    extracted = extractor.extract_raw_eml_bytes(raw_bytes, payload.filename)
    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "extraction_warnings": extracted.parse_warnings,
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }


@app.post("/analyze/components")
def analyze_components(payload: ComponentsRequest):
    from phishguard.models import ExtractedEmailData

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
        technical_details={"source": "components_endpoint"},
        parse_warnings=[],
    )
    result = analyzer.analyze_extracted(extracted)
    return {
        "extracted_email": _to_jsonable(extracted),
        "analysis_result": _to_jsonable(result),
        "analysis_status": result.analysis_status,
        "confidence": result.confidence,
    }
