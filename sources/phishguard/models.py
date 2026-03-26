#Projet : PhishGuard
#Auteurs : Myrddin Bellion, Ilyan Kassous

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttachmentInfo:
    filename: str
    saved_path: str
    size_bytes: int
    content_type: str = ""


@dataclass
class ExtractedEmailData:
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
    attachments: list[AttachmentInfo] = field(default_factory=list)
    technical_details: dict[str, Any] = field(default_factory=dict)
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    verdict: str
    score: int
    confidence: str
    analysis_status: str
    sub_scores: dict[str, int] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    indicators: dict[str, Any] = field(default_factory=dict)
