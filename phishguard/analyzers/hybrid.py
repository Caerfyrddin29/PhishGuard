from __future__ import annotations

from ..config import Settings
from ..models import AnalysisResult, ExtractedEmailData
from .attachment_analyzer import analyze_attachments
from .domain_analyzer import analyze_domains
from .header_analyzer import analyze_headers
from .ml import analyze_ml
from .reputation_analyzer import analyze_reputation
from .text_analyzer import analyze_text
from .url_analyzer import analyze_urls


class HybridPhishingAnalyzer:
    def __init__(self, settings: Settings):
        self.settings = settings

    def analyze_extracted(self, extracted: ExtractedEmailData) -> AnalysisResult:
        reasons: list[str] = []
        sub: dict[str, int] = {}

        text_s   = analyze_text(extracted)
        hdr_s    = analyze_headers(extracted)
        url_s    = analyze_urls(extracted)
        att_s    = analyze_attachments(extracted)
        ml_s     = analyze_ml(extracted, self.settings)
        domain_s = analyze_domains(extracted, self.settings)
        rep_s    = analyze_reputation(extracted)

        sub["text"]        = text_s.score
        sub["headers"]     = hdr_s.score
        sub["url"]         = url_s.score
        sub["attachments"] = att_s.score
        sub["ml"]          = ml_s.score
        sub["domain"]      = domain_s.score
        sub["reputation"]  = rep_s.score

        reasons.extend(text_s.reasons)
        reasons.extend(hdr_s.reasons)
        reasons.extend(url_s.reasons)
        reasons.extend(att_s.reasons)
        reasons.extend(ml_s.reasons)
        reasons.extend(domain_s.reasons)
        reasons.extend(rep_s.reasons)

        total = min(100, sum(sub.values()))
        extraction_ok = bool(
            extracted.sender or extracted.subject
            or extracted.body_text or extracted.body_html
        )

        if not extraction_ok:
            return AnalysisResult(
                verdict="inconclusive",
                score=2,
                confidence="low",
                analysis_status="inconclusive",
                sub_scores=sub,
                reasons=["Extraction failed or empty message."] + reasons,
                indicators={"ml_probability": ml_s.probability},
            )

        if total >= 70:
            verdict, confidence = "phishing", "high"
        elif total >= 40:
            verdict, confidence = "suspicious", "medium"
        else:
            verdict = "legit"
            confidence = "low" if total < 15 else "medium"

        return AnalysisResult(
            verdict=verdict,
            score=total,
            confidence=confidence,
            analysis_status="ok",
            sub_scores=sub,
            reasons=reasons[:40],
            indicators={"ml_probability": ml_s.probability, "urls": extracted.urls},
        )
