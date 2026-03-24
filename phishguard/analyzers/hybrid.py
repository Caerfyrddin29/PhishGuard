#Projet : PhishGuard
#Auteurs : Équipe PhishGuard

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..config import Settings
from ..models import AnalysisResult, ExtractedEmailData
from .attachment_analyzer import analyze_attachments
from .benign_analyzer import analyze_benign
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
        extraction_ok = bool(extracted.sender or extracted.subject or extracted.body_text or extracted.body_html)
        if not extraction_ok:
            return AnalysisResult(
                verdict="inconclusive",
                score=2,
                confidence="low",
                analysis_status="inconclusive",
                sub_scores={},
                reasons=["Extraction failed or empty message."],
                indicators={},
            )

        with ThreadPoolExecutor(max_workers=7) as ex:
            futures = {
                "text": ex.submit(analyze_text, extracted),
                "headers": ex.submit(analyze_headers, extracted),
                "url": ex.submit(analyze_urls, extracted),
                "attachments": ex.submit(analyze_attachments, extracted),
                "ml": ex.submit(analyze_ml, extracted, self.settings),
                "domain": ex.submit(analyze_domains, extracted, self.settings),
                "reputation": ex.submit(analyze_reputation, extracted),
                "benign": ex.submit(analyze_benign, extracted),
            }
            results = {name: fut.result() for name, fut in futures.items()}

        sub = {
            "text": results["text"].score,
            "headers": results["headers"].score,
            "url": results["url"].score,
            "attachments": results["attachments"].score,
            "ml": results["ml"].score,
            "domain": results["domain"].score,
            "reputation": results["reputation"].score,
            "benign": -results["benign"].score,
        }

        reasons: list[str] = []
        for key in ("text", "headers", "url", "attachments", "ml", "domain", "reputation", "benign"):
            reasons.extend(results[key].reasons)

        risk_total = sum(v for k, v in sub.items() if k != "benign")
        trust_total = results["benign"].score
        net_total = max(0, min(100, risk_total - trust_total))

        structural_flag = (
            results["reputation"].score >= 30
            or results["domain"].score >= 20
            or results["attachments"].score >= 20
            or any(
                "Brand impersonation" in r
                or "Homoglyph" in r
                or "Display name spoofing" in r
                or "IP-based URL" in r
                or "Forged reply-chain" in r
                for r in reasons
            )
        )

        forged_reply_chain = any("Forged reply-chain" in r for r in reasons)

        if (structural_flag and net_total >= 70) or (forged_reply_chain and net_total >= 45):
            verdict, confidence = "phishing", ("high" if net_total >= 70 else "medium")
        elif net_total >= 35:
            verdict, confidence = "suspicious", "medium"
        else:
            verdict = "legit"
            confidence = "low" if net_total < 15 else "medium"

        return AnalysisResult(
            verdict=verdict,
            score=net_total,
            confidence=confidence,
            analysis_status="ok",
            sub_scores=sub,
            reasons=reasons[:50],
            indicators={
                "ml_probability": getattr(results["ml"], "probability", None),
                "urls": extracted.urls,
                "risk_total": risk_total,
                "trust_total": trust_total,
                "structural_flag": structural_flag,
            },
        )
