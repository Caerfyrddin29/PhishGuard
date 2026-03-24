#Projet : PhishGuard
#Auteurs : Équipe PhishGuard

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from urllib.parse import urlparse

from ..domain_tools import registrable_domain
from ..models import ExtractedEmailData


@dataclass
class BenignSignals:
    score: int
    reasons: list[str]


_UNSUB_HINTS = ("unsubscribe", "désabonner", "manage preferences", "préférences")


def _sender_domain(extracted: ExtractedEmailData) -> str:
    sender = parseaddr(extracted.sender or "")[1] or extracted.sender or ""
    if "@" not in sender:
        return ""
    return registrable_domain(sender.split("@", 1)[1])


def _header_blob(extracted: ExtractedEmailData) -> str:
    return (extracted.raw_headers or "").lower()


def analyze_benign(extracted: ExtractedEmailData) -> BenignSignals:
    reasons: list[str] = []
    trust = 0
    headers = _header_blob(extracted)

    if "dkim=pass" in headers:
        trust += 5
        reasons.append("[benign] DKIM pass")
    if "spf=pass" in headers:
        trust += 3
        reasons.append("[benign] SPF pass")
    if "dmarc=pass" in headers:
        trust += 5
        reasons.append("[benign] DMARC pass")

    urls = extracted.urls or []
    if urls and all(u.lower().startswith("https://") for u in urls):
        trust += 3
        reasons.append("[benign] All URLs use HTTPS")

    combined = f"{(extracted.body_text or '').lower()}\n{(extracted.body_html or '').lower()}"
    if any(hint in combined for hint in _UNSUB_HINTS):
        trust += 3
        reasons.append("[benign] Newsletter footer / unsubscribe detected")

    sender_reg = _sender_domain(extracted)
    url_regs = set()
    for url in urls[:25]:
        try:
            host = (urlparse(url).netloc or "").split(":")[0].lower()
        except Exception:
            host = ""
        reg = registrable_domain(host)
        if reg:
            url_regs.add(reg)
    if sender_reg and url_regs and sender_reg in url_regs:
        trust += 5
        reasons.append(f"[benign] Sender/link domain coherence: {sender_reg}")

    return BenignSignals(score=min(24, trust), reasons=reasons)
