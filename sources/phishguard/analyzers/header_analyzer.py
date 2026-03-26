#Projet : PhishGuard
#Auteurs : Myrddin Bellion, Ilyan Kassous

from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parseaddr

from ..domain_tools import registrable_domain
from ..models import ExtractedEmailData


@dataclass
class HeaderSignals:
    score: int
    reasons: list[str]


_FREE_WEBMAIL = {
    "hotmail.com", "hotmail.fr", "hotmail.co.uk", "hotmail.es", "hotmail.de",
    "hotmail.it", "hotmail.nl", "hotmail.be", "hotmail.se", "hotmail.no",
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "yahoo.co.uk",
    "yahoo.es", "yahoo.de", "yahoo.it", "yahoo.co.jp", "yahoo.com.br",
    "yahoo.ca", "outlook.com", "live.com", "live.fr", "live.co.uk", "live.nl",
    "live.it", "live.be", "msn.com", "passport.com", "aol.com", "aol.fr",
    "aol.co.uk", "mail.com", "email.com", "usa.com", "icloud.com", "me.com",
    "mac.com", "gmx.com", "gmx.de", "gmx.fr", "gmx.net", "orange.fr", "free.fr",
    "laposte.net", "protonmail.com", "proton.me", "tutanota.com", "zoho.com",
}

_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com", "amazon.fr", "amazon.co.uk", "amazon.de", "amazon.es", "amazon.it"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "stripe": ["stripe.com"],
    "dhl": ["dhl.com", "dhl.fr", "dhl.de", "dhl.co.uk"],
    "fedex": ["fedex.com"],
    "la poste": ["laposte.fr", "laposte.net"],
    "colissimo": ["laposte.fr", "colissimo.fr"],
    "ameli": ["ameli.fr", "assurance-maladie.fr"],
    "credit agricole": ["credit-agricole.fr", "credit-agricole.com"],
    "societe generale": ["societegenerale.fr", "sg.fr"],
    "lcl": ["lcl.fr", "lcl.com"],
}


def _get_raw_header(raw_headers: str, name: str) -> str:
    pattern = re.compile(rf"^{re.escape(name)}\s*:\s*(.+?)(?=\n\S|\Z)", re.IGNORECASE | re.MULTILINE | re.DOTALL)
    m = pattern.search(raw_headers or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _sender_domain(email_addr: str) -> str:
    parts = email_addr.strip().lower().split("@")
    return parts[-1] if len(parts) == 2 else ""


def _check_display_name_spoofing(raw_headers: str, sender_email: str) -> tuple[bool, str]:
    from_raw = _get_raw_header(raw_headers, "From")
    display_name, _ = parseaddr(from_raw)
    display_name = display_name.lower()
    domain = _sender_domain(sender_email)
    reg = registrable_domain(domain)
    for brand, legit_domains in _BRAND_DOMAINS.items():
        if re.search(r"\b" + re.escape(brand) + r"\b", display_name):
            legit_regs = {registrable_domain(d) for d in legit_domains}
            if reg and reg not in legit_regs:
                return True, f"Display name '{display_name}' claims '{brand}' but sent from '{domain}'"
    return False, ""


def _check_reply_to_mismatch(raw_headers: str, sender_email: str) -> tuple[bool, str]:
    reply_to_raw = _get_raw_header(raw_headers, "Reply-To")
    if not reply_to_raw:
        return False, ""
    _, reply_addr = parseaddr(reply_to_raw)
    reply_domain = registrable_domain(_sender_domain(reply_addr))
    from_domain = registrable_domain(_sender_domain(sender_email))
    if reply_domain and from_domain and reply_domain != from_domain:
        return True, f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})"
    return False, ""


def _check_return_path_mismatch(raw_headers: str, sender_email: str) -> tuple[bool, str]:
    rp_raw = _get_raw_header(raw_headers, "Return-Path")
    if not rp_raw:
        return False, ""
    rp_raw = rp_raw.strip("<>").strip()
    rp_domain = registrable_domain(_sender_domain(rp_raw))
    from_domain = registrable_domain(_sender_domain(sender_email))
    if rp_domain and from_domain and rp_domain != from_domain:
        return True, f"Return-Path registrable domain ({rp_domain}) differs from From domain ({from_domain})"
    return False, ""




def _check_thread_brand_mismatch(raw_headers: str, sender_email: str, subject: str) -> tuple[bool, str]:
    sender_reg = registrable_domain(_sender_domain(sender_email))
    if not sender_reg:
        return False, ""
    # Look for foreign brand domains in threading headers; common in forged reply-chain scams.
    vals = []
    for name in ("Message-ID", "In-Reply-To", "References", "Thread-Topic"):
        v = _get_raw_header(raw_headers, name)
        if v:
            vals.append(v)
    hay = " ".join(vals).lower()
    if not hay:
        return False, ""

    for brand, legit_domains in _BRAND_DOMAINS.items():
        legit_regs = {registrable_domain(d) for d in legit_domains}
        if sender_reg in legit_regs:
            continue
        for dom in legit_domains:
            dom_l = dom.lower()
            reg = registrable_domain(dom_l)
            if dom_l in hay or (reg and reg in hay):
                subj = (subject or "").lower()
                if subj.startswith(("re:", "fw:", "fwd:")) or "in-reply-to" in raw_headers.lower() or "references" in raw_headers.lower():
                    return True, f"Threading headers reference {brand}/{reg or dom_l} but sender domain is {sender_reg}"
    return False, ""


def _check_auth_results(raw_headers: str) -> list[tuple[str, int]]:
    issues: list[tuple[str, int]] = []
    auth_raw = _get_raw_header(raw_headers, "Authentication-Results")
    if not auth_raw:
        return []
    auth_lower = auth_raw.lower()
    if "dkim=fail" in auth_lower:
        issues.append(("[header] DKIM signature failed", 8))
    elif "dkim=none" in auth_lower:
        issues.append(("[header] No DKIM signature present", 3))
    if "spf=fail" in auth_lower:
        issues.append(("[header] SPF hard-failed", 8))
    elif "spf=softfail" in auth_lower:
        issues.append(("[header] SPF soft-failed", 4))
    if "dmarc=fail" in auth_lower:
        issues.append(("[header] DMARC failed", 10))
    return issues


def _check_hop_anomalies(raw_headers: str, hop_count: int) -> list[str]:
    issues: list[str] = []
    if hop_count < 0:
        return issues
    if hop_count == 0:
        issues.append("[header] No Received headers — possibly hand-crafted")
        return issues
    if hop_count == 1:
        issues.append("[header] Only 1 Received hop — unusual for external mail")
    if hop_count >= 10:
        issues.append(f"[header] Very high hop count ({hop_count}) — possible routing abuse")
    elif hop_count >= 6:
        issues.append(f"[header] High hop count ({hop_count})")
    return issues


def analyze_headers(extracted: ExtractedEmailData) -> HeaderSignals:
    reasons: list[str] = []
    score = 0
    raw = extracted.raw_headers or ""

    if not extracted.sender:
        reasons.append("[header] Missing From")
        score += 10
    if not extracted.to:
        reasons.append("[header] Missing To")
        score += 5
    if not extracted.subject:
        reasons.append("[header] Missing Subject")
        score += 5
    if not raw:
        reasons.append("[header] Headers missing or unparseable")
        score += 8

    if extracted.sender:
        domain = registrable_domain(_sender_domain(extracted.sender))
        if domain in _FREE_WEBMAIL:
            reasons.append(f"[header] Free webmail sender: {domain}")
            score += 6
        if raw:
            spoofed, msg = _check_display_name_spoofing(raw, extracted.sender)
            if spoofed:
                reasons.append(f"[header] Display name spoofing: {msg}")
                score += 15
            mismatch, msg = _check_reply_to_mismatch(raw, extracted.sender)
            if mismatch:
                reasons.append(f"[header] Reply-To mismatch: {msg}")
                score += 4
            mismatch, msg = _check_return_path_mismatch(raw, extracted.sender)
            if mismatch:
                reasons.append(f"[header] Return-Path mismatch: {msg}")
                score += 3
            thread_mismatch, msg = _check_thread_brand_mismatch(raw, extracted.sender, extracted.subject)
            if thread_mismatch:
                reasons.append(f"[header] Forged reply-chain / thread mismatch: {msg}")
                score += 12

    if raw:
        for reason, delta in _check_auth_results(raw):
            reasons.append(reason)
            score += delta

    hops = int(extracted.technical_details.get("received_hops", 0) or 0)
    for issue in _check_hop_anomalies(raw, hops):
        reasons.append(issue)
        score += 3

    return HeaderSignals(score=min(35, score), reasons=reasons)
