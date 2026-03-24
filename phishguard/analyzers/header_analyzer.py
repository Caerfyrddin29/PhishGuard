from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parseaddr

from ..models import ExtractedEmailData


@dataclass
class HeaderSignals:
    score: int
    reasons: list[str]


_FREE_WEBMAIL = {
    "hotmail.com", "hotmail.fr", "hotmail.co.uk", "hotmail.es", "hotmail.de",
    "hotmail.it", "hotmail.nl", "hotmail.be", "hotmail.se", "hotmail.no",
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.fr", "yahoo.co.uk", "yahoo.es", "yahoo.de",
    "yahoo.it", "yahoo.co.jp", "yahoo.com.br", "yahoo.ca",
    "outlook.com", "live.com", "live.fr", "live.co.uk", "live.nl",
    "live.it", "live.be", "msn.com", "passport.com",
    "aol.com", "aol.fr", "aol.co.uk",
    "mail.com", "email.com", "usa.com", "myself.com",
    "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.de", "gmx.fr", "gmx.net", "gmx.at", "gmx.ch",
    "web.de", "t-online.de", "freenet.de",
    "libero.it", "virgilio.it", "tiscali.it",
    "laposte.net", "orange.fr", "wanadoo.fr", "free.fr",
    "sfr.fr", "bbox.fr", "neuf.fr", "numericable.fr",
    "yandex.com", "yandex.ru", "yandex.fr", "yandex.kz",
    "mail.ru", "inbox.ru", "list.ru", "bk.ru", "rambler.ru",
    "qq.com", "163.com", "126.com", "sina.com", "sohu.com",
    "protonmail.com", "proton.me", "tutanota.com", "tutanota.de",
    "zoho.com", "zohomail.com",
    "fastmail.com", "fastmail.fm",
    "mailfence.com", "hushmail.com",
}

# BUG FIX: short/ambiguous brand names ("free", "orange", "caf", "ups") removed
# from display-name check — they cause too many false positives.
# Only unambiguous, long-enough brand names are kept here.
# Each entry: brand_keyword -> list of legitimate sending domains (exact or suffix match).
_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal":           ["paypal.com"],
    "amazon":           ["amazon.com", "amazon.fr", "amazon.co.uk", "amazon.de",
                         "amazon.es", "amazon.it", "amazon.ca", "amazon.co.jp",
                         "amazon.com.br", "amazon.com.mx"],
    "apple":            ["apple.com", "icloud.com"],
    "microsoft":        ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
    "google":           ["google.com", "gmail.com", "googlemail.com"],
    "netflix":          ["netflix.com"],
    "facebook":         ["facebook.com", "fb.com", "meta.com"],
    "instagram":        ["instagram.com"],
    "twitter":          ["twitter.com", "x.com"],
    "linkedin":         ["linkedin.com"],
    "dropbox":          ["dropbox.com"],
    "docusign":         ["docusign.com", "docusign.net"],
    "dhl":              ["dhl.com", "dhl.fr", "dhl.de", "dhl.co.uk"],
    "fedex":            ["fedex.com"],
    "la poste":         ["laposte.fr", "laposte.net"],
    "colissimo":        ["laposte.fr", "colissimo.fr"],
    "ameli":            ["ameli.fr", "assurance-maladie.fr"],
    # BUG FIX: "impots" is unambiguous enough to keep
    "impots.gouv":      ["impots.gouv.fr", "dgfip.finances.gouv.fr"],
    "assurance maladie": ["ameli.fr", "assurance-maladie.fr"],
    "service-public":   ["service-public.fr"],
    "bouygues":         ["bouyguestelecom.fr", "bouygues.com"],
    "bnp paribas":      ["bnpparibas.com", "bnpparibas.fr"],
    # BUG FIX: "credit agricole" replaces "ca-*.fr" wildcard with real domain list
    "credit agricole":  ["credit-agricole.fr", "ca-paris.fr", "ca-centre-est.fr",
                         "ca-normandie.fr", "ca-normandie-seine.fr", "ca-sudrhonealpes.fr",
                         "ca-languedocroussillon.fr", "ca-briepicardie.fr",
                         "ca-champagne-bourgogne.fr", "credit-agricole.com"],
    "societe generale": ["societegenerale.fr", "sg.fr", "sgcib.com"],
    "lcl":              ["lcl.fr", "lcl.com"],
    "ing direct":       ["ing.fr", "ing.com", "ing.be"],
    "hsbc":             ["hsbc.com", "hsbc.fr"],
    "barclays":         ["barclays.com", "barclays.co.uk"],
    "citibank":         ["citibank.com", "citi.com"],
    "chase":            ["chase.com"],
    "wells fargo":      ["wellsfargo.com"],
    "bank of america":  ["bankofamerica.com"],
}


def _strip_www(domain: str) -> str:
    """BUG FIX: use removeprefix, not lstrip which strips individual chars."""
    return domain.removeprefix("www.")


def _get_raw_header(raw_headers: str, name: str) -> str:
    """Extract a single header value from the raw header block."""
    pattern = re.compile(
        rf"^{re.escape(name)}\s*:\s*(.+?)(?=\n\S|\Z)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    m = pattern.search(raw_headers or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def _sender_domain(email_addr: str) -> str:
    parts = email_addr.strip().lower().split("@")
    return parts[-1] if len(parts) == 2 else ""


def _check_display_name_spoofing(
    raw_headers: str, sender_email: str
) -> tuple[bool, str]:
    from_raw = _get_raw_header(raw_headers, "From")
    display_name, _ = parseaddr(from_raw)
    display_name = display_name.lower()
    domain = _sender_domain(sender_email)

    for brand, legit_domains in _BRAND_DOMAINS.items():
        # Use word-boundary regex so 'apple' doesn't match 'pineapple',
        # and 'ing direct' matches as a phrase. re.escape handles spaces/dots.
        pattern = r"\b" + re.escape(brand) + r"\b"
        if re.search(pattern, display_name):
            if not any(
                domain == d or domain.endswith("." + d)
                for d in legit_domains
            ):
                return (
                    True,
                    f"Display name '{display_name}' claims '{brand}' "
                    f"but sent from '{domain}'",
                )
    return False, ""


def _check_reply_to_mismatch(raw_headers: str, sender_email: str) -> tuple[bool, str]:
    reply_to_raw = _get_raw_header(raw_headers, "Reply-To")
    if not reply_to_raw:
        return False, ""
    _, reply_addr = parseaddr(reply_to_raw)
    reply_domain = _sender_domain(reply_addr)
    from_domain = _sender_domain(sender_email)
    if reply_domain and from_domain and reply_domain != from_domain:
        return (
            True,
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
        )
    return False, ""


def _check_return_path_mismatch(raw_headers: str, sender_email: str) -> tuple[bool, str]:
    """
    BUG FIX: many legitimate bulk senders use a different Return-Path subdomain
    (bounce address). We only flag if the *registrable* domain differs, not just
    the subdomain.
    """
    rp_raw = _get_raw_header(raw_headers, "Return-Path")
    if not rp_raw:
        return False, ""
    rp_raw = rp_raw.strip("<>").strip()
    rp_domain = _sender_domain(rp_raw)
    from_domain = _sender_domain(sender_email)

    def _reg(d: str) -> str:
        parts = _strip_www(d).split(".")
        if len(parts) >= 2:
            if parts[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") and len(parts) >= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return d

    rp_reg = _reg(rp_domain)
    from_reg = _reg(from_domain)
    if rp_reg and from_reg and rp_reg != from_reg:
        return (
            True,
            f"Return-Path registrable domain ({rp_reg}) differs from "
            f"From domain ({from_reg})",
        )
    return False, ""


def _check_auth_results(raw_headers: str) -> list[tuple[str, int]]:
    """
    Returns list of (reason, score_delta) tuples.
    BUG FIX: removed 'no Authentication-Results' penalty — many legitimate
    small mail servers don't add this header.
    """
    issues: list[tuple[str, int]] = []
    auth_raw = _get_raw_header(raw_headers, "Authentication-Results")
    if not auth_raw:
        return []  # absence is not evidence of phishing

    auth_lower = auth_raw.lower()
    if "dkim=fail" in auth_lower:
        issues.append(("[header] DKIM signature failed", 8))
    elif "dkim=none" in auth_lower:
        issues.append(("[header] No DKIM signature present", 4))
    if "spf=fail" in auth_lower:
        issues.append(("[header] SPF hard-failed", 8))
    elif "spf=softfail" in auth_lower:
        issues.append(("[header] SPF soft-failed", 4))
    if "dmarc=fail" in auth_lower:
        issues.append(("[header] DMARC failed", 10))
    return issues


def _check_hop_anomalies(raw_headers: str, hop_count: int) -> list[str]:
    issues: list[str] = []
    # hop_count == -1 means "not applicable" (e.g. /analyze/components virtual email)
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

    received_blocks = re.findall(
        r"Received:.*?(?=Received:|\Z)", raw_headers or "",
        re.IGNORECASE | re.DOTALL,
    )
    private_re = re.compile(
        r"from\s+.*?\[?(10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
        r"|192\.168\.\d+\.\d+)\]?",
        re.IGNORECASE,
    )
    private_count = sum(1 for b in received_blocks if private_re.search(b))
    if private_count >= 2:
        issues.append(
            f"[header] {private_count} Received hops show private IPs "
            f"— internal relay or spoofed"
        )
    return issues


def analyze_headers(extracted: ExtractedEmailData) -> HeaderSignals:
    reasons: list[str] = []
    score = 0
    raw = extracted.raw_headers or ""

    # Basic presence
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
        domain = _sender_domain(extracted.sender)

        # Free webmail
        if domain in _FREE_WEBMAIL:
            reasons.append(f"[header] Free webmail sender: {domain}")
            score += 8

        if raw:
            # Display name spoofing
            spoofed, msg = _check_display_name_spoofing(raw, extracted.sender)
            if spoofed:
                reasons.append(f"[header] Display name spoofing: {msg}")
                score += 15

            # Reply-To mismatch
            mismatch, msg = _check_reply_to_mismatch(raw, extracted.sender)
            if mismatch:
                reasons.append(f"[header] Reply-To mismatch: {msg}")
                score += 10

            # Return-Path mismatch (registrable domain only)
            mismatch, msg = _check_return_path_mismatch(raw, extracted.sender)
            if mismatch:
                reasons.append(f"[header] Return-Path mismatch: {msg}")
                score += 6

    # Auth results (failures only, no penalty for absence)
    if raw:
        for reason, delta in _check_auth_results(raw):
            reasons.append(reason)
            score += delta

    # Hop anomalies
    hops = int(extracted.technical_details.get("received_hops", 0) or 0)
    for issue in _check_hop_anomalies(raw, hops):
        reasons.append(issue)
        score += 4

    return HeaderSignals(score=min(40, score), reasons=reasons)
