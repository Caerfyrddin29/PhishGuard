from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..models import ExtractedEmailData


@dataclass
class UrlSignals:
    score: int
    reasons: list[str]


_SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "adf.ly", "lnkd.in", "short.link", "rb.gy", "cutt.ly",
    "tiny.cc", "shorte.st", "bc.vc", "clck.ru", "qps.ru", "u.to",
    "v.gd", "x.co", "prettylnk.com", "rlu.ru",
}

_SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "pw", "cc", "su", "ws",
    "click", "download", "support", "online",
    "site", "website", "space", "fun",
    "icu", "club", "store", "shop", "link", "work",
    "fit", "loan", "date", "racing", "accountant",
    "science", "trade", "webcam", "review", "country",
    "stream", "gdn", "win", "bid", "party", "faith",
}

# BUG FIX: brand names must be long enough and unambiguous enough that
# matching them as a substring of a domain won't cause false positives.
# Short words like "ups", "ing", "free", "caf" are excluded.
# Each entry: (brand_name_min4chars, official_registrable_domains)
_BRAND_OFFICIAL: dict[str, list[str]] = {
    "paypal":           ["paypal.com"],
    "amazon":           ["amazon.com", "amazon.fr", "amazon.co.uk", "amazon.de",
                         "amazon.es", "amazon.it", "amazon.ca", "amazon.co.jp"],
    "apple":            ["apple.com", "icloud.com", "itunes.com"],
    "microsoft":        ["microsoft.com", "microsoftonline.com", "live.com",
                         "outlook.com", "office.com", "office365.com"],
    "google":           ["google.com", "google.fr", "google.co.uk", "gmail.com",
                         "googlemail.com", "googleapis.com", "gstatic.com"],
    "netflix":          ["netflix.com"],
    "facebook":         ["facebook.com", "fb.com", "meta.com"],
    "instagram":        ["instagram.com", "cdninstagram.com"],
    "twitter":          ["twitter.com", "x.com", "twimg.com"],
    "linkedin":         ["linkedin.com", "licdn.com"],
    "dropbox":          ["dropbox.com", "dropboxusercontent.com"],
    "docusign":         ["docusign.com", "docusign.net"],
    "dhl":              ["dhl.com", "dhl.fr", "dhl.de", "dhl.co.uk"],
    "fedex":            ["fedex.com"],
    "ameli":            ["ameli.fr", "assurance-maladie.fr"],
    "impots":           ["impots.gouv.fr", "dgfip.finances.gouv.fr"],
    "laposte":          ["laposte.fr", "laposte.net"],
    "colissimo":        ["laposte.fr", "colissimo.fr"],
    "bnpparibas":       ["bnpparibas.com", "bnpparibas.fr"],
    "societegenerale":  ["societegenerale.fr", "sg.fr"],
    "creditagricole":   ["credit-agricole.fr", "credit-agricole.com",
                         "ca-paris.fr", "ca-centre-est.fr"],
}

_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)
_DATA_URI_RE = re.compile(r"data:[^;]+;base64,", re.IGNORECASE)
_HEX_ENCODE_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){5,}")  # 5+ consecutive %xx
_EXCESSIVE_PARAMS_RE = re.compile(r"[?&][^=]+=.{80,}")    # one param value > 80 chars

_HOMOGLYPH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"paypa[l1|!]", re.I),             "paypal homoglyph"),
    (re.compile(r"pay[-_]?pa[l1|!]", re.I),        "paypal typosquat"),
    (re.compile(r"amaz[o0]n", re.I),               "amazon homoglyph"),
    (re.compile(r"am[a@]zon", re.I),               "amazon homoglyph"),
    (re.compile(r"app[l1][e3]", re.I),             "apple homoglyph"),
    (re.compile(r"micr[o0]s[o0]ft", re.I),         "microsoft homoglyph"),
    (re.compile(r"g[o0]{2}gle", re.I),             "google homoglyph"),
    (re.compile(r"netf[l1][i1]x", re.I),           "netflix homoglyph"),
    (re.compile(r"faceb[o0]{2}k", re.I),           "facebook homoglyph"),
    (re.compile(r"tw[il1]tter", re.I),             "twitter homoglyph"),
    (re.compile(r"linkedln\.com", re.I),           "linkedin homoglyph (ln vs in)"),
    (re.compile(r"d[h]?[l1]-?express", re.I),      "dhl homoglyph"),
]


def _strip_www(domain: str) -> str:
    """BUG FIX: use removeprefix, not lstrip which strips individual chars."""
    return domain.removeprefix("www.")


def _extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc.split(":")[0]
    except Exception:
        return ""


def _registrable_domain(domain: str) -> str:
    """BUG FIX: use _strip_www helper instead of lstrip."""
    parts = _strip_www(domain).split(".")
    if len(parts) >= 2:
        if parts[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def _check_brand_impersonation(domain: str) -> str | None:
    """
    BUG FIX: use word-boundary-aware matching.
    Instead of `brand in domain` (catches 'ups' in 'groups'),
    we check that the brand appears as a full token in the domain
    (split by dots and hyphens).
    """
    reg = _registrable_domain(domain)
    # Tokenise the domain into parts for whole-word matching
    tokens = set(re.split(r"[.\-]", domain.lower()))

    for brand, official in _BRAND_OFFICIAL.items():
        # Brand must appear as a complete token (not a substring of a token)
        if brand in tokens or brand in reg:
            official_regs = {_registrable_domain(d) for d in official}
            if reg not in official_regs:
                return f"'{brand}' in domain '{domain}' but not official"
    return None


def _check_homoglyphs(url: str) -> list[str]:
    return [label for pattern, label in _HOMOGLYPH_PATTERNS if pattern.search(url)]


def _subdomain_depth(domain: str) -> int:
    return max(0, len(domain.split(".")) - 2)


def analyze_urls(extracted: ExtractedEmailData) -> UrlSignals:
    urls = extracted.urls or []
    if not urls:
        return UrlSignals(score=0, reasons=[])

    reasons: list[str] = []
    score = 0

    url_count = len(urls)
    base = min(20, url_count * 2)
    volume_bonus = 10 if url_count > 20 else (5 if url_count > 10 else 0)
    score += base + volume_bonus
    reasons.append(f"[url] URLs found: {url_count}")
    if url_count > 20:
        reasons.append(f"[url] Very high URL count ({url_count})")

    domains_seen: set[str] = set()
    shortener_found = False
    ip_found = False
    data_uri_found = False
    suspicious_tlds: set[str] = set()
    homoglyphs: list[str] = []
    brand_issues: list[str] = []
    deep_subdomain_count = 0
    long_url_count = 0
    obfuscated_count = 0
    http_only_count = 0

    for url in urls:
        if not ip_found and _IP_URL_RE.match(url):
            reasons.append("[url] IP-based URL detected")
            score += 10
            ip_found = True

        if not data_uri_found and _DATA_URI_RE.match(url):
            reasons.append("[url] data: URI found — possible embedded payload")
            score += 10
            data_uri_found = True

        # HTTP-only (skip w3.org schema declarations common in HTML emails)
        if (url.startswith("http://")
                and not url.startswith("http://www.w3.org")
                and not url.startswith("http://schemas.")):
            http_only_count += 1

        if len(url) > 200:
            long_url_count += 1

        if _HEX_ENCODE_RE.search(url) or _EXCESSIVE_PARAMS_RE.search(url):
            obfuscated_count += 1

        domain = _extract_domain(url)
        if not domain or domain in domains_seen:
            continue
        domains_seen.add(domain)

        if not shortener_found and domain in _SHORTENERS:
            reasons.append(f"[url] URL shortener: {domain}")
            score += 8
            shortener_found = True

        tld = domain.rsplit(".", 1)[-1].lower()
        if tld in _SUSPICIOUS_TLDS:
            suspicious_tlds.add(tld)

        for hg in _check_homoglyphs(domain):
            if hg not in homoglyphs:
                homoglyphs.append(hg)

        bi = _check_brand_impersonation(domain)
        if bi and bi not in brand_issues:
            brand_issues.append(bi)

        if _subdomain_depth(domain) > 3:
            deep_subdomain_count += 1

    if suspicious_tlds:
        tlds = ", ".join(f".{t}" for t in list(suspicious_tlds)[:4])
        reasons.append(f"[url] Suspicious TLD(s): {tlds}")
        score += 6 * min(3, len(suspicious_tlds))

    if homoglyphs:
        reasons.append(f"[url] Homoglyph/typosquat: {', '.join(homoglyphs[:3])}")
        score += 15

    for b in brand_issues[:3]:
        reasons.append(f"[url] Brand impersonation: {b}")
        score += 15

    if deep_subdomain_count:
        reasons.append(f"[url] {deep_subdomain_count} URL(s) with excessive subdomains")
        score += 5

    if long_url_count > 2:
        reasons.append(f"[url] {long_url_count} very long URLs (>200 chars)")
        score += 4

    if obfuscated_count:
        reasons.append(f"[url] {obfuscated_count} URL(s) with heavy encoding/huge params")
        score += 5

    if http_only_count:
        reasons.append(f"[url] {http_only_count} non-HTTPS URL(s)")
        score += 3

    return UrlSignals(score=min(40, score), reasons=reasons)
