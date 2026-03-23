from __future__ import annotations

import concurrent.futures
import datetime
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..config import Settings
from ..models import ExtractedEmailData


@dataclass
class DomainSignals:
    score: int
    reasons: list[str]


_TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "cloudflare.com", "amazonaws.com", "azurewebsites.net",
    "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "gouv.fr", "impots.gouv.fr", "ameli.fr", "caf.fr", "service-public.fr",
    "sendgrid.net", "mailchimp.com", "mailgun.org", "constantcontact.com",
    "salesforce.com", "marketo.net", "hubspot.com",
    "news.lahalle.com", "laposte.net", "orange.fr",
}

_YOUNG_THRESHOLD_DAYS = 180
_VERY_YOUNG_THRESHOLD_DAYS = 30
# BUG FIX: strict per-domain timeout to prevent the API from hanging
_WHOIS_TIMEOUT_SECONDS = 5
# BUG FIX: overall wall-clock budget for ALL WHOIS calls combined
_TOTAL_WHOIS_BUDGET_SECONDS = 12


def _strip_www(domain: str) -> str:
    """BUG FIX: removeprefix, not lstrip."""
    return domain.removeprefix("www.")


def _get_domain_from_value(value: str) -> str:
    value = value.strip()
    if "@" in value and "://" not in value:
        parts = value.split("@")
        return parts[-1].strip().lower() if len(parts) == 2 else ""
    try:
        netloc = urlparse(value).netloc.lower()
        return netloc.split(":")[0]
    except Exception:
        return ""


def _registrable_domain(domain: str) -> str:
    """BUG FIX: use _strip_www helper."""
    parts = _strip_www(domain).split(".")
    if len(parts) >= 2:
        if parts[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def _is_trusted(domain: str) -> bool:
    return domain in _TRUSTED_DOMAINS or any(
        domain.endswith("." + t) for t in _TRUSTED_DOMAINS
    )


def _whois_age_days_blocking(domain: str) -> int | None:
    """Blocking WHOIS lookup — always called inside a thread with timeout."""
    # Attempt 1: python-whois library
    try:
        import whois  # type: ignore
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if isinstance(created, (datetime.datetime, datetime.date)):
            if isinstance(created, datetime.datetime):
                age = (datetime.datetime.utcnow() - created).days
            else:
                age = (datetime.date.today() - created).days
            return max(0, age)
    except Exception:
        pass

    # Attempt 2: system whois CLI
    try:
        import subprocess
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=_WHOIS_TIMEOUT_SECONDS
        )
        date_pat = re.compile(
            r"(?:creation date|created|registered on|domain registered)\s*[:\s]+([0-9T:\-\.Z ]+)",
            re.IGNORECASE,
        )
        m = date_pat.search(result.stdout)
        if m:
            raw = m.group(1).strip()
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y",
                        "%Y.%m.%d", "%d/%m/%Y", "%Y-%m-%dT%H:%M:%S"):
                try:
                    dt = datetime.datetime.strptime(raw[:19], fmt)
                    return max(0, (datetime.datetime.utcnow() - dt).days)
                except ValueError:
                    continue
    except Exception:
        pass

    return None


def _whois_age_days(domain: str) -> int | None:
    """
    BUG FIX: run WHOIS in a thread so we can enforce a hard wall-clock timeout.
    Without this, whois library or CLI can hang for 30+ seconds.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(_whois_age_days_blocking, domain)
        try:
            return future.result(timeout=_WHOIS_TIMEOUT_SECONDS)
        except (concurrent.futures.TimeoutError, Exception):
            return None


def analyze_domains(extracted: ExtractedEmailData, settings: Settings) -> DomainSignals:
    reasons: list[str] = []
    score = 0

    domains_to_check: list[str] = []

    if extracted.sender:
        d = _registrable_domain(_get_domain_from_value(extracted.sender))
        if d and not _is_trusted(d):
            domains_to_check.append(d)

    seen: set[str] = set(domains_to_check)
    for url in (extracted.urls or [])[:20]:
        d = _registrable_domain(_get_domain_from_value(url))
        if d and d not in seen and not _is_trusted(d):
            seen.add(d)
            domains_to_check.append(d)
        if len(domains_to_check) >= 4:  # hard cap: sender + 3 URL domains
            break

    if not domains_to_check:
        return DomainSignals(score=0, reasons=[])

    young_domains: list[str] = []
    failed_lookup: list[str] = []

    import time
    wall_start = time.monotonic()

    for domain in domains_to_check:
        # BUG FIX: respect overall budget
        if time.monotonic() - wall_start > _TOTAL_WHOIS_BUDGET_SECONDS:
            failed_lookup.append(f"{domain} (budget exhausted)")
            continue

        age_days = _whois_age_days(domain)
        if age_days is None:
            failed_lookup.append(domain)
            continue

        if age_days < _VERY_YOUNG_THRESHOLD_DAYS:
            young_domains.append(f"{domain} ({age_days}d old ⚠)")
            score += 20
        elif age_days < _YOUNG_THRESHOLD_DAYS:
            young_domains.append(f"{domain} ({age_days}d old)")
            score += 10

    if young_domains:
        reasons.append(f"[domain] Recently registered: {', '.join(young_domains)}")
    if failed_lookup and not young_domains:
        reasons.append(
            f"[domain] WHOIS unavailable for: {', '.join(failed_lookup[:3])} (inconclusive)"
        )

    return DomainSignals(score=min(30, score), reasons=reasons)
