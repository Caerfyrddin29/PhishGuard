from __future__ import annotations

import concurrent.futures
import datetime
import json
import subprocess
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from urllib.request import Request, urlopen

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
    "example.com", "example.fr", "example.co.uk",
}

_YOUNG_THRESHOLD_DAYS = 180
_VERY_YOUNG_THRESHOLD_DAYS = 30
_RDAP_TIMEOUT_SECONDS = 5
_TOTAL_DOMAIN_AGE_BUDGET_SECONDS = 12
_RDAP_BASE_URL = "https://rdap.org/domain/"
_DEFAULT_HEADERS = {
    "Accept": "application/rdap+json, application/json",
    "User-Agent": "PhishGuard/3.2 (+local-analysis)",
}


def _strip_www(domain: str) -> str:
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
    parts = _strip_www(domain).split(".")
    if len(parts) >= 2:
        if parts[-2] in ("co", "com", "net", "org", "gov", "edu", "ac") and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain


def _is_trusted(domain: str) -> bool:
    return domain in _TRUSTED_DOMAINS or any(domain.endswith("." + t) for t in _TRUSTED_DOMAINS)


def _coerce_datetime(value: object) -> datetime.datetime | None:
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    if isinstance(value, datetime.date):
        return datetime.datetime.combine(value, datetime.time.min, tzinfo=datetime.timezone.utc)
    if not isinstance(value, str):
        return None

    raw = value.strip()
    if not raw:
        return None

    try:
        dt = parsedate_to_datetime(raw)
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        pass

    normalized = raw.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(normalized)
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def _age_days_from_dt(dt: datetime.datetime) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, (now - dt.astimezone(datetime.timezone.utc)).days)


def _parse_rdap_age_days(payload: dict) -> int | None:
    events = payload.get("events") or []
    preferred_actions = {"registration", "registered", "creation", "created"}

    best: datetime.datetime | None = None
    fallback: datetime.datetime | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        dt = _coerce_datetime(event.get("eventDate"))
        if not dt:
            continue
        action = str(event.get("eventAction") or "").strip().lower()
        if action in preferred_actions:
            if best is None or dt < best:
                best = dt
        elif fallback is None or dt < fallback:
            fallback = dt

    chosen = best or fallback
    return _age_days_from_dt(chosen) if chosen else None


def _rdap_fetch(domain: str) -> dict | None:
    req = Request(_RDAP_BASE_URL + domain, headers=_DEFAULT_HEADERS)
    with urlopen(req, timeout=_RDAP_TIMEOUT_SECONDS) as resp:  # nosec B310: fixed https endpoint
        charset = resp.headers.get_content_charset() or "utf-8"
        body = resp.read().decode(charset, errors="replace")
    data = json.loads(body)
    return data if isinstance(data, dict) else None


def _rdap_age_days_blocking(domain: str) -> int | None:
    try:
        payload = _rdap_fetch(domain)
        if payload:
            return _parse_rdap_age_days(payload)
    except Exception:
        return None
    return None


def _whois_cli_age_days_blocking(domain: str) -> int | None:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True,
            text=True,
            timeout=_RDAP_TIMEOUT_SECONDS,
            check=False,
        )
    except Exception:
        return None

    lines = result.stdout.splitlines()
    markers = (
        "creation date:",
        "created:",
        "created on:",
        "registered on:",
        "domain registered:",
    )
    for line in lines:
        lower = line.lower().strip()
        if not lower.startswith(markers):
            continue
        raw = line.split(":", 1)[1].strip() if ":" in line else ""
        dt = _coerce_datetime(raw)
        if dt:
            return _age_days_from_dt(dt)
    return None


def _domain_age_days_blocking(domain: str) -> int | None:
    age = _rdap_age_days_blocking(domain)
    if age is not None:
        return age
    return _whois_cli_age_days_blocking(domain)


def _domain_age_days(domain: str) -> int | None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        future = ex.submit(_domain_age_days_blocking, domain)
        try:
            return future.result(timeout=_RDAP_TIMEOUT_SECONDS)
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
        if len(domains_to_check) >= 4:
            break

    if not domains_to_check:
        return DomainSignals(score=0, reasons=[])

    young_domains: list[str] = []
    wall_start = time.monotonic()

    for domain in domains_to_check:
        if time.monotonic() - wall_start > _TOTAL_DOMAIN_AGE_BUDGET_SECONDS:
            break

        age_days = _domain_age_days(domain)
        if age_days is None:
            continue

        if age_days < _VERY_YOUNG_THRESHOLD_DAYS:
            young_domains.append(f"{domain} ({age_days}d old ⚠)")
            score += 20
        elif age_days < _YOUNG_THRESHOLD_DAYS:
            young_domains.append(f"{domain} ({age_days}d old)")
            score += 10

    if young_domains:
        reasons.append(f"[domain] Recently registered: {', '.join(young_domains)}")

    return DomainSignals(score=min(30, score), reasons=reasons)
