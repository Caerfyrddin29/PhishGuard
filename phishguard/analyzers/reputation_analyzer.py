from __future__ import annotations

"""
Reputation analyzer — no API key required.

Sources:
  1. DNS Blocklists (DNSBL): Spamhaus DBL, SURBL, URIBL
  2. URLhaus (abuse.ch): per-URL POST check, no key needed.
  3. OpenPhish: public feed (~300KB), downloaded and cached in memory for 6 hours.

PhishTank was removed: their public JSON feed is 50-100MB which makes it
impractical to download per analysis, and their URL-check API requires a key.

All sources fail silently — any network error returns score=0, never raises.
"""

import concurrent.futures
import ipaddress
import json
import socket
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from ..models import ExtractedEmailData


@dataclass
class ReputationSignals:
    score: int
    reasons: list[str]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DNS_TIMEOUT = 3            # seconds per DNS query
_HTTP_TIMEOUT = 6           # seconds per HTTP request
_FEED_TTL = 6 * 3600        # seconds before re-downloading a feed (6h)
_MAX_URLS_TO_CHECK = 10     # cap: avoid slow analysis on 80-URL emails
_MAX_URLHAUS_CALLS = 5      # cap URLhaus API calls per email
_THREAD_BUDGET = 10         # wall-clock budget for ALL reputation checks

_DNSBL_ZONES: list[str] = [
    "dbl.spamhaus.org",     # Spamhaus Domain Block List
    "multi.surbl.org",      # SURBL multi
    "black.uribl.com",      # URIBL black
]

_URLHAUS_API    = "https://urlhaus-api.abuse.ch/v1/url/"
_OPENPHISH_FEED = "https://openphish.com/feed.txt"


# ---------------------------------------------------------------------------
# Thread-safe in-memory feed cache
# ---------------------------------------------------------------------------
class _FeedCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: set[str] = set()
        # float("-inf") ensures a never-loaded cache is always considered stale,
        # regardless of how long the process has been running (time.monotonic()
        # starts near 0 at process boot, not at Unix epoch).
        self._loaded_at: float = float("-inf")

    def get(self) -> set[str]:
        with self._lock:
            return set(self._data)

    def update(self, entries: set[str]) -> None:
        with self._lock:
            self._data = entries
            self._loaded_at = time.monotonic()

    def is_stale(self) -> bool:
        with self._lock:
            return (time.monotonic() - self._loaded_at) > _FEED_TTL

    def is_empty(self) -> bool:
        with self._lock:
            return len(self._data) == 0


_openphish_cache = _FeedCache()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _strip_www(domain: str) -> str:
    return domain.removeprefix("www.")


def _extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
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


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _http_post_json(url: str, data: dict[str, str]) -> dict | None:
    try:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url, data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "PhishGuard/3.0",
            },
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read(65536))
    except Exception:
        return None


def _http_get_text(url: str, max_bytes: int = 512 * 1024, timeout: int = _HTTP_TIMEOUT) -> str | None:
    """
    Download a text resource up to max_bytes.
    OpenPhish feed is ~300KB so 512KB is a safe ceiling.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard/3.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(max_bytes).decode("utf-8", errors="replace")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# DNSBL
# ---------------------------------------------------------------------------
def _dnsbl_lookup(domain: str, zone: str) -> bool:
    """
    Returns True if the domain is listed in the given DNSBL zone.
    NXDOMAIN (socket.gaierror) means clean — not listed.

    socket.setdefaulttimeout() is intentionally NOT used here because it
    mutates process-global state and is not thread-safe when called from
    multiple concurrent threads. The wall-clock budget enforced by the
    ThreadPoolExecutor in analyze_reputation() handles hung lookups instead.
    """
    if _is_ip(domain):
        return False
    query = f"{domain}.{zone}"
    try:
        return len(socket.getaddrinfo(query, None)) > 0
    except socket.gaierror:
        return False
    except Exception:
        return False


def _check_dnsbl(domain: str) -> tuple[str, list[str]]:
    reg = _registrable_domain(domain)
    hits: list[str] = []
    if not reg or _is_ip(reg):
        return domain, hits
    for zone in _DNSBL_ZONES:
        if _dnsbl_lookup(reg, zone):
            hits.append(zone.split(".")[0].upper())
    return domain, hits


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------
def _check_urlhaus(url: str) -> tuple[str, str | None]:
    result = _http_post_json(_URLHAUS_API, {"url": url})
    if result is None:
        return url, None
    if result.get("query_status") == "is_available":
        tags = result.get("tags") or []
        threat = result.get("threat") or "malware"
        tag_str = ", ".join(tags[:3]) if tags else threat
        return url, f"URLhaus active {threat} ({tag_str})"
    return url, None


# ---------------------------------------------------------------------------
# OpenPhish
# ---------------------------------------------------------------------------
def _refresh_openphish() -> None:
    text = _http_get_text(_OPENPHISH_FEED, max_bytes=512 * 1024, timeout=8)
    if not text:
        return
    entries: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("http"):
            d = _extract_domain(line)
            if d:
                entries.add(_registrable_domain(d))
            entries.add(line.lower())
    if entries:
        _openphish_cache.update(entries)


def _check_openphish(url: str) -> tuple[str, bool]:
    if _openphish_cache.is_stale() or _openphish_cache.is_empty():
        _refresh_openphish()
    feed = _openphish_cache.get()
    if not feed:
        return url, False
    domain = _registrable_domain(_extract_domain(url))
    return url, (url.lower() in feed or domain in feed)


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------
def analyze_reputation(extracted: ExtractedEmailData) -> ReputationSignals:
    reasons: list[str] = []
    score = 0

    seen_domains: set[str] = set()
    domains_to_check: list[str] = []
    urls_to_check: list[str] = []

    if extracted.sender:
        parts = extracted.sender.split("@")
        if len(parts) == 2:
            d = _registrable_domain(parts[1].strip().lower())
            if d and d not in seen_domains:
                seen_domains.add(d)
                domains_to_check.append(d)

    for url in (extracted.urls or []):
        if len(urls_to_check) >= _MAX_URLS_TO_CHECK:
            break
        d = _registrable_domain(_extract_domain(url))
        if not d:
            continue
        urls_to_check.append(url)
        if d not in seen_domains:
            seen_domains.add(d)
            domains_to_check.append(d)

    if not domains_to_check and not urls_to_check:
        return ReputationSignals(score=0, reasons=[])

    # ── Submit all checks to a thread pool ────────────────────────────────
    # Each worker returns (source_tag, key, value) for unambiguous dispatch.
    # We do NOT use the context manager so we can call shutdown(wait=False)
    # and avoid blocking past our time budget.
    dnsbl_hits: dict[str, list[str]] = {}
    urlhaus_hits: list[str] = []
    openphish_hits: list[str] = []

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
    try:
        futures: list[concurrent.futures.Future] = []
        for d in domains_to_check:
            futures.append(pool.submit(_check_dnsbl, d))
        for url in urls_to_check[:_MAX_URLHAUS_CALLS]:
            futures.append(pool.submit(_check_urlhaus, url))
        for url in urls_to_check:
            futures.append(pool.submit(_check_openphish, url))

        wall_start = time.monotonic()
        for f in concurrent.futures.as_completed(futures):
            if time.monotonic() - wall_start > _THREAD_BUDGET:
                break
            try:
                result = f.result(timeout=1)
            except Exception:
                continue

            if not isinstance(result, tuple) or len(result) != 2:
                continue

            key, val = result

            if isinstance(val, list):
                # _check_dnsbl → (domain, list[str])
                if val:
                    dnsbl_hits[key] = val
            elif isinstance(val, str):
                # _check_urlhaus → (url, description)
                urlhaus_hits.append(f"{key}: {val}")
            elif val is True:
                # _check_openphish → (url, bool)
                domain_key = _registrable_domain(_extract_domain(key))
                if domain_key not in openphish_hits:
                    openphish_hits.append(domain_key)

    finally:
        # FIX: shutdown(wait=False) so we don't block past the time budget.
        # Threads with their own HTTP timeouts (_HTTP_TIMEOUT=6s) will finish
        # naturally; we just don't block the analysis pipeline waiting for them.
        pool.shutdown(wait=False)

    # ── Score and report ──────────────────────────────────────────────────
    if dnsbl_hits:
        for domain, zones in list(dnsbl_hits.items())[:3]:
            reasons.append(f"[reputation] DNSBL listed {domain}: {', '.join(zones)}")
            score += 20

    if urlhaus_hits:
        for hit in urlhaus_hits[:3]:
            reasons.append(f"[reputation] {hit}")
            score += 25

    if openphish_hits:
        reasons.append(
            f"[reputation] Domain(s) in OpenPhish feed: "
            f"{', '.join(openphish_hits[:3])}"
        )
        score += 30

    return ReputationSignals(score=min(40, score), reasons=reasons)
