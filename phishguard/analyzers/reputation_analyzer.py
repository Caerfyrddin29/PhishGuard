#Projet : PhishGuard
#Auteurs : Équipe PhishGuard

from __future__ import annotations

import os

import ipaddress
import json
import socket
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from ..domain_tools import registrable_domain
from ..models import ExtractedEmailData


@dataclass
class ReputationSignals:
    score: int
    reasons: list[str]


_DNS_TIMEOUT = 2
_HTTP_TIMEOUT = 2
_FEED_TTL = 6 * 3600
_MAX_URLS_TO_CHECK = 6
_MAX_URLHAUS_CALLS = 3
_DNSBL_ZONES: list[str] = ["dbl.spamhaus.org", "multi.surbl.org", "black.uribl.com"]
_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
_OPENPHISH_FEED = "https://openphish.com/feed.txt"

_ENABLE_REPUTATION_NET = os.getenv("PHISHGUARD_ENABLE_REPUTATION_NET", "1") != "0"


class _FeedCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: set[str] = set()
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


def _extract_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc.lower()
        return netloc.split(":")[0]
    except Exception:
        return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _http_post_json(url: str, data: dict[str, str]) -> dict | None:
    try:
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "PhishGuard/3.1"})
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read(65536))
    except Exception:
        return None


def _http_get_text(url: str, max_bytes: int = 512 * 1024) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard/3.1"})
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return resp.read(max_bytes).decode("utf-8", errors="replace")
    except Exception:
        return None


def _dnsbl_lookup(domain: str, zone: str) -> bool:
    if _is_ip(domain):
        return False
    query = f"{domain}.{zone}"
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(_DNS_TIMEOUT)
        try:
            return len(socket.getaddrinfo(query, None)) > 0
        finally:
            socket.setdefaulttimeout(old)
    except socket.gaierror:
        return False
    except Exception:
        return False


def _refresh_openphish() -> None:
    text = _http_get_text(_OPENPHISH_FEED)
    if not text:
        return
    entries: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("http"):
            d = _extract_domain(line)
            if d:
                entries.add(registrable_domain(d))
            entries.add(line.lower())
    if entries:
        _openphish_cache.update(entries)


def analyze_reputation(extracted: ExtractedEmailData) -> ReputationSignals:
    reasons: list[str] = []
    score = 0
    if not _ENABLE_REPUTATION_NET:
        return ReputationSignals(score=0, reasons=[])

    seen_domains: set[str] = set()
    domains_to_check: list[str] = []
    urls_to_check: list[str] = []

    if extracted.sender and "@" in extracted.sender:
        d = registrable_domain(extracted.sender.split("@", 1)[1].strip().lower())
        if d and d not in seen_domains:
            seen_domains.add(d)
            domains_to_check.append(d)

    for url in (extracted.urls or [])[:_MAX_URLS_TO_CHECK]:
        d = registrable_domain(_extract_domain(url))
        if d:
            urls_to_check.append(url)
            if d not in seen_domains:
                seen_domains.add(d)
                domains_to_check.append(d)

    for domain in domains_to_check[:4]:
        if _is_ip(domain):
            continue
        hits = [zone.split('.')[0].upper() for zone in _DNSBL_ZONES if _dnsbl_lookup(domain, zone)]
        if hits:
            reasons.append(f"[reputation] DNSBL listed {domain}: {', '.join(hits)}")
            score += 20

    for url in urls_to_check[:_MAX_URLHAUS_CALLS]:
        result = _http_post_json(_URLHAUS_API, {"url": url})
        if result and result.get("query_status") == "is_available":
            threat = result.get("threat") or "malware"
            reasons.append(f"[reputation] {url}: URLhaus active {threat}")
            score += 25

    if _openphish_cache.is_stale() or _openphish_cache.is_empty():
        _refresh_openphish()
    feed = _openphish_cache.get()
    if feed:
        hits: list[str] = []
        for url in urls_to_check:
            d = registrable_domain(_extract_domain(url))
            if url.lower() in feed or d in feed:
                if d and d not in hits:
                    hits.append(d)
        if hits:
            reasons.append(f"[reputation] Domain(s) in OpenPhish feed: {', '.join(hits[:3])}")
            score += 30

    return ReputationSignals(score=min(40, score), reasons=reasons)
