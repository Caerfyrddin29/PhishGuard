#Projet : PhishGuard
#Auteurs : Myrddin Bellion, Ilyan Kassous

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from sources.api import app
from sources.phishguard.analyzers.hybrid import HybridPhishingAnalyzer
from sources.phishguard.analyzers import reputation_analyzer as rep
from sources.phishguard.config import Settings
from sources.phishguard.parser import EmailFileExtractor


client = TestClient(app)


def _make_eml(headers: str, body: bytes) -> bytes:
    return headers.encode("utf-8") + b"\r\n\r\n" + body


def _analyze(eml: bytes, name: str = "x.eml"):
    ex = EmailFileExtractor(Settings()).extract_raw_eml_bytes(eml, name)
    return HybridPhishingAnalyzer(Settings()).analyze_extracted(ex)


def test_utf16_eml_parses_headers(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    headers = "From: a@example.com\r\nTo: b@example.com\r\nSubject: Hello\r\nDate: Tue, 01 Jan 2024 00:00:00 +0000"
    raw = _make_eml(headers, b"Hi")
    raw_utf16 = raw.decode("utf-8").encode("utf-16")

    ex = EmailFileExtractor(Settings()).extract_raw_eml_bytes(raw_utf16, "x.eml")
    assert ex.sender == "a@example.com"
    assert ex.subject == "Hello"


def test_multipart_alternative_extracts_urls(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    eml = (
        "From: a@example.com\r\n"
        "To: b@example.com\r\n"
        "Subject: Test\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: multipart/alternative; boundary=abc\r\n\r\n"
        "--abc\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello http://example.com\r\n"
        "--abc\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body>Hi <a href='http://example.com'>x</a></body></html>\r\n"
        "--abc--\r\n"
    ).encode("utf-8")

    ex = EmailFileExtractor(Settings()).extract_raw_eml_bytes(eml, "m.eml")
    assert "http://example.com" in ex.urls


def test_html_form_and_meta_refresh_urls_extracted(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    eml = (
        "From: news@example.com\r\nTo: b@example.com\r\nSubject: Html\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        "<html><head><meta http-equiv='refresh' content='0;url=https://example.fr/go'></head>"
        "<body><form action='https://example.fr/pay'><button>Pay</button></form></body></html>"
    ).encode("utf-8")
    ex = EmailFileExtractor(Settings()).extract_raw_eml_bytes(eml, "h.eml")
    assert "https://example.fr/go" in ex.urls
    assert "https://example.fr/pay" in ex.urls


def test_invalid_base64_rejected(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    r = client.post("/analyze/base64-eml", json={"base64_eml": "%%%", "filename": "x.eml"})
    assert r.status_code == 400
    assert "Invalid base64" in r.json()["detail"]


def test_newsletter_many_urls_dkim_pass_stays_legit(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    urls = " ".join([f"https://news.example.fr/u/{i}" for i in range(25)])
    eml = (
        "From: newsletter@example.fr\r\n"
        "To: b@example.com\r\n"
        "Subject: Weekly deals\r\n"
        "List-Unsubscribe: <https://example.fr/unsubscribe>\r\n"
        "Authentication-Results: mx; dkim=pass spf=pass dmarc=pass\r\n\r\n"
        f"Hello, see our offers {urls} and unsubscribe here https://example.fr/unsubscribe"
    ).encode("utf-8")
    result = _analyze(eml)
    assert result.verdict == "legit"
    assert result.score <= 15


def test_paypal_receipt_stays_legit(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    eml = (
        "From: service@paypal.com\r\n"
        "To: b@example.com\r\n"
        "Subject: Your PayPal receipt\r\n"
        "Authentication-Results: mx; dkim=pass spf=pass dmarc=pass\r\n\r\n"
        "Receipt amount 12.00 EUR. Manage your account at https://www.paypal.com/activity and unsubscribe preferences available."
    ).encode("utf-8")
    result = _analyze(eml)
    assert result.verdict == "legit"
    assert result.score <= 10


def test_phishing_with_reputation_and_brand_impersonation_stays_high(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    eml = (
        "From: \"PayPal\" <notice@paypal-account-security.xyz>\r\n"
        "To: b@example.com\r\n"
        "Subject: verify your account immediately\r\n"
        "Reply-To: help@evil.xyz\r\n\r\n"
        "Click here now: http://paypal-login-security.xyz/verify to confirm your password"
    ).encode("utf-8")
    result = _analyze(eml)
    assert result.verdict in {"suspicious", "phishing"}
    assert result.score >= 40


def test_hotmail_sender_urgent_without_structural_flag_not_phishing(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    eml = (
        "From: normalperson@hotmail.com\r\n"
        "To: b@example.com\r\n"
        "Subject: Urgent RE: invoice\r\n\r\n"
        "urgent please review the invoice and confirm by reply"
    ).encode("utf-8")
    result = _analyze(eml)
    assert result.verdict != "phishing"



def test_reputation_network_hits_raise_score(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", True)
    monkeypatch.setattr(rep, "_dnsbl_lookup", lambda domain, zone: zone == "dbl.spamhaus.org")
    monkeypatch.setattr(rep, "_http_post_json", lambda url, data: {"query_status": "is_available", "threat": "phishing"})
    rep._openphish_cache.update({"evil-paypal-login.com"})

    eml = (
        'From: "PayPal" <notice@paypal.com>\r\n'
        'To: b@example.com\r\n'
        'Subject: verify your account immediately\r\n\r\n'
        'Click here now: http://evil-paypal-login.com/verify'
    ).encode("utf-8")
    result = _analyze(eml)
    assert result.sub_scores["reputation"] >= 30
    assert any("OpenPhish" in r or "URLhaus" in r or "DNSBL" in r for r in result.reasons)


def test_forged_reply_chain_with_brand_reference_becomes_phishing(monkeypatch):
    monkeypatch.setattr(rep, "_ENABLE_REPUTATION_NET", False)
    eml = (
        "From: Charles Ross <charlesrosskwic@hotmail.com>\r\n"
        "To: b@example.com\r\n"
        "Subject: RE: Last Chance\r\n"
        "Message-ID: <abc@mailer.stripe.com>\r\n"
        "References: <thread@stripe.com>\r\n"
        "In-Reply-To: <thread@stripe.com>\r\n"
        "Authentication-Results: mx; dkim=pass spf=pass dmarc=pass\r\n\r\n"
        "vous avez été sélectionné offre exclusive gratuit prix "
        + " ".join([f"http://trk.bad.example/u/{i}?a=b%20c" for i in range(20)])
        + " unsubscribe"
    ).encode("utf-8")
    result = _analyze(eml)
    assert result.verdict == "phishing"
    assert result.indicators["structural_flag"] is True
    assert any("Forged reply-chain" in r for r in result.reasons)
