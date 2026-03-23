from __future__ import annotations

from phishguard.config import Settings
from phishguard.parser import EmailFileExtractor


def _make_eml(headers: str, body: bytes) -> bytes:
    return headers.encode("utf-8") + b"\r\n\r\n" + body


def test_utf16_eml_parses_headers():
    headers = "From: a@example.com\r\nTo: b@example.com\r\nSubject: Hello\r\nDate: Tue, 01 Jan 2024 00:00:00 +0000"
    raw = _make_eml(headers, b"Hi")
    raw_utf16 = raw.decode("utf-8").encode("utf-16")

    ex = EmailFileExtractor(Settings()).extract_raw_eml_bytes(raw_utf16, "x.eml")
    assert ex.sender == "a@example.com"
    assert ex.subject == "Hello"


def test_multipart_alternative_extracts_urls():
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
