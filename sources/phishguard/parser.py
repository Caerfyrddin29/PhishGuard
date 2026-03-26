#Projet : PhishGuard
#Auteurs : Myrddin Bellion, Ilyan Kassous

from __future__ import annotations

import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Optional, Tuple

from bs4 import BeautifulSoup

from .config import Settings
from .models import AttachmentInfo, ExtractedEmailData
from .utils import normalize_eml_bytes, safe_filename


EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+\.[A-Za-z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HTTP_URL_RE = re.compile(r"(?P<url>https?://[^\s<>\"]+)", re.IGNORECASE)


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _extract_urls_from_html(html: str) -> list[str]:
    urls: list[str] = []
    if not html:
        return urls
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag, attr in (("a", "href"), ("form", "action"), ("img", "src"), ("iframe", "src"), ("script", "src")):
            for node in soup.find_all(tag):
                value = (node.get(attr) or "").strip().strip('"\'')
                if value and value not in urls:
                    urls.append(value)
        for meta in soup.find_all("meta"):
            if (meta.get("http-equiv") or "").lower() == "refresh":
                content = meta.get("content") or ""
                m = re.search(r"url=([^;]+)$", content, re.I)
                if m:
                    value = m.group(1).strip().strip('"\'')
                    if value and value not in urls:
                        urls.append(value)
    except Exception:
        pass
    return urls


def _extract_bodies(msg: Message) -> Tuple[str, str]:
    text_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            if (part.get_content_disposition() or "").lower() == "attachment":
                continue
            ctype = (part.get_content_type() or "").lower()
            if ctype == "text/plain":
                text_parts.append(_decode_part(part))
            elif ctype == "text/html":
                html_parts.append(_decode_part(part))
    else:
        ctype = (msg.get_content_type() or "").lower()
        if ctype == "text/html":
            html_parts.append(_decode_part(msg))
        else:
            text_parts.append(_decode_part(msg))

    body_text = "\n\n".join([t.strip() for t in text_parts if t and t.strip()]).strip()
    body_html = "\n\n".join([h.strip() for h in html_parts if h and h.strip()]).strip()
    if body_html and not body_text:
        try:
            body_text = BeautifulSoup(body_html, "html.parser").get_text("\n", strip=True)
        except Exception:
            pass
    return body_text, body_html


def _parse_bytes(data: bytes) -> Tuple[Optional[Message], list[str]]:
    warnings: list[str] = []
    for pol, tag in ((policy.default, "default"), (policy.compat32, "compat32")):
        try:
            msg = BytesParser(policy=pol).parsebytes(data)
            if msg and msg.keys():
                if tag == "compat32":
                    warnings.append("Parsed with compat32 fallback.")
                return msg, warnings
        except Exception as e:
            warnings.append(f"BytesParser({tag}) failed: {e!r}")
    return None, warnings


def _manual_headers(data: bytes) -> dict[str, str]:
    text = data.decode("utf-8", errors="replace")
    header_blob = text.split("\r\n\r\n", 1)[0]
    lines = header_blob.split("\r\n")
    unfolded: list[str] = []
    for line in lines:
        if not line:
            continue
        if line[0] in (" ", "\t") and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line.strip())
    headers: dict[str, str] = {}
    for line in unfolded:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return headers


def _all_addrs(v: str) -> list[str]:
    out: list[str] = []
    for _name, addr in getaddresses([v or ""]):
        addr = (addr or "").strip()
        if addr and addr not in out:
            out.append(addr)
    return out


def _extract_indicators(text: str) -> tuple[list[str], list[str], list[str]]:
    urls: list[str] = []
    for m in HTTP_URL_RE.finditer(text or ""):
        u = m.group("url").rstrip(").,;]}>\"'")
        if u not in urls:
            urls.append(u)

    emails: list[str] = []
    for m in EMAIL_RE.finditer(text or ""):
        e = m.group(0).lower()
        if e not in emails:
            emails.append(e)

    ips: list[str] = []
    for m in IP_RE.finditer(text or ""):
        ip = m.group(0)
        if ip not in ips:
            ips.append(ip)

    return urls, emails, ips


class EmailFileExtractor:
    def __init__(self, settings: Settings):
        self.settings = settings

    def extract(self, file_path: str) -> ExtractedEmailData:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(str(path))
        ext = path.suffix.lower()
        if ext == ".eml":
            return self.extract_raw_eml_bytes(path.read_bytes(), path.name)
        if ext == ".msg":
            return self._extract_msg(path)
        raise ValueError(f"Unsupported file type: {ext}")

    def extract_raw_eml_bytes(self, raw: bytes, filename: str) -> ExtractedEmailData:
        normalized, norm_warnings = normalize_eml_bytes(raw)
        msg, parse_warnings = _parse_bytes(normalized)

        manual = {}
        if msg is None or not msg.keys():
            manual = _manual_headers(normalized)
            parse_warnings.append("Used manual header fallback (no headers after parse).")

        def h(name: str) -> str:
            if msg is not None:
                v = msg.get(name, "")
                if isinstance(v, str):
                    return v.strip()
            return manual.get(name.lower(), "").strip()

        subject = h("Subject")
        sender = parseaddr(h("From"))[1] or h("From")
        to = _all_addrs(h("To"))
        cc = _all_addrs(h("Cc"))
        bcc = _all_addrs(h("Bcc"))
        date = h("Date")

        if msg is not None:
            raw_headers = "".join([f"{k}: {v}\n" for (k, v) in msg.items()])
        else:
            raw_headers = normalized.decode("utf-8", errors="replace").split("\r\n\r\n", 1)[0]

        body_text = ""
        body_html = ""
        attachments: list[AttachmentInfo] = []
        received_hops = 0

        if msg is not None:
            body_text, body_html = _extract_bodies(msg)
            attachments = self._extract_attachments(msg)
            received_hops = len(msg.get_all("Received", []) or [])

        all_indicator_text = (body_text or "") + "\n" + (body_html or "")
        urls, emails_found, ips_found = _extract_indicators(all_indicator_text.strip())
        for u in _extract_urls_from_html(body_html):
            if u not in urls:
                urls.append(u)

        return ExtractedEmailData(
            file_path=filename,
            file_type="eml",
            subject=subject,
            sender=sender,
            to=to,
            cc=cc,
            bcc=bcc,
            date=date,
            raw_headers=raw_headers,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            emails_found_in_body=emails_found,
            ips_found_in_body=ips_found,
            attachments=attachments,
            technical_details={"received_hops": received_hops, "filename": filename},
            parse_warnings=[*norm_warnings, *parse_warnings],
        )

    def _extract_attachments(self, msg: Message) -> list[AttachmentInfo]:
        out: list[AttachmentInfo] = []
        save_to_disk = bool(self.settings.save_attachments)
        base_dir = Path(self.settings.attachments_dir)
        if save_to_disk:
            base_dir.mkdir(parents=True, exist_ok=True)

        for part in msg.iter_attachments():
            filename = safe_filename(part.get_filename() or "attachment.bin")
            payload = part.get_payload(decode=True) or b""
            content_type = (part.get_content_type() or "").lower()
            saved_path = ""

            if save_to_disk:
                target = base_dir / filename
                if target.exists():
                    stem = target.stem
                    suf = target.suffix
                    i = 1
                    while True:
                        cand = base_dir / f"{stem}_{i}{suf}"
                        if not cand.exists():
                            target = cand
                            break
                        i += 1
                target.write_bytes(payload)
                saved_path = str(target)

            out.append(
                AttachmentInfo(
                    filename=filename,
                    saved_path=saved_path,
                    size_bytes=len(payload),
                    content_type=content_type,
                )
            )
        return out

    def _extract_msg(self, path: Path) -> ExtractedEmailData:
        import extract_msg  # type: ignore

        msg = extract_msg.Message(str(path))
        msg_sender = parseaddr(getattr(msg, "sender", "") or "")[1] or (getattr(msg, "sender", "") or "")
        body_text = getattr(msg, "body", "") or ""
        body_html = getattr(msg, "htmlBody", b"") or b""
        if isinstance(body_html, (bytes, bytearray)):
            body_html = body_html.decode("utf-8", errors="replace")

        attachments: list[AttachmentInfo] = []
        save_to_disk = bool(self.settings.save_attachments)
        base_dir = Path(self.settings.attachments_dir)
        if save_to_disk:
            base_dir.mkdir(parents=True, exist_ok=True)
        for att in getattr(msg, "attachments", []) or []:
            filename = safe_filename(getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "attachment.bin")
            data = getattr(att, "data", b"") or b""
            saved_path = ""
            if save_to_disk:
                target = base_dir / filename
                target.write_bytes(data)
                saved_path = str(target)
            attachments.append(AttachmentInfo(filename=filename, saved_path=saved_path, size_bytes=len(data), content_type=""))

        raw_headers = getattr(msg, "header", "") or ""
        urls, emails_found, ips_found = _extract_indicators((body_text or "") + "\n" + (body_html or ""))
        for u in _extract_urls_from_html(body_html):
            if u not in urls:
                urls.append(u)

        return ExtractedEmailData(
            file_path=path.name,
            file_type="msg",
            subject=getattr(msg, "subject", "") or "",
            sender=msg_sender,
            to=_all_addrs(getattr(msg, "to", "") or ""),
            cc=_all_addrs(getattr(msg, "cc", "") or ""),
            bcc=_all_addrs(getattr(msg, "bcc", "") or ""),
            date=str(getattr(msg, "date", "") or ""),
            raw_headers=raw_headers,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            emails_found_in_body=emails_found,
            ips_found_in_body=ips_found,
            attachments=attachments,
            technical_details={"received_hops": raw_headers.lower().count("received:"), "filename": path.name},
            parse_warnings=[],
        )
