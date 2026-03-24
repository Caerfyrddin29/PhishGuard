#Projet : PhishGuard
#Auteurs : Équipe PhishGuard

from __future__ import annotations

import re
from typing import Tuple

from bs4 import BeautifulSoup


def safe_filename(name: str) -> str:
    name = (name or "").strip().replace("\x00", "")
    name = re.sub(r"[^\w\.\-\(\) ]+", "_", name)
    return name or "attachment.bin"


def strip_html(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text("\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def looks_like_utf16_or_utf32(data: bytes) -> bool:
    if len(data) < 32:
        return False
    sample = data[:2048]
    zero_ratio = sample.count(b"\x00") / max(1, len(sample))
    return zero_ratio > 0.15


def normalize_eml_bytes(data: bytes) -> Tuple[bytes, list[str]]:
    warnings: list[str] = []

    if data.startswith(b"\xff\xfe\x00\x00") or data.startswith(b"\x00\x00\xfe\xff"):
        try:
            data = data.decode("utf-32", errors="replace").encode("utf-8")
            warnings.append("Detected UTF-32, converted to UTF-8.")
        except Exception:
            warnings.append("Failed UTF-32 decode; kept raw bytes.")
    elif data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            data = data.decode("utf-16", errors="replace").encode("utf-8")
            warnings.append("Detected UTF-16 BOM, converted to UTF-8.")
        except Exception:
            warnings.append("Failed UTF-16 decode; kept raw bytes.")
    elif looks_like_utf16_or_utf32(data):
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                data = data.decode(enc, errors="strict").encode("utf-8")
                warnings.append(f"Heuristic {enc} decode, converted to UTF-8.")
                break
            except Exception:
                continue

    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")

    if data.startswith(b"From ") and b"\r\n" in data[:200]:
        first_line, rest = data.split(b"\r\n", 1)
        if first_line.startswith(b"From "):
            data = rest
            warnings.append("Removed mbox 'From ' leading line.")

    return data, warnings
