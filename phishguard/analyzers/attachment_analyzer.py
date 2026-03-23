from __future__ import annotations

from dataclasses import dataclass

from ..models import ExtractedEmailData


@dataclass
class AttachmentSignals:
    score: int
    reasons: list[str]


_RISKY_EXT = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".iso", ".img", ".lnk", ".jar",
    ".ps1", ".hta", ".msi", ".docm", ".xlsm",
}


def analyze_attachments(extracted: ExtractedEmailData) -> AttachmentSignals:
    if not extracted.attachments:
        return AttachmentSignals(score=0, reasons=[])

    score = 5
    reasons = [f"[attachment] Attachments: {len(extracted.attachments)}"]
    for a in extracted.attachments:
        name = (a.filename or "").lower()
        for ext in _RISKY_EXT:
            if name.endswith(ext):
                reasons.append(f"[attachment] Risky extension: {ext}")
                score += 15
                break
    return AttachmentSignals(score=min(score, 30), reasons=reasons)
