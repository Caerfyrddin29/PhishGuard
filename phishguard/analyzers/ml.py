#Projet : PhishGuard
#Auteurs : Équipe PhishGuard

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import joblib

from ..config import Settings
from ..models import ExtractedEmailData


@dataclass
class MlSignals:
    score: int
    probability: Optional[float]
    reasons: list[str]


def _build_ml_text(extracted: ExtractedEmailData) -> str:
    parts = [
        f"Subject: {extracted.subject}",
        f"From: {extracted.sender}",
        f"To: {', '.join(extracted.to)}",
        extracted.body_text or "",
        extracted.body_html or "",
        " ".join(extracted.urls or []),
    ]
    return "\n".join([p for p in parts if p and p.strip()])


_MODEL_CACHE: dict = {}


def _local_predict(settings: Settings, text: str) -> Optional[float]:
    path = settings.ml_model_path
    if not path or not os.path.exists(path):
        return None
    if path not in _MODEL_CACHE:
        _MODEL_CACHE[path] = joblib.load(path)
    model = _MODEL_CACHE[path]
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba([text])[0]
        return float(proba[-1])
    return None


def _hf_predict(settings: Settings, text: str) -> Optional[float]:
    try:
        from transformers import pipeline  # type: ignore
    except Exception:
        return None

    clf = pipeline("text-classification", model=settings.hf_model_id, truncation=True)
    out = clf(text[:10000])
    if not out:
        return None
    best = max(out, key=lambda x: float(x.get("score", 0)))
    label = str(best.get("label", "")).lower()
    score = float(best.get("score", 0))
    if "phish" in label or "spam" in label or label.endswith("1"):
        return score
    return 1.0 - score


def analyze_ml(extracted: ExtractedEmailData, settings: Settings) -> MlSignals:
    text = _build_ml_text(extracted).strip()
    if not text:
        return MlSignals(score=0, probability=None, reasons=["[ml] No text available for ML"])

    proba = _local_predict(settings, text)
    if proba is None and settings.enable_hf_ml:
        proba = _hf_predict(settings, text)

    if proba is None:
        return MlSignals(score=0, probability=None, reasons=["[ml] Model not available"])

    score = int(round(min(30.0, max(0.0, proba * 30.0))))
    return MlSignals(score=score, probability=proba, reasons=[f"[ml] phishing_probability={proba:.3f}"])
