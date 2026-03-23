from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _resolve_model_path(name: str) -> str:
    candidates = []
    cwd = Path.cwd()
    candidates.append(cwd / "models" / name)

    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidates.append(parent / "models" / name)
        candidates.append(parent.parent / "models" / name)

    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[0])


@dataclass(frozen=True)
class Settings:
    """Runtime settings via env vars."""

    ml_model_path: str = os.getenv("PHISHGUARD_MODEL_PATH", _resolve_model_path("phishing_model.joblib"))
    enable_hf_ml: bool = os.getenv("PHISHGUARD_ENABLE_HF_ML", "0") == "1"
    hf_model_id: str = os.getenv("PHISHGUARD_HF_MODEL", "cybersectony/phishing-email-detection-distilbert_v2.4.1")

    temp_dir: str = os.getenv("PHISHGUARD_TEMP_DIR", str(Path.cwd() / "tmp"))
    attachments_dir: str = os.getenv("PHISHGUARD_ATTACHMENTS_DIR", str(Path.cwd() / "Attachments"))
