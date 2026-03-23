from __future__ import annotations

import argparse
import json
from dataclasses import asdict, is_dataclass
from typing import Any

from phishguard.config import Settings
from phishguard.parser import EmailFileExtractor
from phishguard.analyzers.hybrid import HybridPhishingAnalyzer


def _to_jsonable(obj: Any):
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    settings = Settings()
    extractor = EmailFileExtractor(settings=settings)
    analyzer = HybridPhishingAnalyzer(settings=settings)

    extracted = extractor.extract(args.path)
    result = analyzer.analyze_extracted(extracted)

    payload = {"extracted_email": _to_jsonable(extracted), "analysis_result": _to_jsonable(result)}

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        r = result
        print(f"File    : {extracted.file_path}")
        print(f"Subject : {extracted.subject or '(none)'}")
        print(f"Sender  : {extracted.sender or '(unknown)'}")
        print(f"Verdict : {r.verdict.upper()}  |  Score: {r.score}/100  |  Confidence: {r.confidence}")
        if r.reasons:
            print("Reasons :")
            for reason in r.reasons[:10]:
                print(f"  - {reason}")


if __name__ == "__main__":
    main()
