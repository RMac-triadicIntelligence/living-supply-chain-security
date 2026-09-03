#!/usr/bin/env python3
"""Normalize a frozen historical cold-fence JSON report without changing its verdict semantics."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--out", type=Path, default=Path("normalized_historical_report.json"))
    args = parser.parse_args()
    raw = args.report.read_bytes()
    data = json.loads(raw)
    normalized = {
        "source_report": str(args.report),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "harness_verdict": data.get("harness_verdict"),
        "artifact_verdict": data.get("artifact_verdict"),
        "counts": data.get("counts", {}),
        "results": data.get("results", []),
        "warning": "A PASS harness verdict does not convert a RED target artifact into a safe artifact.",
    }
    args.out.write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n")
    print(args.out)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
