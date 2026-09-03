#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.statuses: dict[str, dict[str, str]] = {}

    @staticmethod
    def _short_id(test) -> str:
        parts = test.id().split(".")
        return ".".join(parts[-3:])

    def addSuccess(self, test):
        super().addSuccess(test)
        self.statuses[self._short_id(test)] = {"status": "PASS", "detail": ""}

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.statuses[self._short_id(test)] = {"status": "FAIL", "detail": self._exc_info_to_string(err, test)}

    def addError(self, test, err):
        super().addError(test, err)
        self.statuses[self._short_id(test)] = {"status": "ERROR", "detail": self._exc_info_to_string(err, test)}

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.statuses[self._short_id(test)] = {"status": "SKIP", "detail": reason}


class RecordingRunner(unittest.TextTestRunner):
    resultclass = RecordingResult


def load_matrix() -> dict:
    # JSON is valid YAML 1.2; this avoids adding a parser dependency to the runner.
    return json.loads((ROOT / "claim_test_matrix.yaml").read_text(encoding="utf-8"))


def source_manifest() -> dict[str, str]:
    manifest = {}
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("reports/") or rel == "MANIFEST.sha256" or rel.endswith(".zip") or "__pycache__" in rel:
            continue
        manifest[rel] = sha256_file(path)
    return manifest


def main() -> int:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    runner = RecordingRunner(verbosity=2, stream=sys.stdout)
    result: RecordingResult = runner.run(suite)

    matrix = load_matrix()
    claim_results = []
    missing_tests = []
    for claim in matrix["claims"]:
        tests = []
        for test_id in claim["tests"]:
            outcome = result.statuses.get(test_id)
            if outcome is None:
                missing_tests.append(test_id)
                outcome = {"status": "MISSING", "detail": "test not discovered"}
            tests.append({"test": test_id, **outcome})
        claim_results.append({
            "id": claim["id"],
            "claim": claim["claim"],
            "status": "PASS" if all(t["status"] == "PASS" for t in tests) else "RED",
            "tests": tests,
        })

    deterministic = {
        "battery": "living_supply_chain_security_battery_v1_1_3",
        "release_version": "1.1.3",
        "release_date": "2026-09-03",
        "schema": "living-scs/execution-receipt/v1",
        "tests": {key: result.statuses[key]["status"] for key in sorted(result.statuses)},
        "claims": {item["id"]: item["status"] for item in claim_results},
        "source_manifest": source_manifest(),
    }
    receipt_sha = hashlib.sha256(json.dumps(deterministic, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    counts = {
        "tests": result.testsRun,
        "passed": sum(v["status"] == "PASS" for v in result.statuses.values()),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "claims": len(claim_results),
        "claims_passed": sum(c["status"] == "PASS" for c in claim_results),
        "missing_matrix_tests": len(missing_tests),
    }
    verdict = "PASS" if result.wasSuccessful() and not missing_tests and counts["claims_passed"] == counts["claims"] else "RED"
    report = {
        **deterministic,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "claim_results": claim_results,
        "missing_matrix_tests": missing_tests,
        "verdict": verdict,
        "execution_receipt_sha256": receipt_sha,
        "interpretation": (
            "PASS means the supplied reference implementation satisfied every discovered test and every mapped test group. "
            "It is executable evidence, not a formal proof or a production certification."
        ),
    }
    (REPORTS / "execution_receipt.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "=== LIVING SUPPLY-CHAIN SECURITY FALSIFICATION BATTERY v1.1.3 ===",
        "RELEASE DATE: 2026-09-03",
        f"VERDICT: {verdict}",
        f"TESTS: {counts['tests']}  PASS: {counts['passed']}  FAIL: {counts['failed']}  ERROR: {counts['errors']}  SKIP: {counts['skipped']}",
        f"CLAIMS: {counts['claims']}  CLAIMS PASS: {counts['claims_passed']}  MATRIX MISSING: {counts['missing_matrix_tests']}",
        f"EXECUTION RECEIPT SHA-256: {receipt_sha}",
        "",
        "CLAIM RESULTS:",
    ]
    for claim in claim_results:
        lines.append(f"[{'PASS' if claim['status'] == 'PASS' else 'RED '}] {claim['id']} — {claim['claim']}")
    lines += ["", report["interpretation"]]
    (REPORTS / "execution_receipt.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (ROOT / "MANIFEST.sha256").write_text("\n".join(f"{digest}  {path}" for path, digest in sorted(source_manifest().items())) + "\n", encoding="utf-8")
    print("\n" + (REPORTS / "execution_receipt.txt").read_text(encoding="utf-8"))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
