#!/usr/bin/env python3
"""Additional public-API regressions for Living SCS v1.1.1.

Run: python review_probes.py /path/to/living-supply-chain-security-v1.1.3

The original v1.1.1 produced 6 tests, 3 passes, 3 failures. v1.1.3 passes all six.
The failures demonstrate two findings; dictionary and list payloads exercise
the same nested-shadow finding. The script never edits the target package.
All proposals use the package's public, deterministic TEST signer.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import platform
import sys
import unittest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="Repository root or battery directory")
    parser.add_argument("--json", type=Path, help="Optional result file outside the target package")
    args = parser.parse_args()
    battery = args.package.resolve()
    if not (battery / "living_scs" / "core.py").is_file():
        battery = battery / "src" / "living_supply_chain_security_battery_v1_1_3"
    if not (battery / "living_scs" / "core.py").is_file():
        parser.error("Could not find living_scs/core.py under the supplied path")
    if args.json and args.json.resolve().is_relative_to(battery):
        parser.error("Write probe results outside the target battery")
    sys.path.insert(0, str(battery))

    import cryptography
    from living_scs.core import Decision, OrganArtifact, Refusal, living_ai_bom, make_trace, sha256_hex
    from living_scs.fixtures import NOW, engine, evidence, interpretation, organ

    class PermissiveArtifact(OrganArtifact):
        def verify(self):
            return True

    class ReviewProbes(unittest.TestCase):
        def signed(self, signer, eng, payload):
            prop = eng.proposal_for_mutation(
                proposal_id="review-proposal", mutation_type="review_probe",
                mutation=payload, evidence=evidence(),
                interpretation=interpretation(), created_at=NOW,
            )
            trace = make_trace(prop, trace_id="review-trace")
            auth = signer.issue(
                trace, prop, decision=Decision.AUTHORIZE,
                determination_id="review-determination", nonce="review-nonce",
                issued_at=NOW, expires_at=NOW + 60,
            )
            return prop, trace, auth

        def import_case(self):
            signer, _, eng = engine(maturity="mature")
            approved = organ(name="search", content=b"approved content", use_category="low")
            payload = {
                "op": "install_organ", "name": approved.name,
                "digest": approved.declared_digest,
                "use_category": approved.use_category,
                "source_uri": approved.source_uri,
            }
            return eng, approved, self.signed(signer, eng, payload)

        def expect_refusal(self, eng, signed, **kwargs):
            before = eng.state_digest
            with self.assertRaises(Refusal):
                eng.commit(*signed, **kwargs)
            self.assertEqual(eng.state_digest, before)
            self.assertEqual(eng.records, ())

        def test_normal_artifact_mismatch_is_rejected(self):
            eng, approved, signed = self.import_case()
            tampered = replace(approved, content=b"different unapproved content")
            self.expect_refusal(eng, signed, artifact=tampered)

        def test_valid_artifact_is_accepted(self):
            eng, approved, signed = self.import_case()
            eng.commit(*signed, artifact=approved)
            self.assertEqual(len(eng.records), 1)
            self.assertEqual(
                living_ai_bom(eng)["components"][0]["digest"]["sha256"],
                sha256_hex(approved.content),
            )

        def test_overridden_verify_cannot_approve_mismatched_bytes(self):
            eng, approved, signed = self.import_case()
            tampered = PermissiveArtifact(
                approved.name, b"different unapproved content",
                approved.use_category, approved.declared_digest, approved.source_uri,
            )
            self.assertNotEqual(sha256_hex(tampered.content), approved.declared_digest)
            self.expect_refusal(eng, signed, artifact=tampered)

        def shadow_case(self, path, value):
            signer, _, eng = engine()
            signed = self.signed(signer, eng, {"op": "set", "path": path, "value": value})
            return eng, signed

        @staticmethod
        def shadow():
            return {"organs": {"hidden": {
                "digest": "a" * 64, "use_category": "high", "source_uri": "test://shadow",
            }}}

        def test_direct_shadow_is_rejected(self):
            eng, signed = self.shadow_case(["personality", "organs"], self.shadow()["organs"])
            self.expect_refusal(eng, signed)

        def test_nested_dictionary_cannot_shadow_inventory(self):
            eng, signed = self.shadow_case(["personality", "preferences"], self.shadow())
            self.expect_refusal(eng, signed)

        def test_nested_list_cannot_shadow_inventory(self):
            eng, signed = self.shadow_case(["personality", "preferences"], [self.shadow()])
            self.expect_refusal(eng, signed)

    class RecordingResult(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.outcomes = {}

        def addSuccess(self, test):
            super().addSuccess(test)
            self.outcomes[test._testMethodName] = "PASS"

        def addFailure(self, test, err):
            super().addFailure(test, err)
            self.outcomes[test._testMethodName] = "FAIL"

        def addError(self, test, err):
            super().addError(test, err)
            self.outcomes[test._testMethodName] = "ERROR"

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReviewProbes)
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    report = {
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "tested_core_sha256": hashlib.sha256((battery / "living_scs" / "core.py").read_bytes()).hexdigest(),
        "tests": result.testsRun,
        "passed": sum(status == "PASS" for status in result.outcomes.values()),
        "failed": len(result.failures),
        "errors": len(result.errors),
        "outcomes": result.outcomes,
        "interpretation": "These supplemental expectations are separate from the supplied release battery. Nested-shadow expectations require a stronger recursive anti-shadowing contract than exact-field adapters need.",
    }
    print(json.dumps(report, indent=2))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
