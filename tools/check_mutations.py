#!/usr/bin/env python3
"""Run twelve bounded mutations on disposable copies of v1.1.3."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BATTERY = ROOT / "src" / "living_supply_chain_security_battery_v1_1_3"

MUTATIONS = (
    (
        "M1", "signature verification",
        "if not self._authority.verify(auth):",
        "if False and not self._authority.verify(auth):",
        "test_minato_binding.MinatoBindingTests.test_changed_nonce_breaks_signature",
    ),
    (
        "M2", "authorization decision",
        "if auth.decision is not Decision.AUTHORIZE:",
        "if False and auth.decision is not Decision.AUTHORIZE:",
        "test_authorization_seam.AuthorizationSeamTests.test_refusal_decision_cannot_commit",
    ),
    (
        "M3", "nonce and determination replay",
        "if auth.nonce in self._used_nonces or auth.determination_id in self._used_determinations:",
        "if False and (auth.nonce in self._used_nonces or auth.determination_id in self._used_determinations):",
        "test_minato_binding.MinatoBindingTests.test_determination_id_replay_is_rejected",
    ),
    (
        "M4", "authorization expiry",
        "if auth.expires_at < now:",
        "if False and auth.expires_at < now:",
        "test_minato_binding.MinatoBindingTests.test_expired_authorization_is_rejected",
    ),
    (
        "M5", "verifier signing guard",
        "if self._private_key is None:",
        "if False:",
        "test_adversarial_fence.AdversarialFenceTests.test_verifier_only_boundary_cannot_sign",
    ),
    (
        "M6", "commit policy enforcement",
        "self._validate_mutation_policy(proposal, new_state, artifact)",
        "pass  # mutation: omit commit policy enforcement",
        "test_commit_policy.CommitPolicyTests.test_juvenile_high_import_is_refused_at_commit",
    ),
    (
        "M7", "temporal BOM first-occurrence regression",
        "return digest, copy.deepcopy(self._states[digest]), records[:sequence]",
        "cut = next((record.sequence for record in records if record.resulting_digest == digest), len(records))\n"
        "            return digest, copy.deepcopy(self._states[digest]), records[:cut]",
        "test_temporal_bom.TemporalBomTests.test_current_bom_preserves_every_record_after_rollback",
    ),
    (
        "M8", "constructor public-key pin check",
        "if supplied_public_key != expected_public_key:",
        "if False and supplied_public_key != expected_public_key:",
        "test_authority_pinning.AuthorityPinningTests.test_constructor_rejects_injected_key_under_expected_identity",
    ),
    (
        "M9", "verification delegated to injected authority",
        "self._authority = MinatoAuthority.verifier_only(\n"
        "            expected_authority_id, Ed25519PublicKey.from_public_bytes(expected_public_key)\n"
        "        )",
        "self._authority = authority",
        "test_authority_pinning.AuthorityPinningTests.test_injected_verify_method_is_not_trusted",
    ),
    (
        "M10", "restore caller-controlled byte conversion",
        "    if type(content) is not bytes or not content:\n"
        "        raise Refusal(\"organ import requires verified artifact bytes\")\n"
        "    computed_digest = hashlib.sha256(content).hexdigest()",
        "    content = bytes(content)\n"
        "    if not content:\n"
        "        raise Refusal(\"organ import requires verified artifact bytes\")\n"
        "    computed_digest = hashlib.sha256(content).hexdigest()",
        "test_artifact_snapshot.ArtifactSnapshotTests.test_byte_conversion_substitution_is_refused",
    ),
    (
        "M11", "policy helper trusts supplied artifact verification",
        "        try:\n"
        "            checked = _artifact_snapshot(organ)\n"
        "        except Refusal:\n"
        "            return False\n"
        "        return cls.eligible_use(maturity, checked.use_category)",
        "        return cls.eligible_use(maturity, organ.use_category) and organ.verify()",
        "test_artifact_snapshot.ArtifactSnapshotTests.test_policy_helper_rejects_lying_artifact",
    ),
    (
        "M12", "recursive protected-name scan disabled for mappings",
        "if isinstance(value, Mapping):",
        "if False and isinstance(value, Mapping):",
        "test_review_gaps.ReviewGapTests.test_nested_personality_preferences_organs_is_refused",
    ),
)


def hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
    }


def main() -> int:
    baseline = hashes(BATTERY)
    results = []
    for mutation_id, target, old, new, expected_test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix=f"living-scs-{mutation_id}-") as temp:
            working = Path(temp) / "battery"
            shutil.copytree(BATTERY, working, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            core = working / "living_scs" / "core.py"
            source = core.read_text(encoding="utf-8")
            if source.count(old) != 1:
                raise RuntimeError(f"{mutation_id}: enforcement target is not unique")
            core.write_text(source.replace(old, new, 1), encoding="utf-8")
            execution = subprocess.run(
                [sys.executable, "run_all.py"], cwd=working,
                capture_output=True, text=True, timeout=60,
            )
            report_path = working / "reports" / "execution_receipt.json"
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
            outcome = report.get("tests", {}).get(expected_test)
            caught = execution.returncode == 1 and report.get("verdict") == "RED" and outcome in {"FAIL", "ERROR"}
            results.append({
                "mutation": mutation_id, "target": target, "caught": caught,
                "failed": report.get("counts", {}).get("failed"),
                "errors": report.get("counts", {}).get("errors"),
                "expected_test": expected_test, "test_status": outcome,
            })
            if not caught:
                print(execution.stdout + execution.stderr, file=sys.stderr)
    unchanged = hashes(BATTERY) == baseline
    passed = unchanged and all(item["caught"] for item in results)
    print(json.dumps({
        "verdict": "PASS" if passed else "RED",
        "baseline_unchanged": unchanged,
        "mutations": results,
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
