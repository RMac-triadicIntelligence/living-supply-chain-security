#!/usr/bin/env python3
"""Reproduce the v1.1.2 artifact byte-conversion gap using synthetic data.

Usage: python review_probe_byte_conversion.py /path/to/living-supply-chain-security-v1.1.3
Exit 0 means all three expected outcomes hold; exit 1 reports a mismatch.
The reviewed v1.1.2 produced one unexpected commit. v1.1.3 meets all three expectations.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="Repository root or battery directory")
    args = parser.parse_args()
    battery = args.package.resolve()
    if not (battery / "living_scs" / "core.py").is_file():
        battery = battery / "src" / "living_supply_chain_security_battery_v1_1_3"
    if not (battery / "living_scs" / "core.py").is_file():
        parser.error("Could not locate living_scs/core.py")
    sys.path.insert(0, str(battery))

    from living_scs.core import Decision, Refusal, living_ai_bom, make_trace
    from living_scs.fixtures import NOW, engine, evidence, interpretation, organ

    approved_bytes = b"approved content"
    substituted_bytes = b"different unapproved content"

    class MisleadingBytes(bytes):
        def __bytes__(self):
            return approved_bytes

    approved = organ(name="search", content=approved_bytes, use_category="low")
    payload = {
        "op": "install_organ", "name": approved.name,
        "digest": approved.declared_digest,
        "use_category": approved.use_category, "source_uri": approved.source_uri,
    }
    candidates = [
        ("valid_plain_bytes", approved, True),
        ("ordinary_substitution", replace(approved, content=substituted_bytes), False),
        ("overridden_bytes_conversion", replace(approved, content=MisleadingBytes(substituted_bytes)), False),
    ]
    results = []
    for tag, candidate, expected_commit in candidates:
        signer, _, eng = engine(maturity="mature")
        prop = eng.proposal_for_mutation(
            proposal_id=tag + "-p", mutation_type="review_probe", mutation=payload,
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace = make_trace(prop, trace_id=tag + "-t")
        auth = signer.issue(
            trace, prop, decision=Decision.AUTHORIZE,
            determination_id=tag + "-d", nonce=tag + "-n",
            issued_at=NOW, expires_at=NOW + 60,
        )
        refusal = None
        try:
            eng.commit(prop, trace, auth, artifact=candidate)
            committed = True
        except Refusal as exc:
            committed = False
            refusal = str(exc)
        raw_digest = hashlib.sha256(memoryview(candidate.content)).hexdigest()
        results.append({
            "probe": tag,
            "artifact_type": type(candidate).__name__,
            "content_type": type(candidate.content).__name__,
            "expected_commit": expected_commit,
            "actual_commit": committed,
            "expectation_met": committed == expected_commit,
            "refusal": refusal,
            "signed_digest": approved.declared_digest,
            "raw_buffer_sha256": raw_digest,
            "converted_bytes_sha256": hashlib.sha256(bytes(candidate.content)).hexdigest(),
            "raw_buffer_matches_signed_digest": raw_digest == approved.declared_digest,
            "records": len(eng.records),
            "components": living_ai_bom(eng)["components"],
        })
    report = {
        "tested_core_sha256": hashlib.sha256((battery / "living_scs" / "core.py").read_bytes()).hexdigest(),
        "cases": len(results),
        "expectations_met": sum(item["expectation_met"] for item in results),
        "results": results,
    }
    print(json.dumps(report, indent=2))
    return 0 if all(item["expectation_met"] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
