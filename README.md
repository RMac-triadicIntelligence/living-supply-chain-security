# Living Supply-Chain Security v1.1.3

**Release date: 2026-09-03**

An executable reference for an enforcement layer around systems that update
their own state, configuration, or capability inventory.

**The rule:** a system may propose a change. Commitment requires an external
signed authorization bound to that exact transition.

v1.1.3 is the security patch release following the reviewed v1.1.2. It closes
the custom-byte-conversion bypass and records its own 117-test execution receipt.
The submitted v1.1.2 ZIP and its 111-test receipt are preserved byte-for-byte
under history/submitted-v1.1.2.zip.

## Security changes

- Capture immutable artifact data and hash plain bytes inside the enforcement boundary.
- Refuse bytes subclasses and mutable buffers without invoking conversion hooks.
- Check import eligibility from validated data without calling supplied verify methods.
- Recursively refuse organs/maturity aliases in personality mappings and lists.
- Preserve configured authority pins, exact signed bindings, and temporal BOM history.

Artifact content must have the exact built-in bytes type. Artifact metadata
must contain non-empty plain strings. The factory follows the same content
type contract. Actual module storage and loading belong to a deployment adapter.

## Verify

Tested with Python 3.12.13 and cryptography 46.0.0.

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r src/living_supply_chain_security_battery_v1_1_3/requirements.txt
python tools/verify_manifest.py
python src/living_supply_chain_security_battery_v1_1_3/run_all.py
python tools/check_mutations.py
python tools/review_probes_v1_1_1.py .
python tools/review_probe_byte_conversion.py .
~~~

Expected results: 117/117 battery tests; 10/10 mapped groups; 12/12 mutation
checks caught with baseline_unchanged true; 6/6 previous review probes;
3/3 byte-conversion probe expectations met. All commands exit 0.

**Claim coverage.** The claim-test matrix binds 55 of the 117 tests to the ten
claim groups. The remaining 62 are regression and internal-consistency tests
that back no stated claim. They are not defects and they are not evidence for
any claim group. To evaluate a specific property, read the tests the matrix
names for it rather than the suite total.

The archive folder, battery directory, package metadata, and current receipt
identify v1.1.3. Historical v1.1.2 references identify the retained predecessor.

## Package contents

| Path | Purpose |
|---|---|
| src/living_supply_chain_security_battery_v1_1_3/ | Engine, tests, matrix, runner, battery manifest |
| tools/ | Mutation checks, manifest verification, prior review probes |
| docs/ | Verification, claim boundary, release and validation records |
| reports/ | Recorded supplementary verification results |
| history/ | Submitted v1.1.2 archive and its provenance |
| MANIFEST.sha256 | Package source/documentation hashes |
| LICENSE and NOTICE | Supplied license terms and attribution |

The root manifest excludes generated reports and local interpreter caches;
rerunning validation may refresh report timestamps. Its source and documentation
hashes remain verifiable after a normal rerun.

See docs/CLAIM_BOUNDARY.md for the tested API and deployment assumptions.
A PASS is executable evidence for named cases, not production certification.

## License

Business Source License 1.1. Non-production use is free — clone it, run the
battery, reproduce the receipt, disable an enforcement line and watch it go red.
All of that is permitted and encouraged, because a security claim you cannot
check is worth nothing.

Production use requires a commercial license from the Licensor. On 2030-09-02
this work converts to the Apache License, Version 2.0.

See `LICENSE`, `NOTICE`, and `ABOUT_SOULSHINE.md`. There are no per-file license
headers: they would change hashes covered by `MANIFEST.sha256` and invalidate
the reproduction record.

Architecture, governing invariants, and paper: **Rusty Williams McMurray**.
All rights held by **Soulshine**, a 501(c)(3) nonprofit (Tulsa, Oklahoma).

