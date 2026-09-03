# Verification — v1.1.3 — 2026-09-03

From the package root, use Python 3.12 with the battery's requirements installed:

~~~bash
python tools/verify_manifest.py
python src/living_supply_chain_security_battery_v1_1_3/run_all.py
python tools/check_mutations.py
python tools/review_probes_v1_1_1.py .
python tools/review_probe_byte_conversion.py .
~~~

Expected battery summary:

~~~text
RELEASE DATE: 2026-09-03
VERDICT: PASS
TESTS: 117  PASS: 117  FAIL: 0  ERROR: 0  SKIP: 0
CLAIMS: 10  CLAIMS PASS: 10  MATRIX MISSING: 0
~~~

The mutation tool must report PASS, baseline_unchanged true, and twelve caught
mutations. The earlier review suite must report six passes. The byte-conversion
probe must report three cases and three expectations met. All exit codes are 0.

The review assertions are retained from the earlier reviews, with package paths
updated for v1.1.3. References to historical failing outcomes describe old source. The current
expected outcomes are those above.

The authoritative current receipt and supplementary results are summarized in
VALIDATION.md. Source changes require a new receipt. The release_version field
and battery identifier distinguish v1.1.3 from the submitted v1.1.2 package.

The root manifest covers source, documentation, licenses, the battery manifest,
and the preserved historical archive. Generated reports and caches are excluded.
After intentional source edits, rerun the battery, update the validation record,
and regenerate the root manifest with python tools/verify_manifest.py --write.
