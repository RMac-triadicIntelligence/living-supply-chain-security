# Changelog

## 1.1.3 — 2026-09-03

Security patch release following the submitted v1.1.2 packages. Archive paths,
package metadata, documentation, and the new receipt identify v1.1.3. Submitted
v1.1.2 bytes are archived under history with their original 111-test receipt.

### Fixed

- Reject custom byte conversion and mutable artifact buffers at the boundary.
- Capture exact bytes and plain-string metadata before enforcing digest binding.
- Use data-only eligibility; never invoke the supplied artifact verify method.
- Apply the same snapshot validation to standalone eligibility and base verification.
- Require plain bytes at the artifact factory instead of coercing supplied values.

### Added

- Six artifact snapshot regressions: 117 tests total.
- Three bounded mutations: 12 mutation targets total.
- Earlier review probes, release provenance, and package manifest verification.

### Documentation

- Complete README, AUTHORS, test plan, claim boundary, and verification instructions.
- Regenerate the active receipt and validation record for the v1.1.3 bytes.
- Retain the supplied LICENSE and NOTICE exactly.


## 1.1.2 — 2026-09-02

Addresses the v1.1.1 review findings.

### Fixed

- Commit no longer trusts `OrganArtifact.verify()`. The engine hashes
  `artifact.content` and compares that digest to the signed mutation digest
  and the declared digest. A subclass that returns `True` from `verify()`
  cannot substitute different bytes.
- Personality is scanned recursively, including nested dicts and lists, for
  keys that NFKC-casefold to `organs` or `maturity`.
  `personality.preferences.organs` and list-embedded lookalikes are refused.

### Added

- Four review-gap regressions.
- `LICENSE` (Business Source License 1.1) and `NOTICE`.

### Preserved

- `POLICY_VERSION` remains `LIVING-SCS-POLICY-V1.1`.
- v1.1 and v1.1.1 tests remain and must still pass.

## 1.1.1 — 2026-09-02

Tightening revision. Sealed v1.1.0 source and receipt stay historical.

### Fixed

- Refuse signed `set` writes that are not under exact `personality`.
- Treat NFKC-casefold aliases of `organs` and `maturity` as protected roots
  (`Organs`, `ORGANS`, `Maturity`).
- Refuse unknown top-level roots (`capabilities`, homoglyph `orgаns`, policy
  label rewrites).
- Refuse `personality.organs` and personality dicts that shadow inventory.
- Validate resulting-state shape: only `maturity`, `personality`, `organs`,
  `policy`.

### Added

- 7 `StateSchemaTests` regressions (107 tests total).
- Claim-matrix bindings for the new schema tests.

### Unchanged

- Policy identifier `LIVING-SCS-POLICY-V1.1`
- Constructor authority pins
- `commit(..., artifact=)` import enforcement
- Living-AI-BOM 0.2 snapshot sequences
- Nine mutation targets in `tools/check_mutations.py`

## 1.1.0 — 2026-09-02

See the v1.1.0 repository. That release added commit-time import enforcement,
authority pins, and temporal BOM sequences (100 tests).
