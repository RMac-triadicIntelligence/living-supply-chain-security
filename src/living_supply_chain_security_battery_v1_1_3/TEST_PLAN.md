# Claim-facing test plan — v1.1.3 — 2026-09-03

The active suite contains 117 tests: the submitted 111 plus six artifact snapshot
regressions. The original ten claim groups are retained. Six new tests are mapped
to MATURITY-IMPORT.

## Artifact boundary

- A byte subclass returning approved data from __bytes__ cannot substitute a different buffer.
- Byte subclasses are refused even when their raw buffer matches the signed content.
- Neither commit nor the eligibility helper calls a supplied verify method.
- A lying verification method cannot make the policy helper accept mismatched content.
- The artifact factory rejects custom byte conversion without calling it.
- Mutable byte buffers are refused; a failed import leaves state and history unchanged.

Existing regressions continue to cover exact signed metadata, substituted bytes,
missing content, live maturity checks, and successful authorized imports.

## State and authority

Existing tests cover recursive protected names, alias roots, exact external
bindings, replay/expiry, authority pins, persistence failures, rollback, and
sequence-based temporal BOM exports.

## Supplementary checks

Twelve bounded mutations include the original nine plus restoration of unsafe
byte conversion, delegation to supplied artifact verification, and removal of
the recursive protected-name scan. Each must trigger its named failing test.
The tool treats named FAIL and ERROR outcomes as caught.

The six original reviewer probes and the three byte-conversion cases also run
against the completed source. These tests are bounded executable checks; the
suite is not a formal proof or production certification.
