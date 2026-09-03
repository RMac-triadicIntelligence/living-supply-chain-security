# Release record — v1.1.3 / 2026-09-03

Rusty Williams McMurray requested completion of two uploaded packages. Their ZIP
bytes and internal file contents were identical. Both outputs contain the same
v1.1.3 source; the Grok filename is retained as a requested file label.

## Changes

- Capture a trusted artifact snapshot with exact bytes content and plain-string metadata.
- Hash the captured bytes directly; avoid caller-defined byte conversion.
- Remove supplied artifact verification from both commit and helper eligibility.
- Align factory and built-in verification with the strict byte-content contract.
- Add six behavioral regressions and three mutation targets.
- Update README, AUTHORS, verification, claim-boundary, and test-plan text.
- Preserve LICENSE and NOTICE byte-for-byte.
- Preserve the submitted ZIP and identify the completed source with its own receipt.
- Include earlier review probes and a root source/documentation manifest.

The release version is 1.1.3 because these security changes extend the reviewed
111-test v1.1.2 package. The archive folders, source directory, package metadata,
and execution receipt all use v1.1.3. The validated suite has 117 tests. Actual result digests are recorded in VALIDATION.md.

The prior review's byte-conversion case now refuses the mismatched artifact.
The normal import control still commits. The prior nested-shadow and verifier
override cases also pass their expected refusal checks.

Implementation and local verification were assisted by ChatGPT (OpenAI) Grok XAi, And Anthropic Claude.
This release is a bounded repair of the reference implementation; deployment
assumptions remain documented in CLAIM_BOUNDARY.md.
