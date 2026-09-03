# Claim boundary — v1.1.3 — 2026-09-03

## What the current checks establish

The supplied reference implementation passes 117 named tests and ten mapped
test groups at the source hashes in its current receipt. Twelve bounded
mutations are caught on disposable copies. The six earlier review probes and
all three byte-conversion probe expectations pass. See VALIDATION.md.

The exercised API checks exact external signed authorization, configured
identity/key pins, live maturity, artifact metadata and bytes, recursive
protected state names, and history across repeated state digests.

## Artifact and adapter contract

The artifact factory and engine require exact built-in bytes content. The
engine captures content and non-empty plain-string metadata into an immutable
base value, computes SHA-256 from the captured bytes, compares it with the
signed digest, and applies eligibility to the checked data. It does not invoke
a supplied artifact's __bytes__ or verify method. Byte subclasses and mutable
buffers are refused. The standalone eligibility helper uses the same trusted
snapshot validation.

Artifact subclasses with ordinary immutable data can still pass, but their
custom verification behavior supplies no authority. This Python API is not an
isolation boundary against arbitrary code executing in the trusted process.
The deployment must protect the engine, constructor, and trusted configuration.

Personality is checked recursively through mappings, lists, and tuples for keys
whose NFKC-casefold form is organs or maturity. Generic set is confined to exact
personality. Consumers should use BOM components or the exact inventory fields;
interpretation of arbitrary text or unrelated nested values remains an adapter
choice, not an additional source of authority.

## Trust and deployment assumptions

- Authority pins and initial state are trusted deployment inputs. The governed
  system must not choose its own expected key or replace enforcement code.
- The deterministic fixture signing key is public test data. Production signing
  keys require protected external custody.
- This is an inventory/state-transition engine. It does not execute modules or
  implement a durable artifact store. A loader must validate the bytes it
  actually loads against the authorized digest and use a stable snapshot.
- Restores use known snapshots from trusted initial state and successful commits.
  Retrieval and loading after a restart remain deployment responsibilities.
- History, time, and replay tracking are local. Hash chaining is not an external
  transparency log, and a party able to rewrite the entire store is outside the
  stated model. Cross-instance replay protection and recovery require deployment
  mechanisms beyond this reference.
- Persistence-hook tests exercise bounded in-memory behavior. They do not
  establish a transactional database or crash-recovery protocol.
- Evidence checks are structural. Declared identifiers and digests do not
  independently establish evidence truth. The accumulation test uses 100,000
  additions, not mathematical infinity.
- Exports are reference formats. No in-toto, SPDX, or CycloneDX conformance
  certification is claimed. A sequence identifies a commit occurrence; digest
  selection alone returns its latest occurrence.
- A passing suite or mutation check is not exhaustive security analysis, formal
  proof, or production certification, and does not validate historical targets.

## Provenance

The submitted v1.1.2 ZIP is preserved byte-for-byte under history, including its
111-test source and receipt. Both supplied ZIPs were identical. The current
package is v1.1.3, dated 2026-09-03, with its own release_version and battery
identifier in the receipt. Its current digest applies only to the v1.1.3 source.

Earlier v1/v1.1 records are historical context; this package does not newly
rerun or authenticate those earlier releases. The root manifest additionally
covers documentation, licensing files, and the retained submitted archive.

## Licensing

The supplied LICENSE and NOTICE are retained exactly. The release does not
change their terms or resolve prior licensing provenance. AUTHORS.md identifies
architectural attribution and the assistance used for this release.
