# Vocabulary

The source retains the research program's identifiers. These public-facing
explanations do not rename code, test identifiers, or claim-matrix keys.

| Source term | Meaning in this package |
|---|---|
| organism | Managed system whose state can change |
| organ | Capability artifact represented by bytes and signed inventory metadata |
| lineage | Provenance chain of committed transitions |
| dwelling / basin | Evidence accumulation and deferred commitment |
| Minato authority | External signing authority |
| determination | Authorization decision record |
| maturity | State used by capability-import eligibility policy |
| hard gate / through gate | Policy classifications; both still require authorization |
| grace | A research term appearing in test names; not an unsigned authorization mechanism |
| Refusal | Authorization or policy denial |
| state digest | Hash of state contents; it can repeat after rollback or a no-op |
| snapshot sequence | Commit occurrence; zero denotes initial state |

The governing rule remains: a system may propose its own update, while
commitment requires the configured external authority's signed authorization.
