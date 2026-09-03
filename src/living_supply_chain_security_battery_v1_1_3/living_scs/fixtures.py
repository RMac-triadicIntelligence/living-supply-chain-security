from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping, Optional

from .core import (
    CommitEngine,
    Decision,
    EvidenceItem,
    Interpretation,
    MinatoAuthority,
    OrganArtifact,
    POLICY_VERSION,
    ProposalStatus,
    TrustedClock,
    deterministic_test_private_key,
    make_trace,
)

NOW = 1_800_000_000


def initial_state() -> dict[str, Any]:
    return {
        "maturity": "juvenile",
        "personality": {"verbosity": 0.50, "skepticism": 0.60},
        "organs": {},
        "policy": POLICY_VERSION,
    }


def authority_pair():
    signer = MinatoAuthority("owner-root-1", deterministic_test_private_key())
    verifier = MinatoAuthority.verifier_only("owner-root-1", signer.public_key)
    return signer, verifier


def engine(*, maturity: str = "juvenile", persist_hook=None, organism_id: str = "organism-alpha"):
    signer, verifier = authority_pair()
    state = initial_state()
    state["maturity"] = maturity
    clock = TrustedClock(NOW)
    return signer, clock, CommitEngine(
        organism_id, state, verifier, clock,
        expected_authority_id="owner-root-1",
        expected_public_key=deterministic_test_private_key().public_key().public_bytes_raw(),
        persist_hook=persist_hook,
    )


def evidence(n: int = 2, *, detector: str = "rule_counter", source_prefix: str = "episode", duplicate: bool = False):
    items = []
    for i in range(n):
        evidence_id = "e-0" if duplicate else f"e-{i}"
        items.append(EvidenceItem(
            evidence_id=evidence_id,
            source_uri=f"memory://{source_prefix}/{i}",
            observed_at=NOW - 10 + i,
            detector=detector,
            detector_version="1.0",
            value={"signal": "verbosity_down", "count": i + 1},
        ))
    return tuple(items)


def interpretation(*, confidence: float = 0.91, salience: float = 0.72, resonance: float = 0.50, convergence: float = 0.80):
    return Interpretation(
        method="fenced-enumerated-reader",
        version="0.3",
        output={"read_as": "prefers_brevity", "delta": -0.05},
        confidence=confidence,
        salience=salience,
        resonance=resonance,
        convergence=convergence,
    )


def mutation(value: float = 0.45):
    return {"op": "set", "path": ["personality", "verbosity"], "value": value}


def proposal_trace_auth(
    *,
    maturity: str = "juvenile",
    mutation_value: float = 0.45,
    decision: Decision = Decision.AUTHORIZE,
    nonce: str = "nonce-1",
    determination_id: str = "det-1",
    organism_id: str = "organism-alpha",
    created_at: int = NOW,
    expires_at: int = NOW + 600,
    confidence: float = 0.91,
    salience: float = 0.72,
    persist_hook=None,
):
    signer, clock, eng = engine(maturity=maturity, persist_hook=persist_hook, organism_id=organism_id)
    prop = eng.proposal_for_mutation(
        proposal_id="proposal-1",
        mutation_type="personality_drift",
        mutation=mutation(mutation_value),
        evidence=evidence(),
        interpretation=interpretation(confidence=confidence, salience=salience),
        maturity_state=maturity,
        created_at=created_at,
    )
    trace = make_trace(prop, trace_id="trace-1", status=ProposalStatus.AWAITING_EXTERNAL_AUTHORIZATION, created_at=created_at)
    auth = signer.issue(
        trace,
        prop,
        decision=decision,
        determination_id=determination_id,
        nonce=nonce,
        issued_at=created_at,
        expires_at=expires_at,
    )
    return signer, clock, eng, prop, trace, auth


def organ(name: str = "search", content: bytes = b"print('organ')\n", use_category: str = "low") -> OrganArtifact:
    return OrganArtifact.create(name, content, use_category)
