from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
import time
import unicodedata
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

TRACE_SCHEMA = "living-scs/consolidation-trace/v0.3"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
TRACE_PREDICATE_TYPE = "https://soulshine.example/schemas/consolidation-trace/v0.3"
POLICY_VERSION = "LIVING-SCS-POLICY-V1.1"


class Refusal(PermissionError):
    """Default-deny refusal raised by the validation/authorization/commit boundary."""


class TraceError(ValueError):
    """Structural or semantic trace validation failure."""


class Decision(str, Enum):
    AUTHORIZE = "authorize"
    REFUSE = "refuse"
    FLAG = "flag"


class ProposalStatus(str, Enum):
    PROPOSED = "proposed"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    UNCERTAINTY_BASIN = "uncertainty_basin"
    EVIDENCE_ELIGIBLE = "evidence_eligible"
    AWAITING_EXTERNAL_AUTHORIZATION = "awaiting_external_authorization"
    AUTHORIZED = "authorized"
    REFUSED = "refused"
    COMMITTED = "committed"


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    raw = value if isinstance(value, (bytes, bytearray)) else canonical_json(value)
    return hashlib.sha256(bytes(raw)).hexdigest()


def is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    source_uri: str
    observed_at: int
    detector: str
    detector_version: str
    value: Any

    def digest(self) -> str:
        return sha256_hex(asdict(self))


@dataclass(frozen=True)
class Interpretation:
    method: str
    version: str
    output: Mapping[str, Any]
    confidence: float
    salience: float
    resonance: float = 0.0
    convergence: float = 0.0

    def digest(self) -> str:
        return sha256_hex(asdict(self))


@dataclass(frozen=True)
class MutationProposal:
    proposal_id: str
    organism_id: str
    predecessor_digest: str
    mutation_type: str
    mutation: Mapping[str, Any]
    evidence: tuple[EvidenceItem, ...]
    interpretation: Interpretation
    policy_version: str
    maturity_state: str
    created_at: int
    expected_result_digest: str

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "organism_id": self.organism_id,
            "predecessor_digest": self.predecessor_digest,
            "mutation_type": self.mutation_type,
            "mutation": self.mutation,
            "evidence": [asdict(e) for e in self.evidence],
            "interpretation": asdict(self.interpretation),
            "policy_version": self.policy_version,
            "maturity_state": self.maturity_state,
            "created_at": self.created_at,
            "expected_result_digest": self.expected_result_digest,
        }

    def digest(self) -> str:
        return sha256_hex(self.unsigned_body())

    def evidence_digest(self) -> str:
        return sha256_hex([e.digest() for e in self.evidence])


@dataclass(frozen=True)
class ConsolidationTrace:
    schema: str
    trace_id: str
    proposal_digest: str
    organism_id: str
    predecessor_digest: str
    resulting_digest: str
    evidence_digest: str
    evidence_ids: tuple[str, ...]
    interpretation_digest: str
    interpretation_method: str
    interpretation_version: str
    policy_version: str
    maturity_state: str
    mutation_type: str
    created_at: int
    status: ProposalStatus
    authorization_ref: Optional[str] = None
    reversal_ref: Optional[str] = None
    compensation_ref: Optional[str] = None
    descendant_impact_ref: Optional[str] = None

    def body(self) -> dict[str, Any]:
        body = asdict(self)
        body["status"] = self.status.value
        return body

    def digest(self) -> str:
        return sha256_hex(self.body())


@dataclass(frozen=True)
class AuthorizationEnvelope:
    schema: str
    determination_id: str
    authority_id: str
    decision: Decision
    organism_id: str
    trace_digest: str
    proposal_digest: str
    predecessor_digest: str
    resulting_digest: str
    policy_version: str
    maturity_state: str
    mutation_type: str
    nonce: str
    issued_at: int
    expires_at: int
    scope: str
    signature: str

    def signed_body(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "determination_id": self.determination_id,
            "authority_id": self.authority_id,
            "decision": self.decision.value,
            "organism_id": self.organism_id,
            "trace_digest": self.trace_digest,
            "proposal_digest": self.proposal_digest,
            "predecessor_digest": self.predecessor_digest,
            "resulting_digest": self.resulting_digest,
            "policy_version": self.policy_version,
            "maturity_state": self.maturity_state,
            "mutation_type": self.mutation_type,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class CommitRecord:
    sequence: int
    event: str
    trace_digest: str
    proposal_digest: str
    predecessor_digest: str
    resulting_digest: str
    authorization_id: str
    authority_id: str
    reason: str
    timestamp: int
    previous_record_hash: str
    record_hash: str


@dataclass(frozen=True)
class OrganArtifact:
    name: str
    content: bytes
    use_category: str
    declared_digest: str
    source_uri: str = "marketplace://local"

    @classmethod
    def create(cls, name: str, content: bytes, use_category: str, source_uri: str = "marketplace://local") -> "OrganArtifact":
        if type(content) is not bytes:
            raise TypeError("artifact content must be plain bytes")
        return cls(name, content, use_category, hashlib.sha256(content).hexdigest(), source_uri)

    def verify(self) -> bool:
        try:
            _artifact_snapshot(self)
        except Refusal:
            return False
        return True


def _artifact_snapshot(artifact: Any) -> OrganArtifact:
    """Capture validated immutable data without invoking supplied conversion or verification."""
    if not isinstance(artifact, OrganArtifact):
        raise Refusal("organ import requires verified artifact bytes")
    content = artifact.content
    if type(content) is not bytes or not content:
        raise Refusal("organ import requires verified artifact bytes")
    computed_digest = hashlib.sha256(content).hexdigest()
    name = artifact.name
    use_category = artifact.use_category
    declared_digest = artifact.declared_digest
    source_uri = artifact.source_uri
    if any(type(value) is not str or not value for value in (name, use_category, declared_digest, source_uri)):
        raise Refusal("artifact metadata must contain non-empty plain strings")
    if declared_digest != computed_digest:
        raise Refusal("organ import requires verified artifact bytes; declared digest does not match content")
    return OrganArtifact(name, content, use_category, computed_digest, source_uri)


class TraceValidator:
    REQUIRED_MATURITIES = {"juvenile", "adolescent", "mature"}

    @classmethod
    def validate_proposal(cls, proposal: MutationProposal) -> None:
        if not proposal.proposal_id or not proposal.organism_id:
            raise TraceError("missing proposal or organism identifier")
        if not is_sha256(proposal.predecessor_digest) or not is_sha256(proposal.expected_result_digest):
            raise TraceError("invalid predecessor/result digest")
        if not proposal.mutation_type or not proposal.mutation:
            raise TraceError("missing mutation")
        if proposal.policy_version != POLICY_VERSION:
            raise TraceError("unsupported policy version")
        if proposal.maturity_state not in cls.REQUIRED_MATURITIES:
            raise TraceError("invalid maturity state")
        if not proposal.evidence:
            raise TraceError("empty evidence set")
        ids: set[str] = set()
        for item in proposal.evidence:
            if not item.evidence_id or item.evidence_id in ids:
                raise TraceError("duplicate or missing evidence identifier")
            ids.add(item.evidence_id)
            if not item.source_uri or "://" not in item.source_uri:
                raise TraceError("evidence is not externally addressable")
            if item.detector in {"model_narrative", "self_report", "freeform_narration"}:
                raise TraceError("model narration cannot create evidence")
            if not item.detector or not item.detector_version:
                raise TraceError("undeclared evidence detector")
        interp = proposal.interpretation
        for name, value in {
            "confidence": interp.confidence,
            "salience": interp.salience,
            "resonance": interp.resonance,
            "convergence": interp.convergence,
        }.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
                raise TraceError(f"{name} outside [0,1]")
        if not interp.method or not interp.version:
            raise TraceError("undeclared interpretation method/version")

    @classmethod
    def validate_trace(cls, trace: ConsolidationTrace, proposal: MutationProposal) -> None:
        cls.validate_proposal(proposal)
        if trace.schema != TRACE_SCHEMA:
            raise TraceError("unsupported trace schema")
        if not trace.trace_id:
            raise TraceError("missing trace identifier")
        if trace.proposal_digest != proposal.digest():
            raise TraceError("trace/proposal mismatch")
        if trace.organism_id != proposal.organism_id:
            raise TraceError("organism mismatch")
        if trace.predecessor_digest != proposal.predecessor_digest:
            raise TraceError("predecessor mismatch")
        if trace.resulting_digest != proposal.expected_result_digest:
            raise TraceError("result digest mismatch")
        if trace.evidence_digest != proposal.evidence_digest():
            raise TraceError("evidence digest mismatch")
        if tuple(trace.evidence_ids) != tuple(e.evidence_id for e in proposal.evidence):
            raise TraceError("evidence list mismatch")
        if trace.interpretation_digest != proposal.interpretation.digest():
            raise TraceError("interpretation digest mismatch")
        if (trace.interpretation_method, trace.interpretation_version) != (proposal.interpretation.method, proposal.interpretation.version):
            raise TraceError("interpreter identity mismatch")
        if trace.policy_version != proposal.policy_version or trace.maturity_state != proposal.maturity_state:
            raise TraceError("policy or maturity mismatch")
        if trace.mutation_type != proposal.mutation_type:
            raise TraceError("mutation type mismatch")
        if trace.created_at < proposal.created_at:
            raise TraceError("trace predates proposal")


def make_trace(proposal: MutationProposal, *, trace_id: str, status: ProposalStatus = ProposalStatus.AWAITING_EXTERNAL_AUTHORIZATION, created_at: Optional[int] = None) -> ConsolidationTrace:
    TraceValidator.validate_proposal(proposal)
    trace = ConsolidationTrace(
        schema=TRACE_SCHEMA,
        trace_id=trace_id,
        proposal_digest=proposal.digest(),
        organism_id=proposal.organism_id,
        predecessor_digest=proposal.predecessor_digest,
        resulting_digest=proposal.expected_result_digest,
        evidence_digest=proposal.evidence_digest(),
        evidence_ids=tuple(e.evidence_id for e in proposal.evidence),
        interpretation_digest=proposal.interpretation.digest(),
        interpretation_method=proposal.interpretation.method,
        interpretation_version=proposal.interpretation.version,
        policy_version=proposal.policy_version,
        maturity_state=proposal.maturity_state,
        mutation_type=proposal.mutation_type,
        created_at=proposal.created_at if created_at is None else int(created_at),
        status=status,
    )
    TraceValidator.validate_trace(trace, proposal)
    return trace


class MinatoAuthority:
    """Test/reference external signer. Production key custody remains outside the organism."""

    def __init__(self, authority_id: str, private_key: Optional[Ed25519PrivateKey] = None):
        self.authority_id = authority_id
        self._private_key = private_key
        self.public_key = private_key.public_key() if private_key else None

    @classmethod
    def verifier_only(cls, authority_id: str, public_key: Ed25519PublicKey) -> "MinatoAuthority":
        obj = cls(authority_id, None)
        obj.public_key = public_key
        return obj

    def issue(
        self,
        trace: ConsolidationTrace,
        proposal: MutationProposal,
        *,
        decision: Decision,
        determination_id: str,
        nonce: str,
        issued_at: int,
        expires_at: int,
        scope: str = "organism",
    ) -> AuthorizationEnvelope:
        if self._private_key is None:
            raise Refusal("verifier-only boundary cannot sign")
        unsigned = AuthorizationEnvelope(
            schema="minato/transition/v1",
            determination_id=determination_id,
            authority_id=self.authority_id,
            decision=decision,
            organism_id=proposal.organism_id,
            trace_digest=trace.digest(),
            proposal_digest=proposal.digest(),
            predecessor_digest=proposal.predecessor_digest,
            resulting_digest=proposal.expected_result_digest,
            policy_version=proposal.policy_version,
            maturity_state=proposal.maturity_state,
            mutation_type=proposal.mutation_type,
            nonce=nonce,
            issued_at=int(issued_at),
            expires_at=int(expires_at),
            scope=scope,
            signature="",
        )
        signature = self._private_key.sign(canonical_json(unsigned.signed_body())).hex()
        return replace(unsigned, signature=signature)

    def verify(self, envelope: AuthorizationEnvelope) -> bool:
        if self.public_key is None:
            return False
        try:
            self.public_key.verify(bytes.fromhex(envelope.signature), canonical_json(envelope.signed_body()))
            return True
        except (ValueError, InvalidSignature):
            return False

    def public_key_bytes(self) -> bytes:
        if self.public_key is None:
            raise ValueError("no public key")
        return self.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class TrustedClock:
    """Reference non-decreasing clock boundary; production should use an external trusted source."""

    def __init__(self, initial: int):
        self._value = int(initial)
        self._last_read = int(initial)
        self._lock = threading.Lock()

    def set(self, value: int) -> None:
        with self._lock:
            self._value = int(value)

    def now(self) -> int:
        with self._lock:
            if self._value < self._last_read:
                raise Refusal("trusted clock rollback detected")
            self._last_read = self._value
            return self._value


class OrganImportPolicy:
    MATURITY_ORDER = {"juvenile": 0, "adolescent": 1, "mature": 2}

    @classmethod
    def classify(cls, maturity: str, use_category: str) -> str:
        if maturity not in cls.MATURITY_ORDER:
            raise ValueError("unknown maturity")
        if use_category not in {"low", "medium", "high"}:
            raise ValueError("unknown use category")
        return "hard_gate" if maturity == "juvenile" or use_category == "high" else "through_gate"

    @classmethod
    def eligible_use(cls, maturity: str, use_category: str) -> bool:
        try:
            cls.classify(maturity, use_category)
        except (TypeError, ValueError):
            return False
        return not (maturity == "juvenile" and use_category == "high")

    @classmethod
    def eligible(cls, maturity: str, organ: OrganArtifact) -> bool:
        try:
            checked = _artifact_snapshot(organ)
        except Refusal:
            return False
        return cls.eligible_use(maturity, checked.use_category)


class UncertaintyBasin:
    """Evidence accumulator. It can yield eligibility, never authorization."""

    def __init__(self, eligibility_threshold: float = 0.80, decay: float = 0.98):
        self.threshold = float(eligibility_threshold)
        self.decay = float(decay)
        self._entries: dict[str, dict[str, Any]] = {}

    def add(self, proposal_id: str, support: float, *, contradiction: float = 0.0) -> ProposalStatus:
        if not 0 <= support <= 1 or not 0 <= contradiction <= 1:
            raise ValueError("support/contradiction outside [0,1]")
        entry = self._entries.setdefault(proposal_id, {"score": 0.0, "count": 0})
        entry["score"] = max(0.0, min(1.0, entry["score"] * self.decay + support * (1.0 - contradiction) * 0.25 - contradiction * 0.20))
        entry["count"] += 1
        return ProposalStatus.EVIDENCE_ELIGIBLE if entry["score"] >= self.threshold else ProposalStatus.UNCERTAINTY_BASIN

    def decay_once(self, proposal_id: str) -> ProposalStatus:
        entry = self._entries[proposal_id]
        entry["score"] *= self.decay
        return ProposalStatus.EVIDENCE_ELIGIBLE if entry["score"] >= self.threshold else ProposalStatus.UNCERTAINTY_BASIN

    def score(self, proposal_id: str) -> float:
        return float(self._entries.get(proposal_id, {}).get("score", 0.0))

    def count(self, proposal_id: str) -> int:
        return int(self._entries.get(proposal_id, {}).get("count", 0))


class CommitEngine:
    """Atomic, default-deny state transition engine with append-only hash-chained records."""

    def __init__(
        self,
        organism_id: str,
        initial_state: Mapping[str, Any],
        authority: MinatoAuthority,
        clock: TrustedClock,
        *,
        expected_authority_id: str,
        expected_public_key: bytes,
        persist_hook: Optional[Callable[[CommitRecord, Mapping[str, Any]], None]] = None,
    ):
        if not isinstance(expected_authority_id, str) or not expected_authority_id:
            raise Refusal("expected authority identity is required")
        if not isinstance(expected_public_key, bytes) or len(expected_public_key) != 32:
            raise Refusal("expected Ed25519 public key must be 32 bytes")
        if not isinstance(authority, MinatoAuthority) or authority.authority_id != expected_authority_id:
            raise Refusal("authority identity does not match the configured pin")
        try:
            supplied_public_key = authority.public_key_bytes()
        except (TypeError, ValueError) as exc:
            raise Refusal("authority has no usable public key") from exc
        if supplied_public_key != expected_public_key:
            raise Refusal("authority public key does not match the configured pin")
        self.organism_id = organism_id
        self._state = copy.deepcopy(dict(initial_state))
        # Build a verifier from trusted configuration, not injected verification code.
        self._authority = MinatoAuthority.verifier_only(
            expected_authority_id, Ed25519PublicKey.from_public_bytes(expected_public_key)
        )
        self._clock = clock
        self._persist_hook = persist_hook
        self._records: list[CommitRecord] = []
        self._initial_state_digest = self.state_digest
        self._states: dict[str, dict[str, Any]] = {self._initial_state_digest: copy.deepcopy(self._state)}
        self._parents: dict[str, str] = {}
        self._used_nonces: set[str] = set()
        self._used_determinations: set[str] = set()
        self._lock = threading.RLock()

    @property
    def state(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._state)

    @property
    def state_digest(self) -> str:
        return sha256_hex(self._state)

    @property
    def records(self) -> tuple[CommitRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def state_at(self, digest: str) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self._states[digest])

    def history_snapshot(self, *, state_digest: Optional[str] = None, sequence: Optional[int] = None) -> tuple[str, dict[str, Any], tuple[CommitRecord, ...]]:
        """Return one consistent history cut; a digest alone selects its latest occurrence."""
        with self._lock:
            if not self.verify_history():
                raise Refusal("history integrity failure")
            records = tuple(self._records)
            if sequence is None:
                if state_digest is None:
                    sequence = len(records)
                else:
                    sequence = next(
                        (record.sequence for record in reversed(records) if record.resulting_digest == state_digest),
                        0 if state_digest == self._initial_state_digest else None,
                    )
                    if sequence is None:
                        raise KeyError(state_digest)
            if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= len(records):
                raise ValueError("snapshot sequence must be an existing non-negative integer")
            digest = self._initial_state_digest if sequence == 0 else records[sequence - 1].resulting_digest
            if state_digest is not None and digest != state_digest:
                raise ValueError("snapshot sequence and state digest do not match")
            return digest, copy.deepcopy(self._states[digest]), records[:sequence]

    @staticmethod
    def apply_mutation(state: Mapping[str, Any], mutation: Mapping[str, Any]) -> dict[str, Any]:
        out = copy.deepcopy(dict(state))
        op = mutation.get("op")
        if op == "set":
            path = list(mutation.get("path", []))
            if not path:
                raise TraceError("empty set path")
            cursor: dict[str, Any] = out
            for key in path[:-1]:
                if key not in cursor or not isinstance(cursor[key], dict):
                    cursor[key] = {}
                cursor = cursor[key]
            cursor[path[-1]] = copy.deepcopy(mutation.get("value"))
        elif op == "install_organ":
            name = mutation.get("name")
            digest = mutation.get("digest")
            if not name or not is_sha256(digest):
                raise TraceError("invalid organ mutation")
            out.setdefault("organs", {})[name] = {
                "digest": digest,
                "use_category": mutation.get("use_category"),
                "source_uri": mutation.get("source_uri"),
            }
        elif op == "remove_organ":
            out.setdefault("organs", {}).pop(mutation.get("name"), None)
        elif op == "set_maturity":
            value = mutation.get("value")
            if value not in {"juvenile", "adolescent", "mature"}:
                raise TraceError("invalid maturity mutation")
            out["maturity"] = value
        elif op == "restore_state":
            snapshot = mutation.get("snapshot")
            if not isinstance(snapshot, dict):
                raise TraceError("invalid restore snapshot")
            out = copy.deepcopy(snapshot)
        else:
            raise TraceError("unknown mutation operation")
        return out

    def expected_digest(self, mutation: Mapping[str, Any]) -> str:
        return sha256_hex(self.apply_mutation(self._state, mutation))

    def _validate_binding(self, proposal: MutationProposal, trace: ConsolidationTrace, auth: AuthorizationEnvelope) -> None:
        TraceValidator.validate_trace(trace, proposal)
        if trace.status not in {ProposalStatus.AWAITING_EXTERNAL_AUTHORIZATION, ProposalStatus.AUTHORIZED}:
            raise Refusal("trace is not at the external authorization boundary")
        if not self._authority.verify(auth):
            raise Refusal("invalid authorization signature")
        if auth.decision is not Decision.AUTHORIZE:
            raise Refusal("external authority did not authorize")
        expected = {
            "organism_id": proposal.organism_id,
            "trace_digest": trace.digest(),
            "proposal_digest": proposal.digest(),
            "predecessor_digest": proposal.predecessor_digest,
            "resulting_digest": proposal.expected_result_digest,
            "policy_version": proposal.policy_version,
            "maturity_state": proposal.maturity_state,
            "mutation_type": proposal.mutation_type,
        }
        for name, value in expected.items():
            if getattr(auth, name) != value:
                raise Refusal(f"authorization not bound to {name}")
        if auth.scope != "organism":
            raise Refusal("wrong authorization scope")
        if auth.authority_id != self._authority.authority_id:
            raise Refusal("unknown authority")
        if proposal.organism_id != self.organism_id:
            raise Refusal("cross-organism proposal")

    KNOWN_STATE_ROOTS = frozenset({"maturity", "personality", "organs", "policy"})
    PROTECTED_ROOTS = frozenset({"organs", "maturity"})
    ALLOWED_SET_ROOT = "personality"

    @staticmethod
    def _fold_name(name: Any) -> str:
        if not isinstance(name, str):
            return ""
        return unicodedata.normalize("NFKC", name).casefold()

    def _contains_protected_name(self, value: Any) -> bool:
        if isinstance(value, Mapping):
            for key, inner in value.items():
                if self._fold_name(key) in self.PROTECTED_ROOTS:
                    return True
                if self._contains_protected_name(inner):
                    return True
        elif isinstance(value, (list, tuple)):
            return any(self._contains_protected_name(item) for item in value)
        return False

    def _validate_state_shape(self, state: Mapping[str, Any]) -> None:
        if not isinstance(state, Mapping):
            raise Refusal("resulting state is malformed")
        for key in state:
            if key not in self.KNOWN_STATE_ROOTS:
                raise Refusal("resulting state contains unsupported fields")
            if self._fold_name(key) in self.PROTECTED_ROOTS and key not in self.PROTECTED_ROOTS:
                raise Refusal("resulting state contains protected field alias")
        personality = state.get("personality", {})
        if not isinstance(personality, dict):
            raise Refusal("personality is malformed")
        if self._contains_protected_name(personality):
            raise Refusal("personality cannot shadow protected inventory fields")

    def _validate_set_path(self, mutation: Mapping[str, Any]) -> None:
        path = list(mutation.get("path") or [])
        if not path or not isinstance(path[0], str):
            raise Refusal("protected state requires its dedicated mutation operation")
        root = path[0]
        folded_root = self._fold_name(root)
        if folded_root in self.PROTECTED_ROOTS:
            raise Refusal("protected state requires its dedicated mutation operation")
        if root != self.ALLOWED_SET_ROOT or folded_root != self.ALLOWED_SET_ROOT:
            raise Refusal("generic set is limited to personality fields; undeclared or protected root")
        for segment in path[1:]:
            if self._fold_name(segment) in self.PROTECTED_ROOTS:
                raise Refusal("personality cannot shadow protected inventory fields")
        if self._contains_protected_name(mutation.get("value")):
            raise Refusal("personality cannot shadow protected inventory fields")

    def _validate_mutation_policy(self, proposal: MutationProposal, new_state: Mapping[str, Any], artifact: Optional[OrganArtifact]) -> None:
        maturity = self._state.get("maturity")
        if proposal.maturity_state != maturity:
            raise Refusal("proposal maturity does not match the current state")
        operation = proposal.mutation.get("op")
        if operation == "set":
            self._validate_set_path(proposal.mutation)
        if operation == "restore_state" and sha256_hex(new_state) not in self._states:
            raise Refusal("restore requires a known historical snapshot")
        if operation == "install_organ":
            checked = _artifact_snapshot(artifact)
            if checked.declared_digest != proposal.mutation.get("digest"):
                raise Refusal("organ import requires verified artifact bytes; artifact bytes do not match the signed digest")
            expected_artifact = {
                "name": checked.name,
                "digest": checked.declared_digest,
                "use_category": checked.use_category,
                "source_uri": checked.source_uri,
            }
            if any(proposal.mutation.get(key) != value for key, value in expected_artifact.items()):
                raise Refusal("artifact does not match the signed import metadata")
            if not OrganImportPolicy.eligible_use(maturity, checked.use_category):
                raise Refusal("organ import is ineligible under the current maturity policy")
        resulting_maturity = new_state.get("maturity")
        if resulting_maturity not in TraceValidator.REQUIRED_MATURITIES:
            raise Refusal("resulting state has an invalid maturity")
        organs = new_state.get("organs", {})
        if not isinstance(organs, dict):
            raise Refusal("resulting organ inventory is malformed")
        for name, metadata in organs.items():
            if not isinstance(name, str) or not name or not isinstance(metadata, dict):
                raise Refusal("resulting organ metadata is malformed")
            if not is_sha256(metadata.get("digest")) or not isinstance(metadata.get("source_uri"), str) or not metadata["source_uri"]:
                raise Refusal("resulting organ metadata is malformed")
            if not OrganImportPolicy.eligible_use(resulting_maturity, metadata.get("use_category")):
                raise Refusal("resulting organ inventory is ineligible under the maturity policy")

        self._validate_state_shape(new_state)

    def commit(self, proposal: MutationProposal, trace: Optional[ConsolidationTrace], auth: Optional[AuthorizationEnvelope], *, reason: str = "authorized mutation", artifact: Optional[OrganArtifact] = None) -> str:
        if trace is None:
            raise Refusal("no trace, no drift")
        if auth is None:
            raise Refusal("external authorization required")
        with self._lock:
            if not self.verify_history():
                raise Refusal("history integrity failure")
            self._validate_binding(proposal, trace, auth)
            now = self._clock.now()
            if auth.issued_at > now + 30:
                raise Refusal("authorization issued in the future")
            if auth.expires_at < now:
                raise Refusal("authorization expired")
            if auth.nonce in self._used_nonces or auth.determination_id in self._used_determinations:
                raise Refusal("authorization replay")
            current = self.state_digest
            if proposal.predecessor_digest != current:
                raise Refusal("stale predecessor or fork")
            new_state = self.apply_mutation(self._state, proposal.mutation)
            resulting = sha256_hex(new_state)
            if resulting != proposal.expected_result_digest or resulting != trace.resulting_digest:
                raise Refusal("result digest mismatch")
            self._validate_mutation_policy(proposal, new_state, artifact)
            previous_hash = self._records[-1].record_hash if self._records else "0" * 64
            event = {
                "sequence": len(self._records) + 1,
                "event": "mutation_committed",
                "trace_digest": trace.digest(),
                "proposal_digest": proposal.digest(),
                "predecessor_digest": current,
                "resulting_digest": resulting,
                "authorization_id": auth.determination_id,
                "authority_id": auth.authority_id,
                "reason": reason,
                "timestamp": now,
                "previous_record_hash": previous_hash,
            }
            record = CommitRecord(**event, record_hash=sha256_hex(event))
            # Durable-write hook executes before any in-memory authority consumption.
            if self._persist_hook is not None:
                self._persist_hook(record, copy.deepcopy(new_state))
            self._state = new_state
            self._records.append(record)
            self._states[resulting] = copy.deepcopy(new_state)
            self._parents.setdefault(resulting, current)
            self._used_nonces.add(auth.nonce)
            self._used_determinations.add(auth.determination_id)
            return resulting

    def verify_history(self) -> bool:
        previous = "0" * 64
        for index, record in enumerate(self._records, start=1):
            if record.sequence != index or record.previous_record_hash != previous:
                return False
            body = asdict(record)
            claimed = body.pop("record_hash")
            if sha256_hex(body) != claimed:
                return False
            previous = record.record_hash
        return True

    def descendants_of(self, ancestor_digest: str) -> tuple[str, ...]:
        reachable = {ancestor_digest}
        descendants: set[str] = set()
        for record in self._records:
            if record.predecessor_digest in reachable:
                reachable.add(record.resulting_digest)
                if record.resulting_digest != ancestor_digest:
                    descendants.add(record.resulting_digest)
        return tuple(sorted(descendants))

    def can_exact_rollback(self, target_digest: str) -> bool:
        return bool(self._records and self._records[-1].predecessor_digest == target_digest)

    def proposal_for_mutation(
        self,
        *,
        proposal_id: str,
        mutation_type: str,
        mutation: Mapping[str, Any],
        evidence: Iterable[EvidenceItem],
        interpretation: Interpretation,
        maturity_state: Optional[str] = None,
        created_at: Optional[int] = None,
    ) -> MutationProposal:
        now = self._clock.now() if created_at is None else int(created_at)
        expected = sha256_hex(self.apply_mutation(self._state, mutation))
        return MutationProposal(
            proposal_id=proposal_id,
            organism_id=self.organism_id,
            predecessor_digest=self.state_digest,
            mutation_type=mutation_type,
            mutation=copy.deepcopy(dict(mutation)),
            evidence=tuple(evidence),
            interpretation=interpretation,
            policy_version=POLICY_VERSION,
            maturity_state=maturity_state or str(self._state.get("maturity", "juvenile")),
            created_at=now,
            expected_result_digest=expected,
        )


def to_intoto_statement(trace: ConsolidationTrace, proposal: MutationProposal, authorization: Optional[AuthorizationEnvelope] = None) -> dict[str, Any]:
    TraceValidator.validate_trace(trace, proposal)
    predicate = {
        "trace": trace.body(),
        "predecessorDigest": proposal.predecessor_digest,
        "evidence": [asdict(e) for e in proposal.evidence],
        "interpretation": asdict(proposal.interpretation),
        "policyVersion": proposal.policy_version,
        "maturityState": proposal.maturity_state,
        "mutation": proposal.mutation,
        "authorization": authorization.signed_body() if authorization else None,
    }
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [{"name": f"genome:{proposal.organism_id}", "digest": {"sha256": proposal.expected_result_digest}}],
        "predicateType": TRACE_PREDICATE_TYPE,
        "predicate": predicate,
    }


def living_ai_bom(engine: CommitEngine, *, state_digest: Optional[str] = None, sequence: Optional[int] = None) -> dict[str, Any]:
    digest, state, records = engine.history_snapshot(state_digest=state_digest, sequence=sequence)
    components = []
    for name, organ in sorted(state.get("organs", {}).items()):
        components.append({
            "type": "ai-capability-organ",
            "name": name,
            "digest": {"sha256": organ["digest"]},
            "useCategory": organ.get("use_category"),
            "source": organ.get("source_uri"),
        })
    mutation_history = []
    for record in records:
        mutation_history.append({
            "sequence": record.sequence,
            "predecessorDigest": record.predecessor_digest,
            "resultingDigest": record.resulting_digest,
            "authorizationId": record.authorization_id,
            "authorityId": record.authority_id,
            "reason": record.reason,
            "recordHash": record.record_hash,
        })
    return {
        "bomFormat": "Living-AI-BOM",
        "specVersion": "0.2",
        "organismId": engine.organism_id,
        "genomeDigest": digest,
        "snapshotSequence": len(records),
        "maturityState": state.get("maturity"),
        "components": components,
        "persistentBehavior": copy.deepcopy(state.get("personality", {})),
        "mutationHistory": mutation_history,
    }


def deterministic_test_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
