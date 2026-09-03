"""Regressions for the v1.1.1 review findings."""
from __future__ import annotations

import unittest
from dataclasses import dataclass

from living_scs.core import Decision, OrganArtifact, Refusal, living_ai_bom, make_trace, sha256_hex
from living_scs.fixtures import NOW, engine, evidence, interpretation, organ


def signed(signer, eng, payload, tag, maturity=None):
    prop = eng.proposal_for_mutation(
        proposal_id=f"{tag}-p", mutation_type="review_gap", mutation=payload,
        evidence=evidence(), interpretation=interpretation(),
        maturity_state=maturity, created_at=NOW,
    )
    trace = make_trace(prop, trace_id=f"{tag}-t")
    auth = signer.issue(
        trace, prop, decision=Decision.AUTHORIZE,
        determination_id=f"{tag}-d", nonce=f"{tag}-n",
        issued_at=NOW, expires_at=NOW + 60,
    )
    return prop, trace, auth


@dataclass(frozen=True)
class LyingArtifact(OrganArtifact):
    def verify(self) -> bool:
        return True


class ReviewGapTests(unittest.TestCase):
    def test_overridden_verify_cannot_substitute_bytes(self):
        signer, _, eng = engine(maturity="mature")
        approved = organ(name="search", content=b"approved-bytes", use_category="low")
        payload = {
            "op": "install_organ",
            "name": approved.name,
            "digest": approved.declared_digest,
            "use_category": approved.use_category,
            "source_uri": approved.source_uri,
        }
        prop, trace, auth = signed(signer, eng, payload, "swap", maturity="mature")
        lying = LyingArtifact(
            name=approved.name,
            content=b"substituted-bytes",
            use_category=approved.use_category,
            declared_digest=approved.declared_digest,
            source_uri=approved.source_uri,
        )
        self.assertTrue(lying.verify())
        self.assertNotEqual(sha256_hex(lying.content), approved.declared_digest)
        with self.assertRaisesRegex(Refusal, "digest|bytes"):
            eng.commit(prop, trace, auth, artifact=lying)
        self.assertEqual(eng.state["organs"], {})

    def test_engine_accepts_matching_bytes_without_trusting_verify(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(name="search", content=b"real-bytes", use_category="low")
        payload = {
            "op": "install_organ",
            "name": artifact.name,
            "digest": artifact.declared_digest,
            "use_category": artifact.use_category,
            "source_uri": artifact.source_uri,
        }
        prop, trace, auth = signed(signer, eng, payload, "ok-bytes", maturity="mature")
        lying_but_honest_bytes = LyingArtifact(
            name=artifact.name,
            content=artifact.content,
            use_category=artifact.use_category,
            declared_digest=artifact.declared_digest,
            source_uri=artifact.source_uri,
        )
        eng.commit(prop, trace, auth, artifact=lying_but_honest_bytes)
        self.assertEqual(eng.state["organs"]["search"]["digest"], artifact.declared_digest)

    def test_nested_personality_preferences_organs_is_refused(self):
        signer, _, eng = engine()
        payload = {
            "op": "set",
            "path": ["personality", "preferences"],
            "value": {"organs": {"ghost": {"digest": "a" * 64, "use_category": "high", "source_uri": "x://g"}}},
        }
        prop, trace, auth = signed(signer, eng, payload, "nested")
        with self.assertRaisesRegex(Refusal, "shadow"):
            eng.commit(prop, trace, auth)
        self.assertNotIn("preferences", eng.state["personality"])
        self.assertEqual(living_ai_bom(eng)["components"], [])

    def test_organs_key_inside_personality_list_is_refused(self):
        signer, _, eng = engine()
        payload = {
            "op": "set",
            "path": ["personality", "notes"],
            "value": [{"organs": {"ghost": True}}, {"ok": 1}],
        }
        prop, trace, auth = signed(signer, eng, payload, "list")
        with self.assertRaisesRegex(Refusal, "shadow"):
            eng.commit(prop, trace, auth)
        self.assertNotIn("notes", eng.state["personality"])
