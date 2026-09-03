import copy
import unittest
from dataclasses import replace

from living_scs.core import Decision, OrganImportPolicy, Refusal, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, organ


class CommitPolicyTests(unittest.TestCase):
    def _signed(self, signer, eng, payload, *, tag="policy", maturity=None):
        proposal = eng.proposal_for_mutation(
            proposal_id=f"{tag}-p", mutation_type="policy_test", mutation=payload,
            evidence=evidence(), interpretation=interpretation(),
            maturity_state=maturity, created_at=NOW,
        )
        trace = make_trace(proposal, trace_id=f"{tag}-t")
        auth = signer.issue(
            trace, proposal, decision=Decision.AUTHORIZE,
            determination_id=f"{tag}-d", nonce=f"{tag}-n",
            issued_at=NOW, expires_at=NOW + 60,
        )
        return proposal, trace, auth

    @staticmethod
    def _import(artifact):
        return {
            "op": "install_organ", "name": artifact.name,
            "digest": artifact.declared_digest, "use_category": artifact.use_category,
            "source_uri": artifact.source_uri,
        }

    def test_juvenile_high_import_is_refused_at_commit(self):
        signer, _, eng = engine(maturity="juvenile")
        artifact = organ(use_category="high")
        signed = self._signed(signer, eng, self._import(artifact))
        before = eng.state_digest
        self.assertFalse(OrganImportPolicy.eligible("juvenile", artifact))
        with self.assertRaisesRegex(Refusal, "organ import is ineligible"):
            eng.commit(*signed, artifact=artifact)
        self.assertEqual(eng.state_digest, before)
        self.assertEqual(eng.records, ())

    def test_import_requires_artifact_bytes_at_commit(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ()
        signed = self._signed(signer, eng, self._import(artifact))
        with self.assertRaisesRegex(Refusal, "verified artifact bytes"):
            eng.commit(*signed)
        self.assertEqual(eng.records, ())
        # A refused import must leave its authorization available for a valid retry.
        eng.commit(*signed, artifact=artifact)
        self.assertIn(artifact.name, eng.state["organs"])

    def test_changed_artifact_bytes_are_refused_at_commit(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(content=b"approved bytes")
        signed = self._signed(signer, eng, self._import(artifact))
        changed = replace(artifact, content=b"substituted bytes")
        with self.assertRaisesRegex(Refusal, "verified artifact bytes"):
            eng.commit(*signed, artifact=changed)
        self.assertEqual(eng.records, ())

    def test_artifact_category_cannot_replace_signed_category(self):
        signer, _, eng = engine(maturity="juvenile")
        artifact = organ(use_category="high")
        signed = self._signed(signer, eng, self._import(artifact))
        with self.assertRaisesRegex(Refusal, "signed import metadata"):
            eng.commit(*signed, artifact=replace(artifact, use_category="low"))

    def test_artifact_name_cannot_replace_signed_name(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(name="search")
        signed = self._signed(signer, eng, self._import(artifact))
        with self.assertRaisesRegex(Refusal, "signed import metadata"):
            eng.commit(*signed, artifact=replace(artifact, name="browser"))

    def test_artifact_source_cannot_replace_signed_source(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ()
        signed = self._signed(signer, eng, self._import(artifact))
        with self.assertRaisesRegex(Refusal, "signed import metadata"):
            eng.commit(*signed, artifact=replace(artifact, source_uri="marketplace://other"))

    def test_declared_maturity_cannot_override_live_maturity(self):
        signer, _, eng = engine(maturity="juvenile")
        artifact = organ(use_category="high")
        signed = self._signed(signer, eng, self._import(artifact), maturity="mature")
        with self.assertRaisesRegex(Refusal, "maturity does not match"):
            eng.commit(*signed, artifact=artifact)

    def test_generic_set_cannot_install_an_organ(self):
        signer, _, eng = engine(maturity="juvenile")
        artifact = organ(use_category="high")
        metadata = self._import(artifact)
        metadata.pop("op")
        metadata.pop("name")
        signed = self._signed(signer, eng, {"op": "set", "path": ["organs", artifact.name], "value": metadata})
        with self.assertRaisesRegex(Refusal, "dedicated mutation operation"):
            eng.commit(*signed)
        self.assertEqual(eng.state["organs"], {})

    def test_generic_set_cannot_override_maturity(self):
        signer, _, eng = engine()
        signed = self._signed(signer, eng, {"op": "set", "path": ["maturity"], "value": "mature"})
        with self.assertRaisesRegex(Refusal, "dedicated mutation operation"):
            eng.commit(*signed)

    def test_restore_cannot_introduce_an_unknown_inventory(self):
        signer, _, eng = engine(maturity="mature")
        snapshot = copy.deepcopy(eng.state)
        artifact = organ()
        snapshot["organs"][artifact.name] = {
            "digest": artifact.declared_digest, "use_category": artifact.use_category,
            "source_uri": artifact.source_uri,
        }
        signed = self._signed(signer, eng, {"op": "restore_state", "snapshot": snapshot})
        with self.assertRaisesRegex(Refusal, "known historical snapshot"):
            eng.commit(*signed)

    def test_maturity_change_cannot_leave_ineligible_organs_installed(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(use_category="high")
        eng.commit(*self._signed(signer, eng, self._import(artifact), tag="install"), artifact=artifact)
        signed = self._signed(signer, eng, {"op": "set_maturity", "value": "juvenile"}, tag="maturity")
        with self.assertRaisesRegex(Refusal, "inventory is ineligible"):
            eng.commit(*signed)
        self.assertEqual(eng.state["maturity"], "mature")
        self.assertEqual(len(eng.records), 1)

    def test_juvenile_low_import_still_requires_authorization(self):
        signer, _, eng = engine(maturity="juvenile")
        artifact = organ(use_category="low")
        proposal, trace, auth = self._signed(signer, eng, self._import(artifact))
        with self.assertRaisesRegex(Refusal, "authorization required"):
            eng.commit(proposal, trace, None, artifact=artifact)
        eng.commit(proposal, trace, auth, artifact=artifact)
        self.assertIn(artifact.name, eng.state["organs"])

    def test_mature_high_import_accepts_exact_authorization_and_bytes(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(use_category="high")
        signed = self._signed(signer, eng, self._import(artifact))
        eng.commit(*signed, artifact=artifact)
        self.assertEqual(eng.state["organs"][artifact.name]["use_category"], "high")

    def test_unknown_use_category_is_refused_at_commit(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(use_category="unknown")
        self.assertFalse(OrganImportPolicy.eligible("mature", artifact))
        signed = self._signed(signer, eng, self._import(artifact))
        with self.assertRaisesRegex(Refusal, "organ import is ineligible"):
            eng.commit(*signed, artifact=artifact)


if __name__ == "__main__":
    unittest.main()
