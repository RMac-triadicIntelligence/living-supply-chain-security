"""Regressions for the post-v1.1.2 artifact byte-conversion review."""
import hashlib
import unittest
from dataclasses import replace

from living_scs.core import Decision, OrganArtifact, OrganImportPolicy, Refusal, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, organ


APPROVED = b"approved content"
SUBSTITUTED = b"different unapproved content"


class MisleadingBytes(bytes):
    conversions = 0

    def __bytes__(self):
        type(self).conversions += 1
        return APPROVED


class VerifyMustNotRun(OrganArtifact):
    def verify(self):
        raise AssertionError("supplied verification behavior was invoked")


class LyingArtifact(OrganArtifact):
    def verify(self):
        return True


class ArtifactSnapshotTests(unittest.TestCase):
    def setUp(self):
        MisleadingBytes.conversions = 0

    def signed_import(self):
        signer, _, eng = engine(maturity="mature")
        approved = organ(content=APPROVED)
        payload = {
            "op": "install_organ", "name": approved.name,
            "digest": approved.declared_digest, "use_category": approved.use_category,
            "source_uri": approved.source_uri,
        }
        proposal = eng.proposal_for_mutation(
            proposal_id="snapshot-p", mutation_type="organ_import", mutation=payload,
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace = make_trace(proposal, trace_id="snapshot-t")
        auth = signer.issue(
            trace, proposal, decision=Decision.AUTHORIZE,
            determination_id="snapshot-d", nonce="snapshot-n",
            issued_at=NOW, expires_at=NOW + 60,
        )
        return eng, approved, (proposal, trace, auth)

    def assert_refused_without_commit(self, eng, signed, candidate):
        before = eng.state_digest
        with self.assertRaises(Refusal):
            eng.commit(*signed, artifact=candidate)
        self.assertEqual(eng.state_digest, before)
        self.assertEqual(eng.records, ())

    def test_byte_conversion_substitution_is_refused(self):
        eng, approved, signed = self.signed_import()
        candidate = replace(approved, content=MisleadingBytes(SUBSTITUTED))
        self.assertNotEqual(hashlib.sha256(memoryview(candidate.content)).hexdigest(), approved.declared_digest)
        self.assert_refused_without_commit(eng, signed, candidate)
        self.assertEqual(MisleadingBytes.conversions, 0)
        # Refusal must leave the exact authorization available for valid bytes.
        eng.commit(*signed, artifact=approved)
        self.assertEqual(len(eng.records), 1)

    def test_matching_buffer_subclass_is_refused(self):
        eng, approved, signed = self.signed_import()
        candidate = replace(approved, content=MisleadingBytes(APPROVED))
        self.assertFalse(candidate.verify())
        self.assert_refused_without_commit(eng, signed, candidate)
        self.assertEqual(MisleadingBytes.conversions, 0)

    def test_commit_and_eligibility_do_not_call_supplied_verify(self):
        eng, approved, signed = self.signed_import()
        candidate = VerifyMustNotRun(
            approved.name, approved.content, approved.use_category,
            approved.declared_digest, approved.source_uri,
        )
        self.assertTrue(OrganImportPolicy.eligible("mature", candidate))
        eng.commit(*signed, artifact=candidate)
        self.assertEqual(len(eng.records), 1)

    def test_policy_helper_rejects_lying_artifact(self):
        _, approved, _ = self.signed_import()
        candidate = LyingArtifact(
            approved.name, SUBSTITUTED, approved.use_category,
            approved.declared_digest, approved.source_uri,
        )
        self.assertFalse(OrganImportPolicy.eligible("mature", candidate))

    def test_factory_does_not_invoke_byte_conversion(self):
        with self.assertRaises(TypeError):
            OrganArtifact.create("search", MisleadingBytes(SUBSTITUTED), "low")
        self.assertEqual(MisleadingBytes.conversions, 0)

    def test_mutable_buffers_are_refused(self):
        for content in (bytearray(APPROVED), memoryview(APPROVED)):
            eng, approved, signed = self.signed_import()
            self.assert_refused_without_commit(eng, signed, replace(approved, content=content))


if __name__ == "__main__":
    unittest.main()
