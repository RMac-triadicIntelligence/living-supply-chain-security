import unittest
from dataclasses import replace

from living_scs.core import Decision, OrganImportPolicy, Refusal, TraceError, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, organ


class OrganImportPolicyTests(unittest.TestCase):
    def test_juvenile_high_use_is_ineligible(self):
        artifact = organ(use_category="high")
        self.assertEqual(OrganImportPolicy.classify("juvenile", "high"), "hard_gate")
        self.assertFalse(OrganImportPolicy.eligible("juvenile", artifact))

    def test_juvenile_low_use_still_hits_hard_gate(self):
        self.assertEqual(OrganImportPolicy.classify("juvenile", "low"), "hard_gate")

    def test_mature_low_use_reaches_through_gate(self):
        artifact = organ(use_category="low")
        self.assertEqual(OrganImportPolicy.classify("mature", "low"), "through_gate")
        self.assertTrue(OrganImportPolicy.eligible("mature", artifact))

    def test_mature_high_use_remains_hard_gated(self):
        self.assertEqual(OrganImportPolicy.classify("mature", "high"), "hard_gate")

    def test_missing_organ_content_fails_dna_filter(self):
        artifact = organ(content=b"")
        self.assertFalse(artifact.verify())

    def test_replaced_organ_bytes_fail_dna_filter(self):
        artifact = organ(content=b"version-one")
        replaced = replace(artifact, content=b"version-two")
        self.assertFalse(replaced.verify())

    def test_authorization_for_one_organ_cannot_import_another(self):
        signer, clock, eng = engine(maturity="mature")
        first = organ(name="search", content=b"search-v1")
        mutation1 = {"op": "install_organ", "name": first.name, "digest": first.declared_digest, "use_category": first.use_category, "source_uri": first.source_uri}
        prop1 = eng.proposal_for_mutation(proposal_id="organ-p1", mutation_type="organ_import", mutation=mutation1, evidence=evidence(), interpretation=interpretation(), maturity_state="mature", created_at=NOW)
        trace1 = make_trace(prop1, trace_id="organ-t1")
        auth1 = signer.issue(trace1, prop1, decision=Decision.AUTHORIZE, determination_id="organ-d1", nonce="organ-n1", issued_at=NOW, expires_at=NOW + 60)

        second = organ(name="browser", content=b"browser-v1")
        mutation2 = {"op": "install_organ", "name": second.name, "digest": second.declared_digest, "use_category": second.use_category, "source_uri": second.source_uri}
        prop2 = eng.proposal_for_mutation(proposal_id="organ-p2", mutation_type="organ_import", mutation=mutation2, evidence=evidence(), interpretation=interpretation(), maturity_state="mature", created_at=NOW)
        trace2 = make_trace(prop2, trace_id="organ-t2")
        with self.assertRaises(Refusal):
            eng.commit(prop2, trace2, auth1, artifact=second)

    def test_valid_mature_import_still_requires_and_accepts_exact_authorization(self):
        signer, clock, eng = engine(maturity="mature")
        artifact = organ(name="search", content=b"search-v1")
        self.assertTrue(OrganImportPolicy.eligible("mature", artifact))
        mutation = {"op": "install_organ", "name": artifact.name, "digest": artifact.declared_digest, "use_category": artifact.use_category, "source_uri": artifact.source_uri}
        prop = eng.proposal_for_mutation(proposal_id="organ-p", mutation_type="organ_import", mutation=mutation, evidence=evidence(), interpretation=interpretation(), maturity_state="mature", created_at=NOW)
        trace = make_trace(prop, trace_id="organ-t")
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None, artifact=artifact)
        auth = signer.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id="organ-d", nonce="organ-n", issued_at=NOW, expires_at=NOW + 60)
        eng.commit(prop, trace, auth, artifact=artifact)
        self.assertIn("search", eng.state["organs"])


if __name__ == "__main__":
    unittest.main()
