import unittest

from living_scs.core import (
    INTOTO_STATEMENT_TYPE,
    TRACE_PREDICATE_TYPE,
    Decision,
    living_ai_bom,
    make_trace,
    to_intoto_statement,
)
from living_scs.fixtures import NOW, engine, evidence, interpretation, organ, proposal_trace_auth


class InteroperabilityTests(unittest.TestCase):
    def test_intoto_statement_type_and_subject(self):
        _, _, _, prop, trace, auth = proposal_trace_auth()
        statement = to_intoto_statement(trace, prop, auth)
        self.assertEqual(statement["_type"], INTOTO_STATEMENT_TYPE)
        self.assertEqual(statement["subject"][0]["digest"]["sha256"], prop.expected_result_digest)

    def test_intoto_predicate_type_is_trace_schema(self):
        _, _, _, prop, trace, auth = proposal_trace_auth()
        statement = to_intoto_statement(trace, prop, auth)
        self.assertEqual(statement["predicateType"], TRACE_PREDICATE_TYPE)

    def test_intoto_predicate_contains_full_causal_inputs(self):
        _, _, _, prop, trace, auth = proposal_trace_auth()
        predicate = to_intoto_statement(trace, prop, auth)["predicate"]
        for key in ("predecessorDigest", "evidence", "interpretation", "policyVersion", "maturityState", "mutation", "authorization"):
            self.assertIn(key, predicate)

    def test_living_bom_reconstructs_current_organ_inventory(self):
        signer, _, eng = engine(maturity="mature")
        artifact = organ(name="search", content=b"search")
        mutation = {"op": "install_organ", "name": artifact.name, "digest": artifact.declared_digest, "use_category": artifact.use_category, "source_uri": artifact.source_uri}
        prop = eng.proposal_for_mutation(proposal_id="bom-p", mutation_type="organ_import", mutation=mutation, evidence=evidence(), interpretation=interpretation(), maturity_state="mature", created_at=NOW)
        trace = make_trace(prop, trace_id="bom-t")
        auth = signer.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id="bom-d", nonce="bom-n", issued_at=NOW, expires_at=NOW + 60)
        eng.commit(prop, trace, auth, reason="install search organ", artifact=artifact)
        bom = living_ai_bom(eng)
        self.assertEqual(bom["components"][0]["name"], "search")
        self.assertEqual(bom["components"][0]["digest"]["sha256"], artifact.declared_digest)

    def test_living_bom_records_who_and_why(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth, reason="owner-approved brevity adaptation")
        item = living_ai_bom(eng)["mutationHistory"][0]
        self.assertEqual(item["authorityId"], "owner-root-1")
        self.assertEqual(item["reason"], "owner-approved brevity adaptation")

    def test_historical_bom_snapshot_is_reconstructable(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        first = eng.commit(prop, trace, auth)
        prop2 = eng.proposal_for_mutation(proposal_id="hist-p2", mutation_type="maturity_transition", mutation={"op": "set_maturity", "value": "adolescent"}, evidence=evidence(), interpretation=interpretation(), created_at=NOW)
        trace2 = make_trace(prop2, trace_id="hist-t2")
        auth2 = signer.issue(trace2, prop2, decision=Decision.AUTHORIZE, determination_id="hist-d2", nonce="hist-n2", issued_at=NOW, expires_at=NOW + 60)
        eng.commit(prop2, trace2, auth2)
        old = living_ai_bom(eng, state_digest=first)
        current = living_ai_bom(eng)
        self.assertEqual(old["maturityState"], "juvenile")
        self.assertEqual(current["maturityState"], "adolescent")
        self.assertEqual(len(old["mutationHistory"]), 1)
        self.assertEqual(len(current["mutationHistory"]), 2)


if __name__ == "__main__":
    unittest.main()
