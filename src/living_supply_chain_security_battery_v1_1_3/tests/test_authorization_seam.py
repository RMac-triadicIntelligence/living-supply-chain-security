import unittest
from dataclasses import replace

from living_scs.core import Decision, ProposalStatus, Refusal, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation, proposal_trace_auth


class AuthorizationSeamTests(unittest.TestCase):
    def test_high_confidence_is_not_authority(self):
        _, _, eng, prop, trace, _ = proposal_trace_auth(confidence=1.0)
        with self.assertRaisesRegex(Refusal, "authorization required"):
            eng.commit(prop, trace, None)

    def test_maximum_salience_is_not_authority(self):
        _, _, eng, prop, trace, _ = proposal_trace_auth(salience=1.0)
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)

    def test_maximum_resonance_is_not_authority(self):
        signer, clock, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-res", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(), interpretation=interpretation(resonance=1.0), created_at=NOW,
        )
        trace = make_trace(prop, trace_id="t-res")
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)

    def test_maximum_convergence_is_not_authority(self):
        _, _, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-conv", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(), interpretation=interpretation(convergence=1.0), created_at=NOW,
        )
        trace = make_trace(prop, trace_id="t-conv")
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)

    def test_maturity_is_not_authority(self):
        _, _, eng, prop, trace, _ = proposal_trace_auth(maturity="mature")
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)

    def test_refusal_decision_cannot_commit(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth(decision=Decision.REFUSE)
        with self.assertRaisesRegex(Refusal, "did not authorize"):
            eng.commit(prop, trace, auth)

    def test_flag_decision_cannot_commit(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth(decision=Decision.FLAG)
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, auth)

    def test_owner_grace_must_be_sealed(self):
        _, _, eng, prop, trace, _ = proposal_trace_auth()
        trace = replace(trace, authorization_ref="owner-grace-unsealed")
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)

    def test_basin_status_cannot_commit_even_with_signature_for_other_state(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        basin_trace = replace(trace, status=ProposalStatus.UNCERTAINTY_BASIN)
        with self.assertRaisesRegex(Refusal, "not at the external authorization boundary"):
            eng.commit(prop, basin_trace, auth)

    def test_authorized_status_still_requires_signature(self):
        _, _, eng, prop, trace, _ = proposal_trace_auth()
        trace = replace(trace, status=ProposalStatus.AUTHORIZED)
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)


if __name__ == "__main__":
    unittest.main()
