import unittest

from living_scs.core import Decision, ProposalStatus, Refusal, UncertaintyBasin
from living_scs.fixtures import proposal_trace_auth


class BasinNonAuthorityTests(unittest.TestCase):
    def test_accumulation_can_reach_eligibility(self):
        basin = UncertaintyBasin()
        status = None
        for _ in range(8):
            status = basin.add("p", 1.0)
        self.assertEqual(status, ProposalStatus.EVIDENCE_ELIGIBLE)

    def test_accumulation_never_returns_authorized(self):
        basin = UncertaintyBasin()
        statuses = {basin.add("p", 1.0) for _ in range(100)}
        self.assertNotIn(ProposalStatus.AUTHORIZED, statuses)
        self.assertNotIn(ProposalStatus.COMMITTED, statuses)

    def test_infinite_evidence_never_becomes_authority(self):
        basin = UncertaintyBasin()
        for _ in range(100_000):
            basin.add("p", 1.0)
        _, _, eng, prop, trace, _ = proposal_trace_auth()
        self.assertGreaterEqual(basin.score("p"), basin.threshold)
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, None)

    def test_contradiction_holds_question_open(self):
        basin = UncertaintyBasin()
        status = None
        for _ in range(20):
            status = basin.add("p", 1.0, contradiction=1.0)
        self.assertEqual(status, ProposalStatus.UNCERTAINTY_BASIN)

    def test_decay_can_return_eligible_proposal_to_basin(self):
        basin = UncertaintyBasin(decay=0.90)
        for _ in range(8):
            basin.add("p", 1.0)
        self.assertGreaterEqual(basin.score("p"), basin.threshold)
        status = ProposalStatus.EVIDENCE_ELIGIBLE
        for _ in range(20):
            status = basin.decay_once("p")
        self.assertEqual(status, ProposalStatus.UNCERTAINTY_BASIN)

    def test_grace_enters_only_through_external_authorization(self):
        signer, clock, eng, prop, trace, _ = proposal_trace_auth()
        auth = signer.issue(
            trace, prop, decision=Decision.AUTHORIZE, determination_id="grace-1",
            nonce="grace-nonce", issued_at=clock.now(), expires_at=clock.now() + 60,
        )
        self.assertEqual(eng.commit(prop, trace, auth), prop.expected_result_digest)


if __name__ == "__main__":
    unittest.main()
