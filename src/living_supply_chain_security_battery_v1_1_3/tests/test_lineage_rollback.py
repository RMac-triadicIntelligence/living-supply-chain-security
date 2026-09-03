import unittest

from living_scs.core import Decision, Refusal, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation, proposal_trace_auth


class LineageRollbackTests(unittest.TestCase):
    def _commit_second(self, signer, eng, value=0.40, proposal_id="p2", trace_id="t2", det="d2", nonce="n2"):
        prop = eng.proposal_for_mutation(
            proposal_id=proposal_id, mutation_type="personality_drift", mutation=mutation(value),
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace = make_trace(prop, trace_id=trace_id)
        auth = signer.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id=det, nonce=nonce, issued_at=NOW, expires_at=NOW + 60)
        return prop, trace, auth, eng.commit(prop, trace, auth)

    def test_every_commit_names_its_predecessor(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        initial = eng.state_digest
        result = eng.commit(prop, trace, auth)
        self.assertEqual(eng.records[0].predecessor_digest, initial)
        self.assertEqual(eng.records[0].resulting_digest, result)

    def test_stale_branch_is_detected(self):
        signer, _, eng = engine()
        stale = eng.proposal_for_mutation(proposal_id="stale", mutation_type="personality_drift", mutation=mutation(0.41), evidence=evidence(), interpretation=interpretation(), created_at=NOW)
        stale_trace = make_trace(stale, trace_id="stale-t")
        stale_auth = signer.issue(stale_trace, stale, decision=Decision.AUTHORIZE, determination_id="stale-d", nonce="stale-n", issued_at=NOW, expires_at=NOW + 60)
        live = eng.proposal_for_mutation(proposal_id="live", mutation_type="personality_drift", mutation=mutation(0.45), evidence=evidence(), interpretation=interpretation(), created_at=NOW)
        live_trace = make_trace(live, trace_id="live-t")
        live_auth = signer.issue(live_trace, live, decision=Decision.AUTHORIZE, determination_id="live-d", nonce="live-n", issued_at=NOW, expires_at=NOW + 60)
        eng.commit(live, live_trace, live_auth)
        with self.assertRaisesRegex(Refusal, "stale predecessor"):
            eng.commit(stale, stale_trace, stale_auth)

    def test_exact_rollback_is_append_only(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        initial_digest = eng.state_digest
        initial_snapshot = eng.state
        eng.commit(prop, trace, auth)
        rollback = eng.proposal_for_mutation(proposal_id="rollback", mutation_type="rollback", mutation={"op": "restore_state", "snapshot": initial_snapshot}, evidence=evidence(), interpretation=interpretation(), created_at=NOW)
        rollback_trace = make_trace(rollback, trace_id="rollback-t")
        rollback_auth = signer.issue(rollback_trace, rollback, decision=Decision.AUTHORIZE, determination_id="rollback-d", nonce="rollback-n", issued_at=NOW, expires_at=NOW + 60)
        result = eng.commit(rollback, rollback_trace, rollback_auth, reason="authorized exact rollback")
        self.assertEqual(result, initial_digest)
        self.assertEqual(len(eng.records), 2)
        self.assertTrue(eng.verify_history())

    def test_exact_rollback_only_targets_direct_predecessor(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        initial = eng.state_digest
        first = eng.commit(prop, trace, auth)
        self._commit_second(signer, eng)
        self.assertFalse(eng.can_exact_rollback(initial))
        self.assertTrue(eng.can_exact_rollback(first))

    def test_compensating_transition_preserves_original_record(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        original_hash = eng.records[0].record_hash
        self._commit_second(signer, eng, value=0.50, proposal_id="comp", trace_id="comp-t", det="comp-d", nonce="comp-n")
        self.assertEqual(eng.records[0].record_hash, original_hash)
        self.assertEqual(eng.state["personality"]["verbosity"], 0.50)

    def test_descendant_impact_identifies_later_states(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        first = eng.commit(prop, trace, auth)
        _, _, _, second = self._commit_second(signer, eng)
        self.assertIn(second, eng.descendants_of(first))

    def test_history_verifies_after_multiple_authorized_transitions(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        self._commit_second(signer, eng)
        self.assertTrue(eng.verify_history())


if __name__ == "__main__":
    unittest.main()
