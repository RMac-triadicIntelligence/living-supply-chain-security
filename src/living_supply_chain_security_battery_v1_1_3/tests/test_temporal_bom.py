import unittest
from dataclasses import replace

from living_scs.core import Decision, Refusal, living_ai_bom, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation


class TemporalBomTests(unittest.TestCase):
    def setUp(self):
        self.signer, _, self.eng = engine()
        self.initial_digest = self.eng.state_digest
        self.initial_state = self.eng.state

    def _commit(self, payload, tag):
        proposal = self.eng.proposal_for_mutation(
            proposal_id=f"{tag}-p", mutation_type="history_test", mutation=payload,
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace = make_trace(proposal, trace_id=f"{tag}-t")
        auth = self.signer.issue(
            trace, proposal, decision=Decision.AUTHORIZE,
            determination_id=f"{tag}-d", nonce=f"{tag}-n",
            issued_at=NOW, expires_at=NOW + 60,
        )
        return self.eng.commit(proposal, trace, auth)

    def _rollback_history(self):
        first = self._commit(mutation(0.45), "first")
        snapshot = self.eng.state
        self._commit(mutation(0.40), "second")
        self.assertTrue(self.eng.can_exact_rollback(first))
        self._commit({"op": "restore_state", "snapshot": snapshot}, "rollback")
        return first

    def test_initial_digest_has_empty_history_after_later_commits(self):
        self._commit(mutation(0.45), "first")
        bom = living_ai_bom(self.eng, state_digest=self.initial_digest)
        self.assertEqual(bom["mutationHistory"], [])
        self.assertEqual(bom["snapshotSequence"], 0)

    def test_current_bom_preserves_every_record_after_rollback(self):
        first = self._rollback_history()
        bom = living_ai_bom(self.eng)
        self.assertEqual(bom["genomeDigest"], first)
        self.assertEqual(bom["snapshotSequence"], 3)
        self.assertEqual([row["sequence"] for row in bom["mutationHistory"]], [1, 2, 3])
        self.assertEqual(len(self.eng.records), 3)
        self.assertTrue(self.eng.verify_history())

    def test_digest_selection_uses_latest_occurrence(self):
        first = self._rollback_history()
        bom = living_ai_bom(self.eng, state_digest=first)
        self.assertEqual(bom["snapshotSequence"], 3)
        self.assertEqual(len(bom["mutationHistory"]), 3)

    def test_sequence_distinguishes_repeated_state_digests(self):
        first = self._rollback_history()
        old = living_ai_bom(self.eng, state_digest=first, sequence=1)
        current = living_ai_bom(self.eng, state_digest=first, sequence=3)
        self.assertEqual(old["genomeDigest"], current["genomeDigest"])
        self.assertEqual(old["persistentBehavior"], current["persistentBehavior"])
        self.assertEqual(len(old["mutationHistory"]), 1)
        self.assertEqual(len(current["mutationHistory"]), 3)

    def test_genesis_sequence_remains_available_after_return_to_genesis(self):
        self._commit(mutation(0.45), "first")
        self._commit({"op": "restore_state", "snapshot": self.initial_state}, "rollback")
        genesis = living_ai_bom(self.eng, sequence=0)
        latest = living_ai_bom(self.eng, state_digest=self.initial_digest)
        self.assertEqual(genesis["genomeDigest"], latest["genomeDigest"])
        self.assertEqual(genesis["mutationHistory"], [])
        self.assertEqual(latest["snapshotSequence"], 2)

    def test_no_op_commit_is_retained_in_current_bom(self):
        self._commit(mutation(0.45), "first")
        self._commit(mutation(0.45), "same-state")
        bom = living_ai_bom(self.eng)
        self.assertEqual(len(bom["mutationHistory"]), 2)
        self.assertEqual(bom["snapshotSequence"], 2)

    def test_negative_sequence_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "snapshot sequence"):
            living_ai_bom(self.eng, sequence=-1)

    def test_future_sequence_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "snapshot sequence"):
            living_ai_bom(self.eng, sequence=1)

    def test_boolean_sequence_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "snapshot sequence"):
            living_ai_bom(self.eng, sequence=True)

    def test_mismatched_sequence_and_digest_are_rejected(self):
        first = self._commit(mutation(0.45), "first")
        with self.assertRaisesRegex(ValueError, "do not match"):
            living_ai_bom(self.eng, state_digest=first, sequence=0)

    def test_unknown_digest_is_rejected(self):
        with self.assertRaises(KeyError):
            living_ai_bom(self.eng, state_digest="f" * 64)

    def test_corrupt_history_cannot_be_exported_as_a_bom(self):
        self._commit(mutation(0.45), "first")
        self.eng._records[0] = replace(self.eng._records[0], reason="tampered")
        with self.assertRaisesRegex(Refusal, "history integrity"):
            living_ai_bom(self.eng)


if __name__ == "__main__":
    unittest.main()
