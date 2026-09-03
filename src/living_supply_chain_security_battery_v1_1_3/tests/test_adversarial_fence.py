import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from living_scs.core import Decision, MinatoAuthority, Refusal, TrustedClock, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation, proposal_trace_auth


class AdversarialFenceTests(unittest.TestCase):
    def test_verifier_only_boundary_cannot_sign(self):
        signer, _, _ = engine()
        verifier = MinatoAuthority.verifier_only("owner-root-1", signer.public_key)
        _, _, _, prop, trace, _ = proposal_trace_auth()
        with self.assertRaisesRegex(Refusal, "cannot sign"):
            verifier.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id="x", nonce="x", issued_at=NOW, expires_at=NOW + 60)

    def test_rogue_authority_signature_is_rejected(self):
        _, _, eng, prop, trace, _ = proposal_trace_auth()
        rogue = MinatoAuthority("rogue", Ed25519PrivateKey.generate())
        auth = rogue.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id="rogue-d", nonce="rogue-n", issued_at=NOW, expires_at=NOW + 60)
        with self.assertRaisesRegex(Refusal, "invalid authorization signature"):
            eng.commit(prop, trace, auth)

    def test_hash_chain_tamper_is_detected(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        eng._records[0] = replace(eng._records[0], reason="rewritten history")
        self.assertFalse(eng.verify_history())

    def test_corrupt_history_fails_closed_on_next_commit(self):
        signer, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        eng._records[0] = replace(eng._records[0], authority_id="attacker")
        prop2 = eng.proposal_for_mutation(proposal_id="after-corruption", mutation_type="personality_drift", mutation=mutation(0.40), evidence=evidence(), interpretation=interpretation(), created_at=NOW)
        trace2 = make_trace(prop2, trace_id="after-corruption-t")
        auth2 = signer.issue(trace2, prop2, decision=Decision.AUTHORIZE, determination_id="after-corruption-d", nonce="after-corruption-n", issued_at=NOW, expires_at=NOW + 60)
        with self.assertRaisesRegex(Refusal, "history integrity"):
            eng.commit(prop2, trace2, auth2)

    def test_trusted_clock_rollback_is_detected(self):
        _, clock, eng, prop, trace, auth = proposal_trace_auth()
        clock.set(NOW - 1)
        with self.assertRaisesRegex(Refusal, "clock rollback"):
            eng.commit(prop, trace, auth)

    def test_partial_persistence_never_changes_live_state(self):
        captured = []

        def partial_then_fail(record, state):
            captured.append({"sequence": record.sequence})
            raise OSError("partial append")

        _, _, eng, prop, trace, auth = proposal_trace_auth(persist_hook=partial_then_fail)
        before = eng.state_digest
        with self.assertRaises(OSError):
            eng.commit(prop, trace, auth)
        self.assertEqual(eng.state_digest, before)
        self.assertEqual(len(eng.records), 0)
        self.assertEqual(captured, [{"sequence": 1}])

    def test_mutation_payload_substitution_is_rejected(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        changed = replace(prop, mutation=mutation(0.10))
        with self.assertRaises(Exception):
            eng.commit(changed, trace, auth)

    def test_audit_record_follows_verified_authorization(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        record = eng.records[0]
        self.assertEqual(record.authorization_id, auth.determination_id)
        self.assertEqual(record.trace_digest, trace.digest())
        self.assertTrue(eng.verify_history())


if __name__ == "__main__":
    unittest.main()
