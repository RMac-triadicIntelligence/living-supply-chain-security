import threading
import unittest
from dataclasses import replace

from living_scs.core import Decision, Refusal, make_trace
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation, proposal_trace_auth


class MinatoBindingTests(unittest.TestCase):
    def test_valid_exact_binding_commits(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        self.assertEqual(eng.commit(prop, trace, auth), prop.expected_result_digest)

    def test_changed_nonce_breaks_signature(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        with self.assertRaisesRegex(Refusal, "invalid authorization signature"):
            eng.commit(prop, trace, replace(auth, nonce="changed"))

    def test_changed_result_digest_breaks_signature(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, replace(auth, resulting_digest="a" * 64))

    def test_wrong_policy_binding_is_rejected(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, replace(auth, policy_version="DOWNGRADE"))

    def test_wrong_maturity_binding_is_rejected(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        with self.assertRaises(Refusal):
            eng.commit(prop, trace, replace(auth, maturity_state="mature"))

    def test_wrong_scope_is_rejected(self):
        signer, clock, eng, prop, trace, _ = proposal_trace_auth()
        auth = signer.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id="scope", nonce="scope", issued_at=NOW, expires_at=NOW + 60, scope="marketplace")
        with self.assertRaisesRegex(Refusal, "scope"):
            eng.commit(prop, trace, auth)

    def test_expired_authorization_is_rejected(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth(expires_at=NOW - 1)
        with self.assertRaisesRegex(Refusal, "expired"):
            eng.commit(prop, trace, auth)

    def test_far_future_authorization_is_rejected(self):
        signer, _, eng, prop, trace, _ = proposal_trace_auth()
        auth = signer.issue(trace, prop, decision=Decision.AUTHORIZE, determination_id="future", nonce="future", issued_at=NOW + 31, expires_at=NOW + 100)
        with self.assertRaisesRegex(Refusal, "future"):
            eng.commit(prop, trace, auth)

    def test_nonce_replay_is_rejected(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        with self.assertRaisesRegex(Refusal, "replay"):
            eng.commit(prop, trace, auth)

    def test_determination_id_replay_is_rejected(self):
        signer, clock, eng, prop, trace, auth = proposal_trace_auth()
        eng.commit(prop, trace, auth)
        prop2 = eng.proposal_for_mutation(
            proposal_id="proposal-2", mutation_type="personality_drift", mutation=mutation(0.40),
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace2 = make_trace(prop2, trace_id="trace-2")
        auth2 = signer.issue(trace2, prop2, decision=Decision.AUTHORIZE, determination_id=auth.determination_id, nonce="new-nonce", issued_at=NOW, expires_at=NOW + 60)
        with self.assertRaisesRegex(Refusal, "replay"):
            eng.commit(prop2, trace2, auth2)

    def test_cross_organism_replay_is_rejected(self):
        _, _, _, prop, trace, auth = proposal_trace_auth(organism_id="organism-alpha")
        _, _, beta = engine(organism_id="organism-beta")
        with self.assertRaises(Refusal):
            beta.commit(prop, trace, auth)

    def test_same_nonce_concurrency_allows_exactly_one_commit(self):
        _, _, eng, prop, trace, auth = proposal_trace_auth()
        outcomes = []
        barrier = threading.Barrier(2)

        def worker():
            try:
                barrier.wait()
                eng.commit(prop, trace, auth)
                outcomes.append("ok")
            except Refusal:
                outcomes.append("refused")

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("refused"), 1)

    def test_persist_failure_does_not_burn_authorization(self):
        attempts = {"count": 0}

        def fail_once(record, state):
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise OSError("simulated durable write failure")

        _, _, eng, prop, trace, auth = proposal_trace_auth(persist_hook=fail_once)
        with self.assertRaises(OSError):
            eng.commit(prop, trace, auth)
        self.assertEqual(len(eng.records), 0)
        self.assertEqual(eng.commit(prop, trace, auth), prop.expected_result_digest)


if __name__ == "__main__":
    unittest.main()
