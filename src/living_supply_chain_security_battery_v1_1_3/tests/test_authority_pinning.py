import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from living_scs.core import CommitEngine, Decision, MinatoAuthority, Refusal, TrustedClock, make_trace
from living_scs.fixtures import NOW, authority_pair, evidence, initial_state, interpretation, mutation


class AuthorityPinningTests(unittest.TestCase):
    def setUp(self):
        self.signer, self.verifier = authority_pair()
        self.pins = {
            "expected_authority_id": "owner-root-1",
            "expected_public_key": self.signer.public_key_bytes(),
        }

    def _engine(self, authority, **pins):
        return CommitEngine("pin-test", initial_state(), authority, TrustedClock(NOW), **pins)

    def _signed(self, eng, signer):
        proposal = eng.proposal_for_mutation(
            proposal_id="pin-p", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace = make_trace(proposal, trace_id="pin-t")
        auth = signer.issue(
            trace, proposal, decision=Decision.AUTHORIZE, determination_id="pin-d",
            nonce="pin-n", issued_at=NOW, expires_at=NOW + 60,
        )
        return proposal, trace, auth

    def test_constructor_requires_explicit_pins(self):
        with self.assertRaises(TypeError):
            self._engine(self.verifier)

    def test_constructor_rejects_injected_key_under_expected_identity(self):
        rogue = MinatoAuthority("owner-root-1", Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(Refusal, "public key does not match"):
            self._engine(rogue, **self.pins)

    def test_constructor_rejects_wrong_identity_even_with_expected_key(self):
        wrong_identity = MinatoAuthority.verifier_only("other-root", self.signer.public_key)
        with self.assertRaisesRegex(Refusal, "identity does not match"):
            self._engine(wrong_identity, **self.pins)

    def test_constructor_rejects_empty_key_pin(self):
        with self.assertRaisesRegex(Refusal, "32 bytes"):
            self._engine(self.verifier, expected_authority_id="owner-root-1", expected_public_key=b"")

    def test_changing_supplied_verifier_does_not_change_engine_trust(self):
        eng = self._engine(self.verifier, **self.pins)
        rogue = MinatoAuthority("owner-root-1", Ed25519PrivateKey.generate())
        self.verifier.public_key = rogue.public_key
        with self.assertRaisesRegex(Refusal, "invalid authorization signature"):
            eng.commit(*self._signed(eng, rogue))
        eng.commit(*self._signed(eng, self.signer))
        self.assertEqual(len(eng.records), 1)

    def test_injected_verify_method_is_not_trusted(self):
        class PermissiveVerifier(MinatoAuthority):
            def verify(self, envelope):
                return True

        supplied = PermissiveVerifier.verifier_only("owner-root-1", self.signer.public_key)
        eng = self._engine(supplied, **self.pins)
        rogue = MinatoAuthority("owner-root-1", Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(Refusal, "invalid authorization signature"):
            eng.commit(*self._signed(eng, rogue))

    def test_engine_retains_only_a_verifier(self):
        eng = self._engine(self.signer, **self.pins)
        proposal, trace, auth = self._signed(eng, self.signer)
        with self.assertRaisesRegex(Refusal, "cannot sign"):
            eng._authority.issue(
                trace, proposal, decision=Decision.AUTHORIZE,
                determination_id="self-d", nonce="self-n", issued_at=NOW, expires_at=NOW + 60,
            )
        eng.commit(proposal, trace, auth)


if __name__ == "__main__":
    unittest.main()
