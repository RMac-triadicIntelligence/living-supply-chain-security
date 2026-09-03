import unittest

from living_scs.core import Decision, Refusal, make_trace, living_ai_bom
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation


class StateSchemaTests(unittest.TestCase):
    def _signed(self, signer, eng, payload, tag):
        prop = eng.proposal_for_mutation(
            proposal_id=f"{tag}-p", mutation_type="schema_probe", mutation=payload,
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        trace = make_trace(prop, trace_id=f"{tag}-t")
        auth = signer.issue(
            trace, prop, decision=Decision.AUTHORIZE,
            determination_id=f"{tag}-d", nonce=f"{tag}-n",
            issued_at=NOW, expires_at=NOW + 60,
        )
        return prop, trace, auth

    def test_signed_organs_sibling_is_refused(self):
        signer, _, eng = engine()
        signed = self._signed(signer, eng, {"op": "set", "path": ["Organs", "hidden"], "value": {"digest": "a" * 64, "use_category": "high", "source_uri": "x://y"}}, "sib")
        with self.assertRaisesRegex(Refusal, "protected state|undeclared"):
            eng.commit(*signed)
        self.assertNotIn("Organs", eng.state)
        self.assertEqual(living_ai_bom(eng)["components"], [])

    def test_signed_maturity_sibling_is_refused(self):
        signer, _, eng = engine()
        signed = self._signed(signer, eng, {"op": "set", "path": ["Maturity"], "value": "mature"}, "mat")
        with self.assertRaisesRegex(Refusal, "protected state|undeclared"):
            eng.commit(*signed)
        self.assertEqual(eng.state["maturity"], "juvenile")
        self.assertNotIn("Maturity", eng.state)

    def test_signed_unknown_root_is_refused(self):
        signer, _, eng = engine()
        signed = self._signed(signer, eng, {"op": "set", "path": ["capabilities", "browser"], "value": {"digest": "b" * 64}}, "cap")
        with self.assertRaisesRegex(Refusal, "undeclared"):
            eng.commit(*signed)
        self.assertNotIn("capabilities", eng.state)

    def test_personality_cannot_shadow_organs(self):
        signer, _, eng = engine()
        signed = self._signed(signer, eng, {"op": "set", "path": ["personality", "organs"], "value": {"decoy": True}}, "shadow")
        with self.assertRaisesRegex(Refusal, "shadow"):
            eng.commit(*signed)
        self.assertNotIn("organs", eng.state["personality"])

    def test_homoglyph_organ_root_is_refused(self):
        signer, _, eng = engine()
        # Cyrillic a in "organs"
        signed = self._signed(signer, eng, {"op": "set", "path": ["orgаns", "tool"], "value": {"digest": "c" * 64}}, "cyr")
        with self.assertRaisesRegex(Refusal, "undeclared"):
            eng.commit(*signed)

    def test_policy_label_cannot_be_set(self):
        signer, _, eng = engine()
        signed = self._signed(signer, eng, {"op": "set", "path": ["policy"], "value": "ATTACKER-POLICY"}, "pol")
        with self.assertRaisesRegex(Refusal, "undeclared or protected"):
            eng.commit(*signed)
        self.assertEqual(eng.state["policy"], "LIVING-SCS-POLICY-V1.1")

    def test_legitimate_personality_set_still_commits(self):
        signer, _, eng, prop, trace, auth = __import__("living_scs.fixtures", fromlist=["proposal_trace_auth"]).proposal_trace_auth()
        result = eng.commit(prop, trace, auth)
        self.assertEqual(result, prop.expected_result_digest)
        self.assertEqual(eng.state["personality"]["verbosity"], 0.45)
