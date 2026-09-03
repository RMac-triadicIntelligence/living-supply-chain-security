import unittest
from dataclasses import replace

from living_scs.core import ProposalStatus, Refusal, TraceError, TraceValidator, canonical_json, make_trace, sha256_hex
from living_scs.fixtures import NOW, engine, evidence, interpretation, mutation, proposal_trace_auth


class TraceSchemaTests(unittest.TestCase):
    def test_canonical_serialization_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), canonical_json({"a": 1, "b": 2}))

    def test_no_trace_no_drift(self):
        _, _, eng, prop, _, auth = proposal_trace_auth()
        with self.assertRaisesRegex(Refusal, "no trace"):
            eng.commit(prop, None, auth)

    def test_empty_evidence_is_rejected(self):
        _, _, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-empty", mutation_type="personality_drift", mutation=mutation(),
            evidence=(), interpretation=interpretation(), created_at=NOW,
        )
        with self.assertRaisesRegex(TraceError, "empty evidence"):
            TraceValidator.validate_proposal(prop)

    def test_duplicate_evidence_is_rejected(self):
        _, _, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-dup", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(2, duplicate=True), interpretation=interpretation(), created_at=NOW,
        )
        with self.assertRaisesRegex(TraceError, "duplicate"):
            TraceValidator.validate_proposal(prop)

    def test_model_narration_cannot_create_evidence(self):
        _, _, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-self", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(1, detector="model_narrative"), interpretation=interpretation(), created_at=NOW,
        )
        with self.assertRaisesRegex(TraceError, "narration"):
            TraceValidator.validate_proposal(prop)

    def test_out_of_bounds_confidence_is_rejected(self):
        _, _, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-bounds", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(), interpretation=interpretation(confidence=1.01), created_at=NOW,
        )
        with self.assertRaisesRegex(TraceError, "confidence"):
            TraceValidator.validate_proposal(prop)

    def test_tampered_trace_result_digest_is_rejected(self):
        _, _, _, prop, trace, _ = proposal_trace_auth()
        tampered = replace(trace, resulting_digest="f" * 64)
        with self.assertRaisesRegex(TraceError, "result digest"):
            TraceValidator.validate_trace(tampered, prop)

    def test_trace_cannot_predate_proposal(self):
        _, _, eng = engine()
        prop = eng.proposal_for_mutation(
            proposal_id="p-time", mutation_type="personality_drift", mutation=mutation(),
            evidence=evidence(), interpretation=interpretation(), created_at=NOW,
        )
        with self.assertRaisesRegex(TraceError, "predates"):
            make_trace(prop, trace_id="t-time", status=ProposalStatus.AWAITING_EXTERNAL_AUTHORIZATION, created_at=NOW - 1)

    def test_trace_digest_changes_when_any_bound_field_changes(self):
        _, _, _, _, trace, _ = proposal_trace_auth()
        self.assertNotEqual(trace.digest(), replace(trace, policy_version="OTHER").digest())


if __name__ == "__main__":
    unittest.main()
