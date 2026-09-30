import unittest

from aosp_agent.engine import AospBackportAgent, AssessmentError
from aosp_agent.prompts import parse_impact_response


HUNK = {
    "path": "counter.py",
    "old_start": 1,
    "new_start": 1,
    "patch": "@@ -1,2 +1,2 @@\n def normalize_count(value):\n-    return value\n+    return bounded(value)\n",
}

PURE_ADDITION_HUNK = {
    "path": "counter.py",
    "old_start": 1,
    "new_start": 1,
    "patch": "@@ -1,2 +1,3 @@\n def normalize_count(value):\n+    validate(value)\n    return bounded(value)\n",
}

PURE_DELETION_HUNK = {
    "path": "counter.py",
    "old_start": 1,
    "new_start": 1,
    "patch": "@@ -1,3 +1,2 @@\n def normalize_count(value):\n-    return unbounded(value)\n    return bounded(value)\n",
}


def evidence(revision, start=1, end=2, excerpt="def normalize_count(value):\n    return value"):
    return {"revision": revision, "path": "counter.py", "line_start": start,
            "line_end": end, "excerpt": excerpt, "claim": "executable evidence"}


def assessment(**causal_updates):
    causal = {
        "donor_fault_evidence": [2],
        "donor_fix_evidence": [3],
        "target_fault_evidence": [1],
        "target_harm_evidence": [1],
        "target_fault_state": "The target returns an unbounded value.",
        "donor_to_target_mapping": "Both paths return the same count to the caller.",
        "external_behavior_assumptions": [],
    }
    causal.update(causal_updates)
    return {
        "status": "AFFECTED",
        "root_cause": {"category": "logic_error", "description": "fault", "attack_vector": "caller"},
        "evidence": [evidence("target"), evidence("source_parent"), evidence("source_fix")],
        "causal_chain": causal,
        "reasoning": "The four causal links are grounded.",
        "limitations": [],
    }


class ImpactCausalityTest(unittest.TestCase):
    def agent(self):
        agent = object.__new__(AospBackportAgent)
        agent._current_hunks = [HUNK]
        return agent

    def test_valid_fix_defined_chain_is_accepted(self):
        self.agent()._validate_impact_causality(assessment())

    def test_pure_addition_accepts_parent_context_at_fix_site(self):
        raw = assessment()
        raw["causal_chain"]["donor_fault_evidence"] = [2]
        agent = object.__new__(AospBackportAgent)
        agent._current_hunks = [PURE_ADDITION_HUNK]
        agent._validate_impact_causality(raw)

    def test_pure_deletion_accepts_fix_context_at_fix_site(self):
        raw = assessment()
        raw["causal_chain"]["donor_fix_evidence"] = [3]
        agent = object.__new__(AospBackportAgent)
        agent._current_hunks = [PURE_DELETION_HUNK]
        agent._validate_impact_causality(raw)

    def test_context_does_not_replace_changed_lines_in_mixed_hunk(self):
        raw = assessment()
        raw["evidence"][1] = evidence(
            "source_parent", 1, 1, "def normalize_count(value):")
        with self.assertRaisesRegex(AssessmentError, "donor_fault_evidence"):
            self.agent()._validate_impact_causality(raw)

    def test_affected_requires_causal_chain(self):
        raw = assessment()
        del raw["causal_chain"]
        with self.assertRaises(AssessmentError):
            self.agent()._validate_impact_causality(raw)

    def test_context_comment_cannot_bridge_donor_fault(self):
        comment = "// An old API once returned a phantom value.\n// This comment is outside the fix hunk."
        raw = assessment()
        raw["evidence"][1] = evidence("source_parent", 4, 5, comment)
        raw["causal_chain"]["donor_fault_evidence"] = [2]
        with self.assertRaisesRegex(AssessmentError, "donor_fault_evidence"):
            self.agent()._validate_impact_causality(raw)

    def test_external_behavior_assumption_cannot_prove_affected(self):
        raw = assessment(external_behavior_assumptions=[
            "DefaultDialerManager returns a phantom dialer in the work profile"])
        with self.assertRaisesRegex(AssessmentError, "external API behavior"):
            self.agent()._validate_impact_causality(raw)

    def test_target_comment_is_not_executable_fault_evidence(self):
        comment = "// This path could be vulnerable.\n// No executable state is shown."
        raw = assessment()
        raw["evidence"][0] = evidence("target", 1, 2, comment)
        with self.assertRaisesRegex(AssessmentError, "target_fault_evidence"):
            self.agent()._validate_impact_causality(raw)

    def test_parser_accepts_optional_causal_chain_shape(self):
        parsed = parse_impact_response(assessment())
        self.assertIn("donor_fault_evidence", parsed["causal_chain"])


if __name__ == "__main__":
    unittest.main()
