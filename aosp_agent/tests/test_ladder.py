"""Tests for aosp_agent.ladder (R14 strategy ladder)."""
import unittest

from aosp_agent.ladder import STRATEGIES, ladder_plan, strategy_prompt


class LadderTest(unittest.TestCase):
    def ctx(self, **overrides):
        base = {"applied_hunk_ids": ["f001-h001"],
                "failed_hunks": [{"id": "f001-h002", "path": "src/A.java"}],
                "missing_symbols": ["FrameworkParsingPackageUtils"],
                "history_available": True,
                "diagnosis_json": {"summary": "stage failed", "stage_results": []},
                "claim_feedback": None,
                "failing_stages": ["android_module_build"]}
        base.update(overrides)
        return base

    def test_six_strategies_in_order(self):
        self.assertEqual(STRATEGIES, ["verify_and_complete", "repair", "history_informed",
                                      "alternative_approach", "focused_fix", "final_attempt"])

    def test_t1_describes_mechanical_starting_state(self):
        prompt = strategy_prompt(0, self.ctx())
        self.assertIn("f001-h001", prompt)
        self.assertIn("f001-h002", prompt)
        self.assertIn("FrameworkParsingPackageUtils", prompt)
        self.assertIn("HUNK-RESULT", prompt)

    def test_t2_carries_diagnosis_not_raw_logs(self):
        prompt = strategy_prompt(1, self.ctx())
        self.assertIn("stage failed", prompt)
        self.assertIn("HUNK-RESULT", prompt)

    def test_t3_requires_history(self):
        self.assertIn("hunk-history", strategy_prompt(2, self.ctx()))
        self.assertIsNone(strategy_prompt(2, self.ctx(history_available=False)))

    def test_t4_t5_t6_contents(self):
        self.assertIn("different equivalent implementation", strategy_prompt(3, self.ctx()))
        focused = strategy_prompt(4, self.ctx())
        self.assertIn("android_module_build", focused)
        final = strategy_prompt(5, self.ctx())
        self.assertIn("need_not_ported", final)

    def test_plan_skips_unavailable_levels(self):
        full = [level["strategy"] for level in ladder_plan(self.ctx())]
        self.assertEqual(full, STRATEGIES)
        without_history = [level["strategy"] for level in ladder_plan(
            self.ctx(history_available=False))]
        self.assertEqual(without_history, [s for s in STRATEGIES if s != "history_informed"])

    def test_out_of_range_raises(self):
        with self.assertRaises(IndexError):
            strategy_prompt(len(STRATEGIES), self.ctx())


if __name__ == "__main__":
    unittest.main()
