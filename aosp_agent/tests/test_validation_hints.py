"""Lexical donor vocabulary cannot stand in for behavior or reject rewrites."""
from dataclasses import replace
import sys
import unittest

from aosp_agent.discovery import diff_units
from aosp_agent.engine import AospBackportAgent
from aosp_agent.validation_plan import make_plan
from engine_fixtures import GitFixture, BASELINE, git
from test_diff_workflow import diff
from test_validation_plan import Blobs


UPSTREAM = ('def normalize_count(value):\n    return clamp_count(value)\n\n'
            'def clamp_count(value):\n    return min(10, max(0, value))\n')
REWRITTEN = 'def normalize_count(value):\n    return 0 if value < 0 else 10 if value > 10 else value\n'


class ValidationHintsTest(unittest.TestCase):
    def plan(self, explicit=None):
        patch = diff('counter.py', BASELINE, UPSTREAM)
        units = diff_units(patch)
        return make_plan(Blobs({'counter.py': BASELINE}), units,
                         {u['id']: ['counter.py'] for u in units}, ['counter.py'], patch, explicit=explicit)

    def verify(self, fx, candidate, plan):
        agent = AospBackportAgent(fx.source_root, fx.run_root,
            replace(fx.case(), validation_checks=tuple(plan['checks'])))
        agent.prepare()
        (agent.worktree / 'counter.py').write_text(candidate)
        agent.export_patch(1)
        result = agent.verify()
        self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
        self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
        return result

    def test_equivalent_rewrite_passes_real_functional_check_without_donor_markers(self):
        plan = self.plan([[sys.executable, '-B', 'verify_contract.py']])
        self.assertTrue(plan['provenance'][0]['terms'])
        self.assertTrue(all(term not in REWRITTEN for term in plan['provenance'][0]['terms']))
        with GitFixture() as fx:
            result = self.verify(fx, REWRITTEN, plan)
        self.assertEqual(result['status'], 'PASS')
        self.assertIn('contract verified', result['commands'][0]['stdout'])
        self.assertEqual(len(result['commands']), 1)
        self.assertFalse(result['sufficient_for_validated'], 'ordinary check is not a production build')

    def test_comment_markers_cannot_satisfy_real_functional_check_or_create_auto_pass(self):
        candidate = BASELINE + '# clamp_count max min\n'
        with GitFixture() as fx:
            result = self.verify(fx, candidate, self.plan([[sys.executable, '-B', 'verify_contract.py']]))
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['sufficient_for_validated'])
        with GitFixture() as fx:
            result = self.verify(fx, candidate, self.plan())
        self.assertEqual(result['status'], 'NOT_CONFIGURED')
        self.assertEqual(result['commands'], [])
        self.assertFalse(result['sufficient_for_validated'])

    def test_explicit_operator_source_contract_remains_binding(self):
        plan = self.plan({'source_contract': [[sys.executable, '-B', 'check_lower.py']]})
        with GitFixture() as fx:
            result = self.verify(fx, BASELINE + '# clamp_count\n', plan)
        self.assertEqual(result['stages'], {'source_contract': 'FAIL'})
        self.assertFalse(result['sufficient_for_validated'])
