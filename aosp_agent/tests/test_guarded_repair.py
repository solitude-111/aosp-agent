"""Guarded statements remain obligations even when unchanged in the diff."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from aosp_agent.discovery import diff_units
from aosp_agent.engine import AospBackportAgent
from aosp_agent.guarded_repair import guard_obligations, review_covers_contract
from aosp_agent.mapping_plan import MappingPlan
from test_diff_workflow import QueueRuntime, diff


PATH = 'Controller.java'
PARENT = '''class Controller {
    void update() {
        if (flag() && affected()) {
            reconcile();
            retainUntilSafe();
        }
    }
    void release() { retained = false; }
    boolean retained;
    boolean affected() { return true; }
    boolean flag() { return true; }
    void updateFlags() {}
    void reconcile() {}
    void retainUntilSafe() { retained = true; }
    boolean mayRemove() { return !retained; }
    void cancel() { retained = false; }
}
'''
FIX = PARENT.replace('flag() && ', '')
BASELINE = PARENT.replace('        if (flag() && affected()) {\n            reconcile();\n'
                          '            retainUntilSafe();\n        }\n', '        updateFlags();\n')
PARTIAL = BASELINE.replace('        updateFlags();', '        updateFlags();\n        if (affected()) {\n'
                           '            reconcile();\n        }')
COMPLETE = PARTIAL.replace('            reconcile();', '            reconcile();\n            retainUntilSafe();')
UPSTREAM = diff_units(diff(PATH, PARENT, FIX))[0]


class GuardedRepairTest(unittest.TestCase):
    def test_all_unchanged_guarded_statements_are_extracted(self):
        obligations = guard_obligations(UPSTREAM, PARENT, FIX)
        self.assertEqual([o['behavior']['excerpt'] for o in obligations], ['reconcile();', 'retainUntilSafe();'])
        self.assertEqual(guard_obligations(UPSTREAM, PARENT, PARENT), [])

    def check(self, after, *, verdict, reason, cancellation='covered', evidence=None, corrupt=False):
        obligations = guard_obligations(UPSTREAM, PARENT, FIX)
        main = {'path': 'repo/' + PATH, 'symbol': 'update', 'line_start': 2, 'line_end': 4,
                'action': 'edit', 'relationship': 'same_function'}
        dependency = {**main, 'symbol': 'release', 'line_start': 5, 'line_end': 5, 'action': 'read_dependency'}
        unit = {'id': UPSTREAM['id'], 'status': 'AFFECTED', 'targets': [main, dependency],
                'evidence': [{'origin': 'target', 'path': 'repo/' + PATH, 'line_start': 5, 'line_end': 5,
                              'excerpt': '    void release() { retained = false; }'},
                             {'origin': 'target', 'path': 'repo/' + PATH, 'line_start': 13, 'line_end': 13,
                              'excerpt': '    void cancel() { retained = false; }'}]}
        contract = [{**o, 'disposition': 'edit', 'targets': [main, dependency]} for o in obligations]
        after_lines = after.splitlines()
        def cite(text):
            return {'window_id': 'C1', 'line_start': after_lines.index(text) + 1,
                    'line_end': after_lines.index(text) + 1}
        second = [cite('            retainUntilSafe();')] if verdict == 'covered' else []
        if corrupt:
            second[0]['line_end'] = 1000
        recheck = cite('            reconcile();')
        paths = [{'id': 'normal', 'verdict': verdict, 'reason': reason, 'evidence': second}]
        if cancellation is not None:
            if evidence is None:
                evidence = [{'window_id': 'B2', 'line_start': 13, 'line_end': 13}] if cancellation == 'covered' else []
            paths.append({'id': 'cancellation', 'verdict': cancellation,
                          'reason': 'Cancellation cleanup evidence.', 'evidence': evidence})
        result = {'regions': [], 'obligations': [
            {'id': obligations[0]['id'], 'paths': [
                {'id': 'normal', 'verdict': 'covered', 'reason': 'Reconciles after update.', 'evidence': [recheck]},
                {'id': 'cancellation', 'verdict': 'not_applicable', 'reason': 'Recheck completes in the call.',
                 'evidence': [recheck]}]},
            {'id': obligations[1]['id'], 'paths': paths}],
            'impact': {'overall_risk': 'low', 'reasoning': 'Local change.',
                       **{k: [] for k in ('affected_callers', 'behavior_changes', 'compatibility_risks',
                                          'performance_notes', 'test_recommendations')}}}
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / PATH).write_text(after)
            candidate = diff(PATH, BASELINE, after)
            runtime = QueueRuntime([(result, None)])
            agent = object.__new__(AospBackportAgent)
            agent.record = {"impact_decision": "AFFECTED"}
            agent.case = SimpleNamespace(files=(PATH,))
            agent._current_hunks = [UPSTREAM]
            agent.worktree = agent.run_dir = root
            agent.mapping_plan = MappingPlan.create({'units': [unit], 'writable_paths': ['repo/' + PATH]},
                [SimpleNamespace(key='repo', head='pinned')], [UPSTREAM], {}, repair_contract=contract)
            agent.mapping_repository = 'repo'
            agent._target_baseline_lines = lambda path: BASELINE.splitlines()
            agent._artifact_baseline_text = lambda path: BASELINE
            agent.runtime_factory = runtime.factory
            agent.model = agent.model_provider = None
            agent.turn_timeout = 10
            agent.model_scope = lambda **kwargs: None
            agent.audit_diff = lambda: {}
            agent._render_patch = lambda audit: candidate
            agent._json = lambda name, value: None
            ledger = agent._check_hunk_results('HUNK-RESULT f001-h001 implemented relaxed guard',
                                               [PATH], candidate, review_mapped=True)
            self.assertEqual(len(runtime.calls), 1)
            self.assertTrue(runtime.calls[0]['read_only'])
            self.assertTrue(ledger['claims'][0]['target_evidence']['ok'])
            self.assertEqual(agent.record['impact_decision'], 'AFFECTED')
            receipt = agent.record['repair_obligation_review']
            self.assertEqual(review_covers_contract(receipt, contract), ledger['ok'])
            return ledger, receipt

    def test_exact_guard_match_cannot_hide_missing_behavior(self):
        ledger, receipt = self.check(PARTIAL, verdict='unresolved', reason='No retention or safe release.')
        self.assertFalse(ledger['ok'])
        self.assertIn('No retention or safe release', ledger['feedback'])
        self.assertEqual(receipt['status'], 'UNRESOLVED')

    def test_timing_gap_stops_even_with_both_operations(self):
        ledger, _ = self.check(COMPLETE, verdict='unresolved', reason='Protection ends when the transition starts.')
        self.assertFalse(ledger['ok'])
        self.assertIn('Protection ends when the transition starts', ledger['feedback'])

    def test_complete_candidate_uses_one_review_and_exact_receipt(self):
        ledger, receipt = self.check(COMPLETE, verdict='covered', reason='Retained until safe.')
        self.assertTrue(ledger['ok'], ledger['feedback'])
        self.assertEqual(receipt['status'], 'COVERED')
        self.assertTrue(receipt['patch_sha256'])
        ledger, _ = self.check(COMPLETE, verdict='covered', reason='Retained until safe.', corrupt=True)
        self.assertFalse(ledger['ok'])
        self.assertIn('outside the supplied evidence window', ledger['feedback'])

    def test_remap_requires_grounded_baseline_dependency(self):
        evidence = [{'window_id': 'B1', 'line_start': 5, 'line_end': 5}]
        ledger, receipt = self.check(PARTIAL, verdict='unresolved', reason='Release also needs to be mapped.',
                                     cancellation='remap', evidence=evidence)
        self.assertFalse(ledger['ok'])
        target = receipt['obligations'][1]['targets_to_reconsider'][0]
        self.assertEqual((target['symbol'], target['review_path']), ('release', 'cancellation'))

    def test_normal_coverage_cannot_hide_unconfirmed_or_omitted_cancellation(self):
        for verdict in ('unresolved', None, 'not_applicable'):
            with self.subTest(verdict=verdict):
                ledger, receipt = self.check(COMPLETE, verdict='covered', reason='Normal release.',
                                             cancellation=verdict)
                self.assertFalse(ledger['ok'])
                self.assertEqual(receipt['status'], 'UNRESOLVED')
                self.assertEqual(receipt['coverage_gaps'][0]['path_id'], 'cancellation')
                self.assertEqual(receipt['obligations'][1]['paths'][0]['verdict'], 'covered')

    def test_old_aggregate_receipt_cannot_authorize_build(self):
        contract = guard_obligations(UPSTREAM, PARENT, FIX)
        old = {'status': 'COVERED', 'obligations': [{**o, 'verdict': 'covered'} for o in contract]}
        self.assertFalse(review_covers_contract(old, contract))
