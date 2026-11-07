"""Focused regressions for mapped candidate coverage before compilation."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from aosp_agent.engine import AospBackportAgent
from aosp_agent.mapping_plan import MappingPlan
from aosp_agent.patches import split_hunks
from test_diff_workflow import QueueRuntime, diff


BASELINE = '''class Counter {
    boolean legacyPolicy;
    void entry() {
        sink();
    }
    private void sink() {
        consume();
    }
    void consume() {}
}
'''
GUARD = '        if (legacyPolicy) { return; }\n'
PATH = 'Counter.java'
DONOR = diff('ModernCounter.java', 'void newer() {\n    consumeNew();\n}\n',
             'void newer() {\n    if (freshPolicy) { return; }\n    consumeNew();\n}\n')


class MappedCoverageTest(unittest.TestCase):
    def check(self, before, after, review):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / PATH).write_text(after)
            first = before.splitlines().index('    private void sink() {') + 1
            unit = {'id': 'f001-h001', 'status': 'AFFECTED', 'invariant': 'Policy must guard consumption.',
                    'targets': [{'path': 'repo/' + PATH, 'symbol': 'sink', 'line_start': first, 'line_end': first + 2,
                                 'action': 'edit', 'reason': 'Enforce the policy before consumption.'}]}
            hunk = split_hunks(DONOR)[0]
            candidate = diff(PATH, before, after)
            runtime = QueueRuntime([] if review is None else [(review, None)])
            agent = object.__new__(AospBackportAgent)
            agent.case = SimpleNamespace(files=(PATH,))
            agent._current_hunks = [hunk]
            agent.worktree = agent.run_dir = root
            agent.mapping_plan = MappingPlan.create({'units': [unit], 'writable_paths': ['repo/' + PATH]},
                [SimpleNamespace(key='repo', head='pinned')], [hunk], {})
            agent.mapping_repository = 'repo'
            agent._target_baseline_lines = lambda path: before.splitlines()
            agent._artifact_baseline_text = lambda path: before
            agent.runtime_factory = runtime.factory
            agent.model = agent.model_provider = None
            agent.turn_timeout = 10
            agent.model_scope = lambda **kwargs: None
            agent.audit_diff = lambda: {}
            agent._render_patch = lambda audit: candidate
            agent._json = lambda name, value: None
            ledger = agent._check_hunk_results('HUNK-RESULT f001-h001 implemented mapped protection',
                                               [PATH], candidate, review_mapped=True)
            return ledger, runtime.calls

    def verdict(self, after, *, line=None):
        return {'regions': [{'id': 'f001-h001:1', 'verdict': 'COVERED',
            'reason': 'The target policy returns before consumption.',
            'candidate_lines': [after.splitlines().index(GUARD.rstrip()) + 1 if line is None else line]}]}

    def test_target_specific_direct_edit_is_reviewed(self):
        after = BASELINE.replace('        consume();', GUARD + '        consume();')
        ledger, calls = self.check(BASELINE, after, self.verdict(after))
        self.assertTrue(ledger['ok'], ledger['feedback'])
        self.assertTrue(calls[0]['read_only'])
        self.assertIn('direct_edit', calls[0]['prompt'])

    def test_unchanged_private_method_with_closed_guarded_caller(self):
        after = BASELINE.replace('        sink();', GUARD + '        sink();')
        ledger, calls = self.check(BASELINE, after, self.verdict(after))
        self.assertTrue(ledger['ok'], ledger['feedback'])
        self.assertIn('guarded_callers', calls[0]['prompt'])

    def test_nested_exit_guard_can_be_reviewed(self):
        before = BASELINE.replace('    boolean legacyPolicy;', '    boolean legacyPolicy;\n    boolean transition;')
        guard = '        if (legacyPolicy) {\n            if (transition) { return; }\n        }\n'
        after = before.replace('        sink();', guard + '        sink();')
        ledger, _ = self.check(before, after, self.verdict(after, line=after.splitlines().index(guard.splitlines()[0]) + 1))
        self.assertTrue(ledger['ok'], ledger['feedback'])

    def test_unguarded_alternate_call_blocks_without_review(self):
        before = BASELINE.replace('    void consume() {}', '    void alternate() { sink(); }\n    void consume() {}')
        after = before.replace('        sink();', GUARD + '        sink();')
        ledger, calls = self.check(before, after, None)
        self.assertFalse(ledger['ok'])
        self.assertIn('without a newly added preceding exit guard', ledger['feedback'])
        self.assertFalse(calls)

    def test_review_cannot_cite_unchanged_candidate_line(self):
        after = BASELINE.replace('        consume();', GUARD + '        consume();')
        ledger, _ = self.check(BASELINE, after, self.verdict(after, line=1))
        self.assertFalse(ledger['ok'])
        self.assertIn('ungrounded candidate lines', ledger['feedback'])
