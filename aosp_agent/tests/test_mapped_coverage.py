"""Focused regressions for mapped candidate coverage before compilation."""
import json
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


class CppEquivalentCoverageTest(unittest.TestCase):
    def test_cpp_change_in_read_dependency_reports_its_pinned_location(self):
        from aosp_agent.mapped_coverage import _cpp_read_dependency_changes
        path = 'port.cc'
        before = 'void connect() { open(); }\nvoid open() { store(); }\n'
        after = before.replace('store();', 'store_private();')
        agent = SimpleNamespace(mapping_repository='repo', _artifact_baseline_text=lambda _: before)
        edit = {'path': path, 'line_start': 1, 'line_end': 1, 'action': 'edit'}
        dependency = {'path': path, 'line_start': 2, 'line_end': 2, 'symbol': 'open',
                      'action': 'read_dependency'}
        hunks = split_hunks(diff(path, before, after))
        gaps = _cpp_read_dependency_changes(agent, 'f001-h001', path, hunks, [edit, dependency], [edit])
        gap, = gaps
        self.assertEqual((gap['path'], gap['symbol'], gap['line_start']), ('repo/port.cc', 'open', 2))
        self.assertEqual(gap['excerpt'], before.splitlines()[1])
        self.assertEqual(_cpp_read_dependency_changes(agent, 'f001-h001', path, hunks,
            [edit, dependency], [edit, {**dependency, 'action': 'edit'}]), [])

    def test_cpp_regions_share_identical_evidence_without_losing_region_references(self):
        from aosp_agent.mapped_coverage import _review_payload
        shared = {'kind': 'cpp_equivalent_direct_edit', 'target_fault': 'Shared state.',
                  'target_evidence': [{'excerpt': 'store()'}], 'invariant': 'Separate owners.',
                  'donor_patch': 'Patch excerpt.'}
        first = {'path': 'read.cc', 'patch': 'Read changed.'}
        second = {'path': 'write.cc', 'patch': 'Write changed.'}
        payload = json.loads(_review_payload([
            {**shared, 'id': 'f001-h001:1', 'related_candidate_hunks': [first, second]},
            {**shared, 'id': 'f001-h001:2', 'related_candidate_hunks': [second]},
        ]))
        self.assertEqual(len(payload['shared_cpp_context']), 1)
        self.assertEqual(payload['shared_cpp_context'][0]['target_evidence'], shared['target_evidence'])
        self.assertEqual(payload['related_candidate_hunks'], [first, second])
        self.assertEqual([r['related_hunk_indices'] for r in payload['regions']], [[1, 2], [2]])

    def test_cpp_substitute_requires_changed_code_and_an_independent_verdict(self):
        before = 'void connect() {\n  attach_shared_state();\n}\n'
        donor = diff('modern.cc', 'void modern() {\n  store_modern_global_mode();\n}\n',
                     'void modern() {\n}\n')
        path = 'old.cc'
        hunk = split_hunks(donor)[0]
        region = {'path': 'repo/' + path, 'symbol': 'connect', 'line_start': 1, 'line_end': 3,
                  'action': 'edit', 'relationship': 'moved', 'reason': 'Old connection path.'}
        dependency = {**region, 'path': 'repo/store.cc', 'symbol': 'attach_shared_state',
                      'line_end': 2, 'action': 'read_dependency', 'relationship': 'dependency'}
        store = 'void attach_shared_state() {\n  write_global_state();\n}\n'
        unit = {'id': hunk['id'], 'status': 'AFFECTED', 'invariant': 'Keep state connection-specific.',
                'targets': [region, dependency]}
        for mode in ('covered', 'unresolved', 'remap', 'bad_scope_citation', 'bad_citation',
                     'comment_only', 'removed', 'bad_removed_line'):
            with self.subTest(mode=mode), TemporaryDirectory() as tmp:
                root = Path(tmp)
                after = before.replace('  attach_shared_state();',
                    '  // no functional change\n  attach_shared_state();' if mode == 'comment_only'
                    else '  attach_private_state();')
                removed = mode in ('removed', 'bad_removed_line')
                if removed:
                    after = before.replace('  attach_shared_state();\n', '')
                (root / path).write_text(after)
                candidate = diff(path, before, after)
                verdict = 'UNRESOLVED' if mode in ('unresolved', 'remap', 'bad_scope_citation') else 'COVERED'
                review = {'regions': [{'id': hunk['id'] + ':1', 'verdict': verdict,
                    'reason': 'State effect must be established from source.',
                    'candidate_lines': [] if removed or verdict == 'UNRESOLVED' else
                                       [1 if mode == 'bad_citation' else 2]}]}
                if removed:
                    review['regions'][0]['removed_baseline_lines'] = [1 if mode == 'bad_removed_line' else 2]
                if mode in ('remap', 'bad_scope_citation'):
                    review['regions'][0]['needed_target_citations'] = [1, 2, 3]
                runtime = QueueRuntime([(review, None)])
                agent = object.__new__(AospBackportAgent)
                agent.record = {'required_affected_units': [hunk['id']], 'assessment': {
                    'scope_contract': {'representation_change': 'equivalent_representation'},
                    'causal_chain': {'target_fault_state': 'The old connection uses shared state.'},
                    'evidence': [
                        {'revision': 'target', 'path': 'repo/store.cc', 'line_start': 2,
                         'line_end': 3, 'excerpt': '\n'.join(store.splitlines()[1:])
                         if mode != 'bad_scope_citation' else 'incorrect quote'},
                        {'revision': 'target', 'path': path, 'line_start': 2,
                         'line_end': 2, 'excerpt': before.splitlines()[1]},
                    ]}}
                agent.case = SimpleNamespace(files=(path,))
                agent._current_hunks = [hunk]
                agent.worktree = agent.run_dir = root
                agent.mapping_plan = MappingPlan.create({'units': [unit], 'writable_paths': ['repo/' + path]},
                    [SimpleNamespace(key='repo', head='pinned')], [hunk], {})
                agent.mapping_repository = 'repo'
                agent._target_baseline_lines = lambda p: before.splitlines()
                agent._artifact_baseline_text = lambda p: store if p == 'store.cc' else before
                agent.runtime_factory = runtime.factory
                agent.model = agent.model_provider = None
                agent.turn_timeout = 10
                agent.model_scope = lambda **kwargs: None
                agent.audit_diff = lambda: {}
                agent._render_patch = lambda audit: candidate
                agent._json = lambda *args: None
                ledger = agent._check_hunk_results(f'HUNK-RESULT {hunk["id"]} implemented substitute',
                                                   [path], candidate, review_mapped=True)
                self.assertEqual(ledger['ok'], mode in ('covered', 'removed'), ledger['feedback'])
                result = ledger['claims'][0]['target_evidence']['regions'][0]
                hints = result.get('reconsider_locations', [])
                self.assertEqual([h['path'] for h in hints], ['repo/store.cc'] if mode == 'remap' else [])
                self.assertEqual(agent.mapping_plan.files('repo'), (path,))
                self.assertEqual(len(runtime.calls), 0 if mode == 'comment_only' else 1)
                if runtime.calls:
                    self.assertTrue(runtime.calls[0]['read_only'])
                    self.assertIn('cpp_equivalent_direct_edit', runtime.calls[0]['prompt'])
                    self.assertIn('"related_hunk_indices": [1]', runtime.calls[0]['prompt'])

    def test_cpp_field_evidence_requires_a_real_change_in_the_named_record(self):
        from aosp_agent.mapped_coverage import _cpp_equivalent_evidence
        before = 'typedef struct {\n  int mode;\n} Port;\n'
        region = {'symbol': 'Port', 'line_start': 2, 'line_end': 3,
                  'relationship': 'data_or_configuration'}
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = SimpleNamespace(worktree=root, _artifact_baseline_text=lambda path: before,
                record={'assessment': {'evidence': [], 'causal_chain': {'target_fault_state': 'Shared state.'}}})
            path = 'port.h'
            for change, expected in [('  int mode;\n  int security_mode;', [3]),
                                     ('  int mode;  // comment', [])]:
                after = before.replace('  int mode;', change)
                (root / path).write_text(after)
                detail, error = _cpp_equivalent_evidence(agent, path, split_hunks(diff(path, before, after)), region)
                if expected:
                    self.assertIsNone(error)
                    self.assertEqual(detail['changed_field_lines'], expected)
                else:
                    self.assertIsNone(detail)
                    self.assertIn('changed statement or field', error)


class MappedCoverageTest(unittest.TestCase):
    def check(self, before, after, review, *, symbol='sink', bounds=None, relationship='same_function'):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / PATH).write_text(after)
            first = before.splitlines().index('    private void sink() {') + 1
            start, end = bounds or (first, first + 2)
            unit = {'id': 'f001-h001', 'status': 'AFFECTED', 'invariant': 'Policy must guard consumption.',
                    'targets': [{'path': 'repo/' + PATH, 'symbol': symbol, 'line_start': start, 'line_end': end,
                                 'action': 'edit', 'relationship': relationship, 'reason': 'Enforce the policy before consumption.'}]}
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

    def test_saved_cross_method_mapping_only_credits_the_named_method(self):
        after = BASELINE.replace('        consume();', GUARD + '        consume();')
        ledger, calls = self.check(BASELINE, after, self.verdict(after), bounds=(3, 7))
        self.assertTrue(ledger['ok'], ledger['feedback'])
        self.assertIn('"effective_range": [6, 7]', calls[0]['prompt'])

    def test_state_field_requires_set_guard_and_clear(self):
        after = (BASELINE.replace('    boolean legacyPolicy;', '    boolean deferred;\n    boolean legacyPolicy;')
                 .replace('        sink();', '        this.deferred = true;\n        sink();')
                 .replace('        consume();', '        if (this.deferred) return;\n        consume();')
                 .replace('    void consume() {}', '    void consume() { this.deferred = false; }'))
        review = {'regions': [{'id': 'f001-h001:1', 'verdict': 'COVERED',
                               'reason': 'The bound state is set, guarded and cleared.',
                               'candidate_lines': [2], 'state_evidence': [1, 2, 3]}]}
        options = {'symbol': 'Counter.deferred', 'bounds': (2, 2), 'relationship': 'data_or_configuration'}
        ledger, calls = self.check(BASELINE, after, review, **options)
        self.assertTrue(ledger['ok'], ledger['feedback'])
        self.assertIn('field_lifecycle', calls[0]['prompt'])
        no_clear = after.replace('    void consume() { this.deferred = false; }', '    void consume() {}')
        ledger, calls = self.check(BASELINE, no_clear, None, **options)
        self.assertFalse(ledger['ok'])
        self.assertIn('missing changed, bound evidence: clear', ledger['feedback'])
        self.assertFalse(calls)
        review['regions'][0]['state_evidence'] = [1, 2]
        ledger, _ = self.check(BASELINE, after, review, **options)
        self.assertFalse(ledger['ok'])
        self.assertIn('ungrounded candidate lines', ledger['feedback'])

    def test_review_cannot_cite_unchanged_candidate_line(self):
        after = BASELINE.replace('        consume();', GUARD + '        consume();')
        ledger, _ = self.check(BASELINE, after, self.verdict(after, line=1))
        self.assertFalse(ledger['ok'])
        self.assertIn('ungrounded candidate lines', ledger['feedback'])
