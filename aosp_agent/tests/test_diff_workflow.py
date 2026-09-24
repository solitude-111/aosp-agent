"""Small local Git regressions for diff-only discovery and semantic-plan guards.

Runtime doubles test orchestration; they do not establish a real model's accuracy.
All examples are ordinary count normalization, not exploit reproductions.
"""
import copy
import difflib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.discovery import Locator, diff_units, functions, repositories
from aosp_agent.engine import AssessmentError
from engine_fixtures import BASELINE, FIXED, GitFixture, git


def diff(path, before, after):
    return ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                       fromfile='a/' + path, tofile='b/' + path))


class QueueRuntime:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def factory(self, **kwargs):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def start(self, cwd, instructions):
        self.cwd = Path(cwd)
        return 'test-thread'

    def run(self, prompt, read_only, output_schema):
        self.calls.append({'prompt': prompt, 'read_only': read_only})
        response, edit = self.replies.pop(0)
        if edit:
            edit(self.cwd)
        return {'status': 'completed', 'final_response': json.dumps(response)}


class DiffWorkflowTest(unittest.TestCase):
    def agent(self, fx, runtime=None, *, patch=None, validation=None):
        path = fx.root / 'input.diff'
        path.write_text(patch or diff('new/metrics.py', BASELINE, FIXED))
        return DiffBackportAgent(path, fx.repo, fx.run_root, runtime_factory=runtime.factory if runtime else None,
                                 validation=validation)

    def assessment(self, agent, status='AFFECTED'):
        u = agent.units[0]
        target = {'path': 'repo/counter.py', 'symbol': 'normalize_count', 'line_start': 1, 'line_end': 2,
                  'action': 'edit',
                  'relationship': 'moved', 'reason': 'Same ordinary counter logic in the older layout.'}
        return {'reasoning': 'Compare counter normalization.', 'limitations': ['No Android runtime configured.'],
                'units': [{'id': u['id'], 'status': status, 'invariant': 'Keep the ordinary count between 0 and 10.',
                    'reasoning': 'The old counter returns the input directly.', 'absence_basis': 'none',
                    'targets': [target], 'candidate_resolution': 'The counter implementation defines the shared symbol.',
                    'evidence': [{'origin': 'target', 'path': 'repo/counter.py', 'line_start': 1, 'line_end': 2,
                                  'excerpt': BASELINE.strip(), 'claim': 'Target returns raw ordinary count.'},
                                 {'origin': 'patch_after', 'path': u['new_path'], 'line_start': 1, 'line_end': 2,
                                  'excerpt': FIXED.strip(), 'claim': 'Diff bounds the ordinary count.'}]}], 'new_files': []}

    def coverage(self, agent, content=FIXED):
        return {'summary': 'Adapted the count bound.', 'limitations': ['Source fixture only.'], 'coverage': [
            {'id': agent.units[0]['id'], 'status': 'implemented', 'explanation': 'Both limits implemented.',
             'evidence': [{'path': 'repo/counter.py', 'line_start': 1, 'line_end': 2, 'excerpt': content.strip()}]}]}

    def test_raw_input_needs_no_cve_source_commits_or_target_paths(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            result = agent.run(inspect_only=True)
            self.assertEqual(result['status'], 'DISCOVERED')
            report = json.loads((agent.run_dir / 'location.json').read_text())
            self.assertIn('repo/counter.py', [c['workspace_path'] for c in report['units'][0]['candidates']])
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertFalse(agent.workspace.exists())

    def test_file_and_function_rename_found_by_body_anchors(self):
        before = 'class Modern {\n int acceptCount(int requestedCount) {\n  return storage.queueCount(requestedCount);\n }\n}\n'
        target = before.replace('Modern', 'Legacy').replace('acceptCount', 'dispatchCount')
        after = before.replace('  return', '  if (requestedCount < 0) return 0;\n  return')
        with GitFixture() as fx:
            (fx.repo / 'OldGate.java').write_text(target)
            git(fx.repo, 'add', 'OldGate.java')
            git(fx.repo, 'commit', '-qm', 'old gateway')
            report = Locator(repositories(fx.repo), diff_units(diff('moved/NewGate.java', before, after))).locate()
            c = report['units'][0]['candidates'][0]
            self.assertEqual(c['path'], 'OldGate.java')
            self.assertTrue(any(w['function'] and w['function']['symbol'] == 'dispatchCount' for w in c['windows']))

    def test_duplicate_candidates_remain_ambiguous(self):
        with GitFixture() as fx:
            (fx.repo / 'copy.py').write_text(BASELINE)
            git(fx.repo, 'add', 'copy.py')
            git(fx.repo, 'commit', '-qm', 'second independent implementation')
            agent = self.agent(fx)
            report = Locator(agent.repos, agent.units).locate()
            self.assertEqual(report['units'][0]['status'], 'AMBIGUOUS_CANDIDATES')
            self.assertEqual({c['path'] for c in report['units'][0]['candidates']}, {'counter.py', 'copy.py'})

    def test_missing_is_unresolved_and_never_not_affected(self):
        with GitFixture() as fx:
            before = 'class QuantumThing {\n void fluxCapacitor() { entangledQuotas(); }\n}\n'
            after = before.replace('entangledQuotas();', 'validatedEntanglement();')
            agent = self.agent(fx, patch=diff('missing/QuantumThing.java', before, after))
            report = Locator(agent.repos, agent.units).locate()
            self.assertEqual(report['units'][0]['status'], 'UNRESOLVED')
            self.assertEqual(report['impact'], 'UNASSESSED')

    def test_truncated_search_is_recorded(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            report = Locator(agent.repos, agent.units, scan_limit=0).locate()
            self.assertTrue(any(i.get('status') == 'TRUNCATED' for i in report['issues']))

    def test_unknown_blocks_migration(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            assessment = self.assessment(agent, 'UNKNOWN')
            runtime = QueueRuntime([(assessment, None)])
            agent.factory = runtime.factory
            result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(len(runtime.calls), 1)
            self.assertFalse(agent.workspace.exists())

    def test_missing_unit_cannot_be_silently_skipped(self):
        with GitFixture() as fx:
            agent = self.agent(fx, patch=diff('new/metrics.py', BASELINE, FIXED) + diff('Other.py', BASELINE, FIXED))
            with self.assertRaisesRegex(AssessmentError, 'every diff unit'):
                agent.ground(self.assessment(agent))

    def test_exact_lines_and_diff_only_source_evidence(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            for origin in ('target', 'patch_after'):
                raw = self.assessment(agent)
                e = next(e for e in raw['units'][0]['evidence'] if e['origin'] == origin)
                e['line_start'], e['line_end'] = 2, 3
                with self.assertRaises(AssessmentError):
                    agent.ground(raw)

    def test_absence_requires_affirmative_entrypoint_evidence(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            raw = self.assessment(agent, 'NOT_AFFECTED')
            raw['units'][0]['absence_basis'] = 'feature_absent'
            with self.assertRaisesRegex(AssessmentError, 'two distinct'):
                agent.ground(raw)

    def test_already_fixed_stops_without_worktree(self):
        with GitFixture() as fx:
            git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
            agent = self.agent(fx)
            raw = self.assessment(agent, 'ALREADY_FIXED')
            raw['units'][0]['absence_basis'] = 'equivalent_protection'
            raw['units'][0]['evidence'][0]['excerpt'] = FIXED.strip()
            agent.factory = QueueRuntime([(raw, None)]).factory
            result = agent.run()
            self.assertEqual(result['status'], 'ALREADY_FIXED')
            self.assertFalse(agent.workspace.exists())

    def test_shared_rfcomm_security_record_cannot_prove_already_fixed(self):
        with GitFixture() as fx:
            target = 'def normalize_count(value):\n    rfcomm_security_records[scn] = sec_mask\n    return value\n'
            before = 'def normalize_count(value):\n    BTM_SetSecurityLevel(sec_mask)\n    return value\n'
            after = 'def normalize_count(value):\n    return value\n'
            (fx.repo / 'counter.py').write_text(target)
            git(fx.repo, 'add', 'counter.py')
            git(fx.repo, 'commit', '-qm', 'old shared rfcomm security record')
            agent = self.agent(fx, patch=diff('new/security.py', before, after))
            raw = self.assessment(agent, 'ALREADY_FIXED')
            raw['units'][0]['absence_basis'] = 'equivalent_protection'
            raw['units'][0]['targets'][0]['action'] = 'read_dependency'
            raw['units'][0]['targets'][0]['line_end'] = 3
            raw['units'][0]['evidence'][0]['line_end'] = 3
            raw['units'][0]['evidence'][0]['excerpt'] = target.strip()
            raw['units'][0]['evidence'][1]['excerpt'] = after.strip()
            with self.assertRaisesRegex(AssessmentError, 'shared only by SCN'):
                agent.ground(raw)

    def test_interior_function_mapping_is_normalized_to_symbol_boundary(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            raw = self.assessment(agent)
            raw['units'][0]['targets'][0]['line_start'] = 2
            raw['units'][0]['targets'][0]['line_end'] = 2
            self.assertEqual(agent.ground(raw)['writable_paths'], ['repo/counter.py'])

    def test_model_can_map_one_unit_to_split_functions(self):
        with GitFixture() as fx:
            (fx.repo / 'second.py').write_text(BASELINE.replace('normalize_count', 'normalize_other_count'))
            git(fx.repo, 'add', 'second.py')
            git(fx.repo, 'commit', '-qm', 'split old entry points')
            agent = self.agent(fx)
            raw = self.assessment(agent)
            t = copy.deepcopy(raw['units'][0]['targets'][0])
            t.update(path='repo/second.py', symbol='normalize_other_count', relationship='split')
            raw['units'][0]['targets'].append(t)
            e = copy.deepcopy(raw['units'][0]['evidence'][0])
            e.update(path=t['path'], excerpt=(fx.repo / 'second.py').read_text().strip())
            raw['units'][0]['evidence'].append(e)
            self.assertEqual(agent.ground(raw)['writable_paths'], ['repo/counter.py', 'repo/second.py'])

    def test_new_helper_requires_verified_existing_anchor(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            raw = self.assessment(agent)
            raw['new_files'] = [{'path': 'repo/helper.py', 'anchor_path': 'repo/counter.py', 'reason': 'Old API needs helper.'}]
            self.assertIn('repo/helper.py', agent.ground(raw)['writable_paths'])
            raw['new_files'][0]['anchor_path'] = 'repo/unrelated.py'
            with self.assertRaises(AssessmentError):
                agent.ground(raw)

    def test_grounded_migration_replays_and_remains_unverified(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            runtime = QueueRuntime([(self.assessment(agent), None),
                (self.coverage(agent), lambda cwd: (cwd / 'repo/counter.py').write_text(FIXED))])
            agent.factory = runtime.factory
            result = agent.run(verify=True)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(result['patch_replay'], 'pass')
            patch = Path(result['patches']['repo']['file']).read_text()
            self.assertIn('counter.py', patch)
            self.assertNotIn('new/metrics.py', patch)
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_configured_functional_regression_runs_on_candidate(self):
        with GitFixture() as fx:
            agent = self.agent(fx, validation={'repo': [[sys.executable, '-B', 'verify_contract.py']]})
            agent.factory = QueueRuntime([(self.assessment(agent), None),
                (self.coverage(agent), lambda cwd: (cwd / 'repo/counter.py').write_text(FIXED))]).factory
            result = agent.run(verify=True)
            self.assertEqual(result['status'], 'VALIDATED')
            self.assertIn('contract verified', result['verification']['repo']['commands'][0]['stdout'])

    def test_unmodified_excerpts_do_not_establish_migration_coverage(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            agent.factory = QueueRuntime([(self.assessment(agent), None), (self.coverage(agent, BASELINE), None)]).factory
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'MIGRATION_INCOMPLETE')
            self.assertNotEqual(result['patch_replay'], 'pass')

    def test_illegal_write_fails_and_original_is_preserved(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            agent.factory = QueueRuntime([(self.assessment(agent), None),
                (self.coverage(agent), lambda cwd: (cwd / 'repo/unrelated.py').write_text('x=1\n'))]).factory
            with self.assertRaisesRegex(RuntimeError, 'diff audit failed'):
                agent.run(max_attempts=1)
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_new_test_is_exported(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            assessment = self.assessment(agent)
            assessment['new_files'] = [{'path': 'repo/test_count.py', 'anchor_path': 'repo/counter.py', 'reason': 'Benign contract test.'}]
            def edit(cwd):
                (cwd / 'repo/counter.py').write_text(FIXED)
                (cwd / 'repo/test_count.py').write_text('from counter import normalize_count\nassert normalize_count(4) == 4\n')
            agent.factory = QueueRuntime([(assessment, None), (self.coverage(agent), edit)]).factory
            result = agent.run(max_attempts=1)
            self.assertIn('test_count.py', Path(result['patches']['repo']['file']).read_text())

    def test_discovery_does_not_follow_symlink_repository(self):
        with GitFixture() as fx:
            root = fx.root / 'only-links'
            root.mkdir()
            (root / 'linked').symlink_to(fx.repo, target_is_directory=True)
            with self.assertRaises(ValueError):
                repositories(root)

    def test_diff_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            diff_units(diff('../outside.py', BASELINE, FIXED))

    def test_added_deleted_and_metadata_units_are_kept(self):
        added = diff_units(diff('helper.py', '', FIXED))[0]
        deleted = diff_units(diff('helper.py', BASELINE, ''))[0]
        self.assertFalse(added['before'])
        self.assertEqual(added['after'][2], FIXED.splitlines()[1])
        self.assertFalse(deleted['after'])
        self.assertEqual(deleted['before'][2], BASELINE.splitlines()[1])
        unit = diff_units('diff --git a/old.xml b/new.xml\nsimilarity index 100%\nrename from old.xml\nrename to new.xml\n')[0]
        self.assertEqual(unit['kind'], 'whole_file')

    def test_function_ranges_ignore_comment_and_string_braces(self):
        java = 'class X {\n int oldName() {\n String s = "}"; // {\n return readCounter();\n }\n}\n'
        defs = functions(java, '.java')
        self.assertEqual([(d['symbol'], d['line_start'], d['line_end']) for d in defs], [('oldName', 2, 5)])

    def test_fabricated_function_name_is_rejected(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            raw = self.assessment(agent)
            raw['units'][0]['targets'][0]['symbol'] = 'inventedFunction'
            with self.assertRaisesRegex(AssessmentError, 'named function'):
                agent.ground(raw)

    def test_split_function_left_unmodified_is_incomplete(self):
        with GitFixture() as fx:
            (fx.repo / 'second.py').write_text(BASELINE)
            git(fx.repo, 'add', 'second.py')
            git(fx.repo, 'commit', '-qm', 'old split implementation')
            agent = self.agent(fx)
            raw = self.assessment(agent)
            target = copy.deepcopy(raw['units'][0]['targets'][0])
            target.update(path='repo/second.py', relationship='split')
            raw['units'][0]['targets'].append(target)
            evidence = copy.deepcopy(raw['units'][0]['evidence'][0])
            evidence['path'] = target['path']
            raw['units'][0]['evidence'].append(evidence)
            agent.factory = QueueRuntime([(raw, None),
                (self.coverage(agent), lambda cwd: (cwd / 'repo/counter.py').write_text(FIXED))]).factory
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'MIGRATION_INCOMPLETE')
            self.assertIn('repo/second.py', result['coverage_error'])

    def test_two_repositories_are_discovered_and_replayed_together(self):
        with GitFixture() as fx:
            second = fx.source_root / 'repo2'
            second.mkdir()
            git(second, 'init', '-q')
            (second / 'counter.py').write_text(BASELINE)
            git(second, 'add', '.')
            git(second, 'commit', '-qm', 'second baseline')
            path = fx.root / 'input.diff'
            path.write_text(diff('modern/one.py', BASELINE, FIXED) + diff('modern/two.py', BASELINE, FIXED))
            agent = DiffBackportAgent(path, fx.source_root, fx.run_root)
            raw = self.assessment(agent)
            unit = copy.deepcopy(raw['units'][0])
            unit['id'] = agent.units[1]['id']
            unit['targets'][0]['path'] = 'repo2/counter.py'
            unit['evidence'][0]['path'] = 'repo2/counter.py'
            unit['evidence'][1]['path'] = 'modern/two.py'
            raw['units'].append(unit)
            coverage = self.coverage(agent)
            cov = copy.deepcopy(coverage['coverage'][0])
            cov['id'] = agent.units[1]['id']
            cov['evidence'][0]['path'] = 'repo2/counter.py'
            coverage['coverage'].append(cov)
            def edit(cwd):
                for key in ('repo', 'repo2'):
                    (cwd / key / 'counter.py').write_text(FIXED)
            agent.factory = QueueRuntime([(raw, None), (coverage, edit)]).factory
            result = agent.run(max_attempts=1)
            self.assertEqual(set(result['patches']), {'repo', 'repo2'})
            self.assertTrue(all(p['replay'] == 'pass' for p in result['patches'].values()))
            self.assertEqual((second / 'counter.py').read_text(), BASELINE)

    def test_read_dependency_is_not_writable(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            raw = self.assessment(agent)
            target = {'path': 'repo/verify_contract.py', 'symbol': 'contract test', 'action': 'read_dependency',
                      'line_start': 1, 'line_end': 5, 'relationship': 'test', 'reason': 'Inspect existing contract.'}
            raw['units'][0]['targets'].append(target)
            raw['units'][0]['evidence'].append({'origin': 'target', 'path': target['path'], 'line_start': 1, 'line_end': 5,
                'excerpt': (fx.repo / 'verify_contract.py').read_text().strip(), 'claim': 'Independent normal-input checks.'})
            self.assertEqual(agent.ground(raw)['writable_paths'], ['repo/counter.py'])


if __name__ == '__main__':
    unittest.main()
