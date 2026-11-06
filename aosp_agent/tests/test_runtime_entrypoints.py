from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from aosp_agent.mapped_run import from_case
from aosp_agent.project_first import ProjectFirstAgent
from aosp_agent.runtime_batch import RuntimeBatch
from engine_fixtures import GitFixture, git, BASELINE, FIXED, ScriptedRuntime, write_counter
from test_diff_workflow import diff, QueueRuntime
import test_project_first as routing_fixtures


ORIGIN = 'https://android.googlesource.com/platform/repo'


def manifest(fx):
    root = fx.source_root / '.repo/manifests'; root.mkdir(parents=True)
    git(root, 'init', '-q')
    (root / 'default.xml').write_text('<manifest><project name="platform/repo" path="repo" revision="' + fx.target + '"/>'
        '<project name="platform/unused" path="unused" revision="missing-objects"/></manifest>')
    git(root, 'add', '.'); git(root, 'commit', '-qm', 'fixed release')
    git(root, 'tag', 'release-target')
    broken = fx.source_root / 'unused'; broken.mkdir(); (broken / '.git').write_text('gitdir: unavailable\n')
    return root


def row(fx, **changes):
    return dict({'source_commit_sequence': [fx.donor], 'source_parent_sequence': [fx.target],
                 'donor_repositories': [ORIGIN], 'target_revision': 'release-target'}, **changes)


class RuntimeEntrypointsTest(unittest.TestCase):
    def test_cleanup_failure_blocks_mapped_backend_and_remaining_batch_rows(self):
        from aosp_agent.validation_process import VerifierCleanupBlocked
        with GitFixture() as fx:
            manifest(fx)
            path = fx.root / 'input.jsonl'
            path.write_text(json.dumps(row(fx)) + '\n' + json.dumps(row(fx)))
            mapping = QueueRuntime([(routing_fixtures.ProjectFirstTest().assessment(), None)])
            backend = ScriptedRuntime(fx.assessment(), [write_counter(FIXED)])
            def factory(**kwargs):
                return mapping if Path(kwargs['events_path']).name == 'sdk-assessment.jsonl' else backend
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={ORIGIN: str(fx.repo)}, runtime_factory=factory,
                agent_options={'repository_keys': ['repo'], 'auto_validation': False,
                               'validation': {'repo': [[sys.executable, '-B', 'verify_contract.py']]}})
            with patch('aosp_agent.engine.run_check', side_effect=VerifierCleanupBlocked('unverified group')):
                result = runner.run(verify=True, max_attempts=1)
            self.assertEqual(result['status'], 'BLOCKED', result)
            self.assertEqual(len(result['rows']), 1)
            self.assertEqual(result['rows'][0]['completion_blocked_by'], 'VERIFIER_CLEANUP_UNVERIFIED')
            self.assertFalse((runner.run_dir / 'row-0002').exists())
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-m', 'aosp_agent', *map(str, args)], capture_output=True, text=True)

    def test_default_diff_inspection_is_project_first_and_starts_no_model(self):
        with GitFixture() as fx:
            patch = fx.root / 'input.patch'; patch.write_text(diff('counter.py', BASELINE, FIXED))
            result = self.cli('diff', '--patch', patch, '--target-root', fx.repo, '--run-root', fx.run_root, '--inspect-only')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            summary = json.loads(result.stdout)
            self.assertEqual(summary['execution_path'], 'project_first')
            record = json.loads(Path(summary['record']).read_text())
            self.assertEqual(record['model_turns']['used'], 0)
            self.assertEqual(record['analysis_scope']['mode'], 'explicit_projects')

    def test_unknown_multi_project_inspection_requests_scope_without_full_scan(self):
        with GitFixture() as fx:
            broken = fx.source_root / 'unused'; broken.mkdir(); (broken / '.git').write_text('gitdir: missing\n')
            patch = fx.root / 'input.patch'; patch.write_text(diff('counter.py', BASELINE, FIXED))
            result = self.cli('diff', '--patch', patch, '--target-root', fx.source_root, '--run-root', fx.run_root, '--inspect-only')
            self.assertEqual(result.returncode, 4, result.stderr + result.stdout)
            summary = json.loads(result.stdout)
            self.assertEqual(summary['completion_blocked_by'], 'INSPECTION_REQUIRES_PROJECT_SCOPE')
            record = json.loads(Path(summary['record']).read_text())
            self.assertEqual(record['model_turns']['used'], 0)
            self.assertEqual(record['rounds'], [])

    def test_default_run_ignores_answer_fields_and_retains_real_backend_validation(self):
        with GitFixture() as fx:
            case = replace(fx.case(), files=('SECRET_ANSWER_PATH.py',), validation=(('ANSWER_CHECK',),))
            routing = QueueRuntime([(routing_fixtures.ProjectFirstTest().plan(), None)])
            mapping = QueueRuntime([(routing_fixtures.ProjectFirstTest().assessment(), None)])
            backend = ScriptedRuntime(fx.assessment(), [write_counter(FIXED)])
            def factory(**kwargs):
                name = Path(kwargs['events_path']).name
                return routing if name.startswith('sdk-routing-') else mapping if name == 'sdk-assessment.jsonl' else backend
            agent = from_case(case, fx.source_root, fx.run_root, runtime_factory=factory, auto_validation=False,
                              validation={'repo': [[sys.executable, '-B', 'verify_contract.py']]})
            self.assertIsInstance(agent, ProjectFirstAgent)
            result = agent.run(verify=True)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)
            prompts = '\n'.join(c['prompt'] for runtime in (routing, mapping, backend) for c in runtime.calls)
            self.assertNotIn('SECRET_ANSWER_PATH', prompts)
            self.assertNotIn('ANSWER_CHECK', prompts)
            self.assertEqual(result['execution_path'], 'project_first')
            child = json.loads((agent.run_dir / 'rounds/r01/repositories/repo/run.json').read_text())
            self.assertTrue(child['assessment']['causal_chain'])
            self.assertEqual(child['hunk_results'][0]['status'], 'implemented')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_default_run_inspection_does_not_read_unselected_broken_repository(self):
        with GitFixture() as fx:
            broken = fx.source_root / 'unused'; broken.mkdir(); (broken / '.git').write_text('gitdir: missing\n')
            agent = from_case(fx.case(), fx.source_root, fx.run_root,
                              runtime_factory=lambda **kw: self.fail('inspection started a model'))
            result = agent.run(inspect_only=True)
            self.assertEqual(result['status'], 'DISCOVERED', result)
            self.assertEqual(result['selected_projects'], ['repo'])

    def test_jsonl_rows_are_isolated_and_duplicate_inputs_are_not_dropped(self):
        with GitFixture() as fx:
            manifest(fx)
            path = fx.root / 'input.jsonl'
            path.write_text('\n'.join(json.dumps(r) for r in (row(fx), row(fx, source_commit_sequence=['deadbeef']), row(fx))))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors', donor_map={ORIGIN: str(fx.repo)},
                                  runtime_factory=lambda **kw: self.fail('inspection started a model'))
            result = runner.run(inspect_only=True)
            self.assertEqual(result['status'], 'COMPLETED')
            self.assertEqual([r['status'] for r in result['rows']], ['DISCOVERED', 'INPUT_UNRESOLVED', 'DISCOVERED'])
            self.assertEqual([r['line'] for r in result['rows']], [1, 2, 3])
            self.assertEqual(result['rows'][0]['input_task_id'], result['rows'][2]['input_task_id'])
            self.assertNotEqual(result['rows'][0]['record'], result['rows'][2]['record'])
            self.assertGreater(result['rows'][2]['object_cache']['hits'], 0)
            self.assertEqual(result['rows'][0]['pinned_targets']['repo']['head'], fx.target)
            self.assertTrue(Path(result['rows'][1]['record']).is_file())

    def test_jsonl_invalid_line_and_missing_release_cannot_fall_back_to_head(self):
        with GitFixture() as fx:
            manifest(fx)
            path = fx.root / 'input.jsonl'
            path.write_text('bad json\n' + json.dumps(row(fx, target_revision='missing-release')) + '\n' + json.dumps(row(fx)))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors', donor_map={ORIGIN: str(fx.repo)})
            result = runner.run(inspect_only=True)
            self.assertEqual([r['status'] for r in result['rows']], ['FAILED', 'FAILED', 'DISCOVERED'])
            self.assertNotIn('pinned_targets', result['rows'][1])

    def test_jsonl_cli_creates_independent_row_records(self):
        with GitFixture() as fx:
            manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text(json.dumps(row(fx)))
            mapping = fx.root / 'donors.json'; mapping.write_text(json.dumps({ORIGIN: str(fx.repo)}))
            result = self.cli('batch', '--input', path, '--target-root', fx.source_root, '--run-root', fx.run_root,
                              '--donor-root', fx.root / 'donors', '--donor-map', mapping, '--inspect-only')
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            summary = json.loads(result.stdout)
            self.assertEqual(summary['counts'], {'DISCOVERED': 1})
            self.assertTrue(Path(summary['record']).is_file())

    def test_single_source_jsonl_retains_causal_run_backend(self):
        with GitFixture() as fx:
            manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text(json.dumps(row(fx)))
            routing = QueueRuntime([(routing_fixtures.ProjectFirstTest().plan(), None)])
            mapping = QueueRuntime([(routing_fixtures.ProjectFirstTest().assessment(), None)])
            backend = ScriptedRuntime(fx.assessment(), [write_counter(FIXED)])
            def factory(**kwargs):
                name = Path(kwargs['events_path']).name
                return routing if name.startswith('sdk-routing-') else mapping if name == 'sdk-assessment.jsonl' else backend
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={ORIGIN: str(fx.repo)}, runtime_factory=factory,
                agent_options={'auto_validation': False, 'validation': {'repo': [[sys.executable, '-B', 'verify_contract.py']]}})
            result = runner.run(verify=True)
            self.assertEqual(result['rows'][0]['status'], 'PATCH_UNVERIFIED', result)
            child = json.loads((runner.run_dir / 'row-0001/execution/rounds/r01/repositories/repo/run.json').read_text())
            self.assertTrue(child['assessment']['causal_chain'])
            self.assertEqual(child['hunk_results'][0]['status'], 'implemented')

    def test_multi_source_jsonl_keeps_every_step_in_inspection(self):
        with GitFixture() as fx:
            manifest(fx)
            git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
            (fx.repo / 'counter.py').write_text(FIXED.replace('10', '9'))
            git(fx.repo, 'commit', '-qam', 'adjust bound')
            second = git(fx.repo, 'rev-parse', 'HEAD')
            git(fx.repo, 'checkout', '--detach', '-q', fx.target)
            path = fx.root / 'input.jsonl'
            path.write_text(json.dumps(row(fx, source_commit_sequence=[fx.donor, second],
                                            source_parent_sequence=[fx.target, fx.donor])))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors', donor_map={ORIGIN: str(fx.repo)})
            result = runner.run(inspect_only=True)
            self.assertEqual(result['rows'][0]['status'], 'DISCOVERED', result)
            inspection = json.loads((runner.run_dir / 'row-0001/execution/rounds/r01/inspection.json').read_text())
            self.assertEqual({u['id'] for u in inspection['hunks']}, {'s001:f001-h001', 's002:f001-h001'})
            self.assertEqual(result['rows'][0]['source_provenance']['dependency_edges'],
                             [{'before': 's001', 'after': 's002', 'basis': 'direct_parent'}])
