# Executor regression fixtures explicitly select the legacy exhaustive adapter.
# Default project-first entrypoints are covered by test_runtime_entrypoints.py.
import copy
import json
import os
from pathlib import Path
import sys
import unittest

from aosp_agent.joint_validation import verify_joint, assess_joint_impact
from aosp_agent.mapped_run import from_case
from engine_fixtures import BASELINE, FIXED, PARTIAL, GitFixture, ScriptedRuntime, git, write_counter
import test_diff_workflow as diff_fixtures


class JointValidationTest(unittest.TestCase):
    def review(self):
        return {'overall_risk': 'low', 'affected_callers': [], 'behavior_changes': [],
                'compatibility_risks': [], 'performance_notes': [], 'test_recommendations': [],
                'reasoning': 'Ordinary two-repository candidate review.'}

    def test_successful_generic_joint_checks_do_not_cover_required_production_builds(self):
        with GitFixture() as fx:
            script = self.script(fx, 'noop.py', 'pass\n')
            agent = self.controller(fx, joint=[[sys.executable, str(script)]], prepare=True)
            result = verify_joint(agent)
            self.assertEqual(result['status'], 'PASS')
            self.assertFalse(result['sufficient_for_validated'])
            self.assertEqual(result['uncovered_repositories'], ['repo', 'repo2'])

    def test_review_rechecks_unchanged_peer_when_final_bundle_changes(self):
        with GitFixture() as fx:
            agent = self.controller(fx, prepare=True)
            runtimes = {}
            for key, child in agent.children.items():
                runtimes[key] = diff_fixtures.QueueRuntime([(self.review(), None), (self.review(), None)])
                child.runtime_factory = runtimes[key].factory
            assess_joint_impact(agent)
            first = agent.record['post_fix_review']['bundle_sha256']
            assess_joint_impact(agent)  # Same successfully reviewed vector is reusable.
            self.assertTrue(all(len(r.calls) == 1 for r in runtimes.values()))
            peer = agent.children['repo2']
            (peer.worktree / 'counter.py').write_text(FIXED.replace('max(0, min(value, 10))', 'min(10, max(value, 0))'))
            peer.export_patch(2)
            assess_joint_impact(agent)
            self.assertNotEqual(first, agent.record['post_fix_review']['bundle_sha256'])
            self.assertTrue(all(len(r.calls) == 2 for r in runtimes.values()))
            self.assertEqual(agent.record['post_fix_review']['status'], 'COMPLETED')

    def test_failed_review_is_explicit_and_not_reused_as_success(self):
        with GitFixture() as fx:
            agent = self.controller(fx, prepare=True)
            runtimes = {}
            for key, child in agent.children.items():
                runtimes[key] = diff_fixtures.QueueRuntime([({}, None)])
                child.runtime_factory = runtimes[key].factory
            assess_joint_impact(agent)
            self.assertEqual(agent.record['post_fix_review']['status'], 'INCOMPLETE')
            self.assertEqual(set(agent.record['post_fix_review']['repositories'].values()), {'FAILED'})
            for runtime in runtimes.values(): runtime.replies.append((self.review(), None))
            assess_joint_impact(agent)
            self.assertEqual(agent.record['post_fix_review']['status'], 'COMPLETED')
            self.assertTrue(all(len(r.calls) == 2 for r in runtimes.values()))

    def script(self, fx, name, source):
        path = fx.root / name
        path.write_text(f'#!{sys.executable}\n' + source)
        path.chmod(0o700)
        return path

    def controller(self, fx, *, validation=None, joint=None, runner=None, prepare=False):
        second = fx.source_root / 'repo2'
        git(fx.source_root, 'clone', '-q', '--no-hardlinks', str(fx.repo), str(second))
        git(second, 'checkout', '--detach', '-q', fx.target)
        agent = from_case(fx.case(), fx.source_root, fx.run_root, auto_validation=False,
                          validation=validation, joint_validation=joint, build_runner=runner, exhaustive_discovery=True)
        raw = diff_fixtures.DiffWorkflowTest().assessment(agent)
        target = copy.deepcopy(raw['units'][0]['targets'][0])
        target['path'] = 'repo2/counter.py'
        raw['units'][0]['targets'].append(target)
        evidence = copy.deepcopy(raw['units'][0]['evidence'][0])
        evidence['path'] = target['path']
        raw['units'][0]['evidence'].append(evidence)
        mapping = diff_fixtures.QueueRuntime([(raw, None)])
        backends = {key: ScriptedRuntime(fx.assessment(), [write_counter(FIXED)]) for key in ('repo', 'repo2')}
        def factory(**kwargs):
            path = Path(kwargs['events_path'])
            return mapping if path.name == 'sdk-assessment.jsonl' else backends[path.parent.name]
        agent.factory = factory
        if prepare:
            agent._prepare_children(agent.ground(raw))
            for child in agent.children.values():
                write_counter(FIXED)(child.worktree)
                child.export_patch(1)
        return agent

    def build_runner(self, fx, stale_second=False):
        project = str(Path(__file__).resolve().parents[2])
        marker = fx.root / 'build-invocations'
        return self.script(fx, 'module_runner.py', f'''import json, os, sys
from pathlib import Path
sys.path.insert(0, {project!r})
from aosp_agent.build_transaction import transaction
marker = Path({str(marker)!r})
if '--build-only' not in sys.argv:
    if {stale_second!r} and marker.exists():
        raise SystemExit(0)
    raise SystemExit(transaction({str(fx.source_root)!r}, {str(fx.root / 'shared.lock')!r},
        [sys.executable, __file__, '--build-only', *sys.argv[1:]]))
bundle = json.loads(Path(os.environ['AOSP_AGENT_PATCH_BUNDLE']).read_text())
assert Path.cwd() == Path(os.environ['AOSP_AGENT_WORKTREE'])
assert all((Path.cwd() / key / 'counter.py').read_text() == {FIXED!r} for key in ('repo', 'repo2'))
assert len(bundle['repositories']) == 2
assert all((Path(e['target_repo']) / 'counter.py').read_text() == {FIXED!r} for e in bundle['repositories'])
marker.write_text(str(int(marker.read_text()) + 1) if marker.exists() else '1')
artifacts = Path(os.environ['AOSP_AGENT_ARTIFACT_DIR'])
artifacts.mkdir(parents=True, exist_ok=True)
(artifacts / 'modules.txt').write_text(','.join(sorted(sys.argv[2:])))
''')

    def test_module_build_is_deferred_coalesced_and_validates_the_whole_bundle(self):
        with GitFixture() as fx:
            runner = self.build_runner(fx)
            validation = {key: [{'stage': 'android_module_build', 'argv': [str(runner), 'module_' + key],
                                 'artifacts': ['out-artifacts/modules.txt']}] for key in ('repo', 'repo2')}
            agent = self.controller(fx, validation=validation, runner=runner)
            result = agent.run(verify=True, max_attempts=1)
            self.assertEqual(result['status'], 'VALIDATED', result)
            self.assertEqual(result['combined_verification'], 'PASS')
            self.assertEqual(result['android_module_build'], 'PASS')
            self.assertTrue(all(c.record['post_fix_impact']['overall_risk'] == 'low' for c in agent.children.values()))
            self.assertEqual((fx.root / 'build-invocations').read_text(), '1')
            self.assertEqual((agent.run_dir / 'joint-artifacts/modules.txt').read_text(), 'module_repo,module_repo2')
            self.assertEqual(len(result['joint_verification']['commands']), 1)
            for child in agent.children.values():
                self.assertNotIn('android_module_build', [c['stage'] for c in child.case.validation_checks])
                self.assertEqual((child.repo / 'counter.py').read_text(), BASELINE)
                self.assertEqual(git(child.repo, 'status', '--porcelain'), '')

    def test_explicit_joint_functional_check_can_fail_after_local_success(self):
        for passing in (True, False):
            with self.subTest(passing=passing), GitFixture() as fx:
                checker = self.script(fx, 'joint_check.py',
                    f'from pathlib import Path\nassert all(Path(k, "counter.py").read_text() == {FIXED!r} for k in ("repo", "repo2"))\nraise SystemExit({0 if passing else 7})\n')
                validation = {key: [[sys.executable, '-B', 'verify_contract.py']] for key in ('repo', 'repo2')}
                agent = self.controller(fx, validation=validation, joint=[[sys.executable, str(checker)]])
                result = agent.run(verify=True, max_attempts=1)
                self.assertEqual(result['status'], 'PATCH_UNVERIFIED' if passing else 'VALIDATION_FAILED')
                self.assertEqual(result['joint_verification']['commands'][0]['returncode'], 0 if passing else 7)
                self.assertEqual(len(result['patches']), 2)

    def test_without_verify_neither_joint_checker_nor_builder_runs(self):
        with GitFixture() as fx:
            checker = self.script(fx, 'must_not_run.py', 'raise AssertionError("must not run")\n')
            agent = self.controller(fx, joint=[[sys.executable, str(checker)]])
            result = agent.run(verify=False, max_attempts=1)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(result['joint_verification']['status'], 'NOT_REQUESTED')

    def test_local_pass_cache_is_invalidated_when_a_dependency_patch_changes(self):
        with GitFixture() as fx:
            checker = self.script(fx, 'depends_on_second.py', '''import os
from pathlib import Path
workspace = Path(os.environ['AOSP_AGENT_WORKTREE']).parent
assert 'min(value' in (workspace / 'repo2/counter.py').read_text(), 'other candidate lost its bound'
''')
            joint = self.script(fx, 'joint.py', 'pass\n')
            agent = self.controller(fx, validation={'repo': [[sys.executable, str(checker)]]},
                                    joint=[[sys.executable, str(joint)]], prepare=True)
            self.assertEqual(verify_joint(agent)['status'], 'PASS')
            child = agent.children['repo2']
            write_counter(PARTIAL)(child.worktree)
            child.export_patch(2)
            result = verify_joint(agent)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['blocked_by'], 'FINAL_LOCAL_CHECK')
            self.assertEqual(result['repository'], 'repo')
            self.assertFalse(agent.children['repo'].record['final_verification']['commands'][0].get('skipped_passed'))

    def test_fresh_bundle_receipt_required_even_if_runner_returns_zero(self):
        with GitFixture() as fx:
            runner = self.build_runner(fx, stale_second=True)
            validation = {key: [{'stage': 'android_module_build', 'argv': [str(runner), 'module_' + key]}]
                          for key in ('repo', 'repo2')}
            agent = self.controller(fx, validation=validation, runner=runner, prepare=True)
            self.assertEqual(verify_joint(agent)['status'], 'PASS')
            result = verify_joint(agent)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['commands'][0]['returncode'], 125)
            self.assertIn('fresh successful', result['commands'][0]['stderr'])

    def test_changed_unexported_candidate_never_reaches_joint_checker(self):
        with GitFixture() as fx:
            checker = self.script(fx, 'must_not_run.py', 'raise AssertionError("must not run")\n')
            agent = self.controller(fx, joint=[[sys.executable, str(checker)]], prepare=True)
            write_counter(PARTIAL)(agent.children['repo2'].worktree)
            with self.assertRaisesRegex(ValueError, 'changed after export'):
                verify_joint(agent)

    def test_stale_joint_artifact_cannot_satisfy_a_new_check(self):
        with GitFixture() as fx:
            checker = self.script(fx, 'artifact_once.py', '''import os
from pathlib import Path
run = Path(os.environ['AOSP_AGENT_RUN_DIR'])
marker = run / 'artifact-created'
if not marker.exists():
    out = Path(os.environ['AOSP_AGENT_ARTIFACT_DIR'])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'result.txt').write_text('first check')
    marker.touch()
''')
            agent = self.controller(fx, joint=[{'stage': 'configured', 'argv': [sys.executable, str(checker)],
                'artifacts': ['joint-artifacts/result.txt']}], prepare=True)
            self.assertEqual(verify_joint(agent)['status'], 'PASS')
            result = verify_joint(agent)
            self.assertEqual(result['status'], 'FAIL')
            self.assertIn('missing joint artifact', result['commands'][0]['stderr'])
            self.assertEqual((agent.run_dir / 'previous-joint-artifacts/2-1/joint-artifacts/result.txt').read_text(), 'first check')

    def test_partial_build_coverage_does_not_validate_the_bundle(self):
        with GitFixture() as fx:
            runner = self.build_runner(fx)
            agent = self.controller(fx, validation={'repo': [{'stage': 'android_module_build',
                'argv': [str(runner), 'module_repo']}]}, runner=runner, prepare=True)
            result = verify_joint(agent)
            self.assertEqual(result['status'], 'PASS')
            self.assertFalse(result['sufficient_for_validated'])
            self.assertEqual(result['uncovered_repositories'], ['repo2'])

    def test_artifact_directory_escape_is_rejected_before_checker(self):
        with GitFixture() as fx:
            checker = self.script(fx, 'must_not_run.py', 'raise AssertionError("must not run")\n')
            agent = self.controller(fx, joint=[[sys.executable, str(checker)]], prepare=True)
            (agent.run_dir / 'joint-artifacts').symlink_to(fx.repo, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'unsafe joint artifact'):
                verify_joint(agent)
