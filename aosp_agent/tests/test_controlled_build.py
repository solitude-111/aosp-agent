"""Prepared baseline/candidate wiring using real local Git transactions, no model."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import contextmanager
from dataclasses import replace

from aosp_agent.build_environment import validate_build_config, canonical_hash, BuildEnvironmentBlocked
from aosp_agent.controlled_build import controlled_build_session
from aosp_agent.joint_validation import verify_joint, finish_joint
from aosp_agent.delivery import update_delivery
from aosp_agent.project_first import ProjectFirstAgent
from engine_fixtures import GitFixture, BASELINE, git
from test_build_environment import config_for
import test_joint_validation as joint_fixtures


class ControlledBuildTest(unittest.TestCase):
    def controller(self, fx, *, baseline_code=0, candidate_code=0, stderr=''):
        fixture = joint_fixtures.JointValidationTest()
        runner = fixture.build_runner(fx)
        original = runner.read_text()
        # Both phases run a real process. Only candidate phase applies the
        # bundle through the production transaction/restore implementation.
        source = original.replace("if '--build-only' not in sys.argv:", f"""if '--baseline' in sys.argv:
    assert all((Path({str(fx.source_root)!r}) / key / 'counter.py').read_text() == {BASELINE!r} for key in ('repo', 'repo2'))
    marker.with_name('baseline-invocations').write_text('baseline')
    print('undefined module dependency' if {baseline_code} else 'baseline complete')
    raise SystemExit({baseline_code})
if '--build-only' not in sys.argv:""")
        source += f"\nprint({stderr!r}, file=sys.stderr)\nraise SystemExit({candidate_code})\n"
        runner.write_text(source)
        agent = fixture.controller(fx, runner=runner, prepare=True)
        check = {'stage': 'android_module_build', 'argv': [str(runner), 'module_repo', 'module_repo2'],
                 'covers': ['repo', 'repo2'], 'coverage': 'partial', 'artifacts': []}
        agent.joint_plan['checks'] = [check]
        config = config_for(fx); config['runner'] = str(runner)
        config = validate_build_config(config)
        prepared = SimpleNamespace(manager=SimpleNamespace(config={'build': config}),
            receipt_path=fx.root / 'preparation.json', environment={'source_root': str(fx.source_root),
                'project_pins': {'repo': fx.target, 'repo2': fx.target},
                'manifest': {'manifest_commit': 'a'*40}})
        prepared.materialize_all = lambda: prepared.environment
        agent.prepared_case = prepared
        agent.record.update(status='PATCH_UNVERIFIED', patches={key: {'sha256': child.record['patch_sha256']}
                                                               for key, child in agent.children.items()})
        return agent

    def test_unprepared_bundled_runner_blocks_before_any_build_or_candidate_repair(self):
        with GitFixture() as fx:
            fixture = joint_fixtures.JointValidationTest()
            agent = fixture.controller(fx, runner=Path(__file__).resolve().parents[2] / 'scripts/module-build-r760.sh', prepare=True)
            with patch('aosp_agent.joint_validation.run_check', side_effect=AssertionError('must not execute')):
                result = verify_joint(agent)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(result['blocked_by'], 'BUILD_ENVIRONMENT_BLOCKED')
            self.assertTrue(all(child.record['patch_sha256'] for child in agent.children.values()))

    def test_baseline_blocks_candidate_and_preserves_delivery(self):
        with GitFixture() as fx:
            agent = self.controller(fx, baseline_code=1)
            result = verify_joint(agent)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(result['blocked_by'], 'BUILD_ENVIRONMENT_BLOCKED')
            self.assertFalse((fx.root / 'build-invocations').exists())
            agent.record['joint_verification'] = result
            update_delivery(agent.record)
            self.assertEqual(agent.record['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(agent.record['delivery_status'], 'UNVERIFIED')
            self.assertEqual(agent.record['build_validation']['evidence_status'], 'BLOCKED')

    def test_successful_partial_build_uses_cached_baseline_but_rebuilds_candidate(self):
        with GitFixture() as fx:
            agent = self.controller(fx)
            first = verify_joint(agent)
            second = verify_joint(agent)
            self.assertEqual(first['status'], 'PASS')
            self.assertFalse(first['sufficient_for_validated'])
            self.assertTrue(second['commands'][0]['baseline']['cache_hit'])
            self.assertEqual((fx.root / 'build-invocations').read_text(), '2')
            self.assertEqual(first['commands'][0]['classification']['status'], 'PASS_PARTIAL')
            self.assertEqual(first['commands'][0]['source_restoration'], 'PASS')
            with patch('aosp_agent.joint_validation.assess_joint_impact'), \
                 patch('aosp_agent.joint_validation.verify_joint', return_value=second), \
                 patch('aosp_agent.candidate_store.archive_controller_candidates'):
                finish_joint(agent, verify=True)
            self.assertEqual(agent.record['android_module_build'], 'PARTIAL')
            self.assertEqual(agent.record['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(agent.record['delivery_status'], 'UNVERIFIED')

    def test_environment_failure_does_not_trigger_candidate_rewrite(self):
        for stderr, expected in [('No space left on device', 'HOST_RESOURCE_BLOCKED'),
                                 ('unrelated/other.cpp:4:2: error: invalid', 'BUILD_FAILURE_UNATTRIBUTED'),
                                 ('repo/counter.py:4:2: error: invalid', 'CANDIDATE_CODE_ERROR')]:
            with self.subTest(expected=expected), GitFixture() as fx:
                agent = self.controller(fx, candidate_code=1, stderr=stderr)
                result = verify_joint(agent)
                self.assertEqual(result['commands'][0]['classification']['status'], expected)
                self.assertEqual(result['status'], 'FAIL' if expected == 'CANDIDATE_CODE_ERROR' else 'BLOCKED')

    def test_outer_summary_keeps_environment_and_dependency_evidence(self):
        agent = ProjectFirstAgent.__new__(ProjectFirstAgent)
        agent.record = {'impact_decision': 'AFFECTED', 'impact_analysis': {'status': 'COMPLETED'},
                        'rounds': [{'record': '/fixture/round.json', 'projects': ['repo']}]}
        agent._save = lambda: update_delivery(agent.record)
        result = {'status': 'PATCH_UNVERIFIED', 'impact_decision': 'AFFECTED',
            'build_environment': {'environment_id': 'e'}, 'runtime_build_discovery': {'coverage': 'partial'},
            'dependency_evidence_revalidation': {'status': 'REQUIRED'},
            'completion_blocked_by': 'BUILD_ENVIRONMENT_BLOCKED', 'pause_batch': False}
        saved = agent._finish(result)
        for key in result:
            self.assertEqual(saved[key], result[key])

    def test_derived_view_rebinds_only_identical_dependency_trees_and_restores_original_pins(self):
        for change_tree in (False, True):
            with self.subTest(change_tree=change_tree), GitFixture() as fx:
                agent = self.controller(fx)
                dependency = agent.children['repo2']
                (dependency.worktree / 'counter.py').write_text(BASELINE)
                dependency.case = replace(dependency.case, files=())
                repo = dependency.repo
                git(repo, 'config', 'user.name', 'Fixture')
                git(repo, 'config', 'user.email', 'fixture@example.test')
                if change_tree:
                    (repo / 'counter.py').write_text(BASELINE + '\n# changed dependency tree\n')
                    git(repo, 'add', 'counter.py')
                git(repo, 'commit', '--allow-empty', '-qm', 'independent dependency revision')
                new_pin = git(repo, 'rev-parse', 'HEAD')
                git(repo, 'checkout', '--detach', '-q', fx.target)
                prepared = agent.prepared_case
                original = prepared.environment['project_pins']
                selected = {**original, 'repo2': new_pin}
                prepared.manager.config['build']['compatibility_mappings'] = [{
                    'id': 'fixture-fixed-release', 'target_vector_sha256': canonical_hash(original),
                    'validation_pins': selected, 'basis': 'explicit fixture manifest mapping'}]
                @contextmanager
                def view(pins):
                    git(repo, 'checkout', '--detach', '-q', pins['repo2'])
                    try:
                        yield {**prepared.environment, 'project_pins': pins, 'original_project_pins': original}
                    finally:
                        git(repo, 'checkout', '--detach', '-q', fx.target)
                prepared.validation_view = view
                if change_tree:
                    with self.assertRaisesRegex(BuildEnvironmentBlocked, 'impact-evidence revalidation'):
                        with controlled_build_session(agent):
                            self.fail('changed dependency must not be built using stale proof')
                    self.assertEqual(agent.record['dependency_evidence_revalidation']['invalidated_repositories'], ['repo2'])
                else:
                    with controlled_build_session(agent) as build:
                        build.audit()
                        self.assertEqual(build.identity['project_pins'], selected)
                        from aosp_agent.joint_validation import candidate_bundle
                        original_bundle = candidate_bundle(agent)
                        self.assertEqual(original_bundle['dependencies'][0]['target_commit'], fx.target)
                        self.assertEqual(build.validation_bundle(original_bundle)['dependencies'][0]['target_commit'], new_pin)
                    self.assertEqual(agent.record['dependency_evidence_revalidation']['status'], 'TREE_EQUIVALENT')
                self.assertEqual(git(repo, 'rev-parse', 'HEAD'), fx.target)
                self.assertEqual(dependency.case.target_commit, fx.target)
                agent._audit()


if __name__ == '__main__':
    unittest.main()
