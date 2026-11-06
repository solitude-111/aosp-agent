"""Partial discovery must preserve evidence and never certify missing scope."""
import copy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from aosp_agent import discovery
from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.engine import AssessmentError
from engine_fixtures import BASELINE, FIXED, GitFixture, git
import test_diff_workflow as workflow
import test_joint_validation as joint


class DiscoveryResilienceTest(unittest.TestCase):
    def peer(self, fx):
        repo = fx.source_root / 'unavailable'
        git(fx.source_root, 'clone', '-q', '--no-hardlinks', str(fx.repo), str(repo))
        return repo

    def unavailable(self, repo, calls=None):
        original = discovery.local_git
        def call(root, *args, **kwargs):
            if root == repo and args[0] == 'rev-parse':
                if calls is not None:
                    calls.append(args)
                raise subprocess.TimeoutExpired(['git', *args], kwargs.get('timeout', 45))
            return original(root, *args, **kwargs)
        return patch.object(discovery, 'local_git', side_effect=call)

    def agent(self, fx, **kwargs):
        return DiffBackportAgent(workflow.diff('new/metrics.py', BASELINE, FIXED).encode(),
                                 fx.source_root, fx.run_root, auto_validation=False, **kwargs)

    def test_unavailable_peer_does_not_discard_healthy_candidates(self):
        with GitFixture() as fx:
            peer = self.peer(fx)
            calls = []
            with self.unavailable(peer, calls):
                agent = self.agent(fx)
                result = agent.run(inspect_only=True)
            self.assertEqual(len(calls), 2)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['inventory_status'], 'INCOMPLETE')
            self.assertEqual(result['source_guard']['unavailable'], ['unavailable'])
            self.assertEqual(result['source_guard']['unavailable_integrity'], 'NOT_VERIFIED')
            location = json.loads((agent.run_dir / 'location.json').read_text())
            self.assertIn('repo/counter.py', [c['workspace_path'] for c in location['units'][0]['candidates']])
            inventory = json.loads((agent.run_dir / 'inventory.json').read_text())
            self.assertEqual({r['key']: r['status'] for r in inventory},
                             {'repo': 'AVAILABLE', 'unavailable': 'UNAVAILABLE'})
            self.assertEqual(location['issues'][0]['stage'], 'resolve_commit')

    def test_all_unavailable_is_durable_inconclusive_without_model(self):
        with GitFixture() as fx, self.unavailable(fx.repo):
            agent = self.agent(fx)
            result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['model_execution'], 'not_run')
            self.assertEqual(result['completion_blocked_by'], 'NO_AVAILABLE_REPOSITORIES')
            self.assertEqual(json.loads((agent.run_dir / 'run.json').read_text()), result)
            self.assertFalse(agent.workspace.exists())

    def test_required_pin_failure_is_recorded_and_never_substituted(self):
        with GitFixture() as fx, self.unavailable(fx.repo):
            with self.assertRaisesRegex(ValueError, 'pinned target repository is unavailable') as caught:
                self.agent(fx, pinned_heads={'repo': fx.target})
            from pathlib import Path
            record = json.loads(Path(caught.exception.record_path).read_text())
            self.assertEqual(record['status'], 'FAILED')
            self.assertEqual(record['error']['kind'], 'REPOSITORY_INITIALIZATION_ERROR')
            self.assertEqual(record['inventory_issues'][0]['repository'], 'repo')
            self.assertEqual(record['model_execution'], 'not_run')

    def test_progress_exists_before_first_object_read(self):
        with GitFixture() as fx:
            original = discovery.local_git
            def read(root, *args, **kwargs):
                records = list(fx.run_root.glob('*/run.json'))
                self.assertEqual(len(records), 1)
                self.assertEqual(json.loads(records[0].read_text())['status'], 'INITIALIZING')
                self.assertTrue((records[0].parent / 'inventory-progress.json').exists())
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=read):
                self.agent(fx)

    def test_guard_failure_quarantines_peer_and_preserves_healthy_guards(self):
        with GitFixture() as fx:
            peer = self.peer(fx)
            original = discovery.Repository.state
            def state(repo, **kwargs):
                if repo.root == peer:
                    raise subprocess.TimeoutExpired(['git', 'status'], 10)
                return original(repo, **kwargs)
            with patch.object(discovery.Repository, 'state', state):
                agent = self.agent(fx)
            self.assertEqual(agent.record['inventory_issues'][0]['stage'], 'source_guard')
            (fx.repo / 'counter.py').write_text(FIXED)
            with self.assertRaisesRegex(RuntimeError, 'original repository changed'):
                agent._originals_unchanged()

    def test_unavailable_repository_cannot_be_a_mapped_dependency(self):
        with GitFixture() as fx:
            with self.unavailable(self.peer(fx)):
                agent = self.agent(fx)
            raw = workflow.DiffWorkflowTest().assessment(agent)
            target = copy.deepcopy(raw['units'][0]['targets'][0])
            target.update(path='unavailable/counter.py', action='read_dependency', relationship='dependency')
            raw['units'][0]['targets'].append(target)
            with self.assertRaisesRegex(AssessmentError, 'does not belong'):
                agent.ground(raw)
            self.assertFalse(agent.workspace.exists())

    def test_partial_scope_cannot_certify_already_fixed(self):
        with GitFixture() as fx:
            git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
            with self.unavailable(self.peer(fx)):
                agent = self.agent(fx)
            raw = workflow.DiffWorkflowTest().assessment(agent, 'ALREADY_FIXED')
            raw['units'][0]['absence_basis'] = 'equivalent_protection'
            raw['units'][0]['evidence'][0]['excerpt'] = FIXED.strip()
            from test_exclusion_review import ExclusionReviewTest
            reviewer = ExclusionReviewTest()
            reviewer.wire(agent, [raw], [reviewer.review(agent, 'CONFIRMED_PROTECTED')])
            result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(result['available_scope_impact'], 'ALREADY_FIXED')

    def test_two_repo_joint_pass_does_not_hide_unavailable_third_repo(self):
        for build in (False, True):
          with self.subTest(build=build), GitFixture() as fx:
            helper = joint.JointValidationTest()
            checker = helper.script(fx, 'joint.py',
                f'from pathlib import Path\nassert all(Path(k, "counter.py").read_text() == {FIXED!r} for k in ("repo", "repo2"))\n')
            runner = helper.build_runner(fx) if build else None
            validation = {k: ([{'stage': 'android_module_build', 'argv': [str(runner), 'module_' + k]}]
                             if build else [[sys.executable, '-B', 'verify_contract.py']]) for k in ('repo', 'repo2')}
            with self.unavailable(self.peer(fx)):
                agent = helper.controller(fx, joint=[[sys.executable, str(checker)]], runner=runner,
                    validation=validation)
            result = agent.run(verify=True, max_attempts=1)
            self.assertEqual(result['combined_verification'], 'PASS')
            self.assertEqual(set(result['patches']), {'repo', 'repo2'})
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(result['completion_blocked_by'], 'INCOMPLETE_REPOSITORY_INVENTORY')
            self.assertEqual(result['available_scope_status'], 'VALIDATED' if build else 'PATCH_UNVERIFIED')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertEqual((fx.source_root / 'repo2/counter.py').read_text(), BASELINE)

    def test_identifier_timeout_is_not_retried_for_every_unit(self):
        with GitFixture() as fx:
            repos = discovery.repositories(fx.repo)
            units = discovery.diff_units(workflow.diff('one.py', BASELINE, FIXED) +
                                         workflow.diff('two.py', BASELINE, FIXED))
            original, calls = discovery.local_git, []
            def read(root, *args, **kwargs):
                if args[0] == 'grep':
                    calls.append(args)
                    raise subprocess.TimeoutExpired(['git', *args], 10)
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=read):
                report = discovery.Locator(repos, units).locate()
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(report['issues']), 2)
            self.assertTrue(all(i['stage'] == 'identifier_search' for i in report['issues']))

    def test_blob_failure_is_cached_across_units(self):
        with GitFixture() as fx:
            repo = discovery.repositories(fx.repo)[0]
            locator = discovery.Locator([repo], [])
            with patch.object(repo, 'read', side_effect=subprocess.TimeoutExpired(['git', 'show'], 45)) as read:
                for _ in range(2):
                    with self.assertRaises((subprocess.TimeoutExpired, ValueError)):
                        locator.read(repo, 'counter.py')
                self.assertEqual(read.call_count, 1)

    def test_existing_diagnostics_are_not_overwritten_by_second_constructor(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            before = (agent.run_dir / 'run.json').read_bytes()
            with self.assertRaises(FileExistsError):
                self.agent(fx)
            self.assertEqual((agent.run_dir / 'run.json').read_bytes(), before)

    def test_run_root_inside_original_is_rejected_without_writes(self):
        with GitFixture() as fx:
            with self.assertRaisesRegex(ValueError, 'outside original target root'):
                DiffBackportAgent(workflow.diff('counter.py', BASELINE, FIXED).encode(), fx.repo, fx.repo / 'runs')
            self.assertFalse((fx.repo / 'runs').exists())

    def test_configuration_failure_does_not_leave_initializing_record(self):
        with GitFixture() as fx:
            with self.assertRaisesRegex(ValueError, 'validation must be an object'):
                self.agent(fx, validation=[])
            record = json.loads(next(fx.run_root.glob('*/run.json')).read_text())
            self.assertEqual(record['status'], 'FAILED')
            self.assertEqual(record['model_execution'], 'not_run')

    def test_metadata_diagnostic_does_not_claim_missing_objects_or_run_git(self):
        with GitFixture() as fx:
            directory = fx.repo / '.git/objects/pack'
            for number in range(1025):
                (directory / f'pack-{number}.pack').touch()
            with patch.object(discovery, 'local_git', side_effect=AssertionError('diagnostic must not run Git')):
                report = discovery.object_store_diagnostic(fx.repo)
                bounded = discovery.object_store_diagnostic(fx.repo, limit=10)
            self.assertEqual(report['pack_files'], 1025)
            self.assertEqual(report['maintenance_hint'], 'MANY_PACK_FILES')
            self.assertEqual(report['object_completeness'], 'NOT_CHECKED')
            self.assertTrue(bounded['truncated'])

    def test_object_search_failure_after_inventory_cannot_certify_absence(self):
        with GitFixture() as fx:
            git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
            agent = self.agent(fx)
            raw = workflow.DiffWorkflowTest().assessment(agent, 'ALREADY_FIXED')
            raw['units'][0]['absence_basis'] = 'equivalent_protection'
            raw['units'][0]['evidence'][0]['excerpt'] = FIXED.strip()
            from test_exclusion_review import ExclusionReviewTest
            reviewer = ExclusionReviewTest()
            reviewer.wire(agent, [raw], [reviewer.review(agent, 'CONFIRMED_PROTECTED')])
            original = discovery.local_git
            def read(root, *args, **kwargs):
                if args[0] == 'grep':
                    raise subprocess.TimeoutExpired(['git', 'grep'], 10)
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=read):
                result = agent.run()
            self.assertEqual(result['inventory_status'], 'COMPLETE')
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(result['completion_blocked_by'], 'INCOMPLETE_OBJECT_RETRIEVAL')
