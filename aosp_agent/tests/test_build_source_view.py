"""Source-view integration contracts with real Git; kernel proofs are mocked.

The source-base/provider tests exercise a simulated kernel verification boundary.
These tests prove that the build consumer requires that provider, audits writable
repositories, and never converts source reuse into stale build PASS evidence.
"""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from aosp_agent.build_environment import (_source_snapshot, canonical_hash,
    environment_identity, run_baseline)
from aosp_agent.controlled_build import controlled_build_session
from aosp_agent.discovery import local_git
from aosp_agent.lifecycle import RecoveryBlocked
from engine_fixtures import GitFixture, git
from test_build_environment import config_for
import test_controlled_build


VERIFY = 'aosp_agent.preparation.verify_active_source_view'


def descriptor(vector, writable):
    return {'version': 1, 'base_id': 'b' * 64, 'base_receipt_sha256': 'c' * 64,
            'base_vector_sha256': canonical_hash(vector),
            'project_pins_sha256': canonical_hash(vector),
            'writable_repositories': sorted(writable)}


class BuildSourceViewTest(unittest.TestCase):
    def fixture(self, fx):
        git(fx.source_root, 'clone', '-q', str(fx.repo), str(fx.source_root / 'readonly'))
        config = config_for(fx)
        environment = {'source_root': str(fx.source_root),
            'project_pins': {'repo': fx.target, 'readonly': fx.target},
            'manifest': {'manifest_commit': 'a' * 40}}
        legacy = environment_identity(environment, config, {'repo': fx.target})
        clean = _source_snapshot(legacy)
        environment['source_view'] = descriptor(environment['project_pins'], ['repo'])
        proof = {'base_id': 'b' * 64, 'base_receipt_sha256': 'c' * 64,
            'repositories': {'readonly': clean['readonly']}, 'writable_repositories': ['repo'],
            'runtime_mount_proof': {'fixture_provider_not_kernel': True, 'mount_id': 1}}
        return config, environment, legacy, clean, proof

    def test_only_writable_repositories_are_scanned_and_proof_ids_do_not_change_state(self):
        with GitFixture() as fx:
            config, environment, _, clean, proof = self.fixture(fx)
            def verify(source, vector, declared):
                self.assertEqual(source, str(fx.source_root))
                self.assertEqual(vector, environment['project_pins'])
                self.assertEqual(declared, environment['source_view'])
                proof['runtime_mount_proof']['mount_id'] += 1
                return deepcopy(proof)
            with patch(VERIFY, side_effect=verify, create=True), \
                    patch('aosp_agent.discovery.local_git', wraps=local_git) as calls:
                identity = environment_identity(environment, config, {'repo': fx.target})
                before = _source_snapshot(identity, receipt_path=fx.root / 'before.json')
                after = _source_snapshot(identity, receipt_path=fx.root / 'after.json')
            self.assertEqual(before, clean)
            self.assertEqual(after, before)
            self.assertEqual(len(calls.call_args_list), 14)
            self.assertTrue(all(Path(call.args[0]) == fx.repo for call in calls.call_args_list))
            first = json.loads((fx.root / 'before.json').read_text())
            second = json.loads((fx.root / 'after.json').read_text())
            self.assertEqual(first['inherited_repositories'], ['readonly'])
            self.assertEqual(first['inspected_repositories'], ['repo'])
            self.assertNotEqual(first['source_base']['runtime_mount_proof'], second['source_base']['runtime_mount_proof'])
            self.assertNotIn('runtime_mount_proof', identity['source_view'])

    def test_missing_or_invalid_active_proof_never_falls_back_to_declared_success(self):
        with GitFixture() as fx:
            config, environment, _, _, proof = self.fixture(fx)
            with patch(VERIFY, return_value=proof, create=True):
                identity = environment_identity(environment, config, {'repo': fx.target})
            with patch(VERIFY, side_effect=RecoveryBlocked('active mount lost'), create=True), \
                    patch('aosp_agent.discovery.local_git') as git_calls:
                with self.assertRaisesRegex(RecoveryBlocked, 'active mount lost'):
                    _source_snapshot(identity, receipt_path=fx.root / 'lost.json')
                git_calls.assert_not_called()
            receipt = json.loads((fx.root / 'lost.json').read_text())
            self.assertEqual(receipt['status'], 'UNVERIFIED')
            self.assertEqual(receipt['audit_mode'], 'immutable_base_with_project_work_layers')
            for invalid in (None, {}, {**proof, 'repositories': {}},
                            {**proof, 'writable_repositories': []}):
                with self.subTest(invalid=invalid), patch(VERIFY, return_value=invalid, create=True):
                    with self.assertRaises(RecoveryBlocked):
                        _source_snapshot(identity)

    def test_writable_dirty_or_ignored_files_still_block_with_partial_receipt(self):
        for ignored in (False, True):
            with self.subTest(ignored=ignored), GitFixture() as fx:
                config, environment, _, _, proof = self.fixture(fx)
                with patch(VERIFY, return_value=proof, create=True):
                    identity = environment_identity(environment, config, {'repo': fx.target})
                    if ignored:
                        (fx.repo / '.git/info/exclude').write_text('extra.bin\n')
                        (fx.repo / 'extra.bin').write_text('unexpected input')
                    else:
                        (fx.repo / 'counter.py').write_text('unexpected tracked change')
                    with self.assertRaises(ValueError):
                        _source_snapshot(identity, receipt_path=fx.root / 'dirty.json')
                receipt = json.loads((fx.root / 'dirty.json').read_text())
                self.assertEqual(receipt['status'], 'UNVERIFIED')
                self.assertEqual(receipt['inspected_repositories'], ['repo'])

    def test_inherited_rows_must_be_clean_and_complete(self):
        with GitFixture() as fx:
            config, environment, _, _, proof = self.fixture(fx)
            with patch(VERIFY, return_value=proof, create=True):
                identity = environment_identity(environment, config, {'repo': fx.target})
            for key, value in (('head', '0' * 40), ('status', ' M counter.py'),
                               ('undeclared_ignored_files', ['secret.bin']),
                               ('index_flags_verified', False),
                               ('index_check_returncode', 1)):
                bad = deepcopy(proof); bad['repositories']['readonly'][key] = value
                with self.subTest(key=key), patch(VERIFY, return_value=bad, create=True):
                    with self.assertRaisesRegex(RecoveryBlocked, 'sealed source audit'):
                        _source_snapshot(identity)

    def test_runner_change_keeps_source_base_but_invalidates_baseline_cache(self):
        with GitFixture() as fx:
            config, environment, _, _, proof = self.fixture(fx)
            calls = []
            def build(*args, **kwargs):
                calls.append(args[0]); return 'fixture baseline', '', 0
            with patch(VERIFY, return_value=proof, create=True):
                first = environment_identity(environment, config, {'repo': fx.target})
                run_baseline(first, config, ['module'], fx.root / 'run1', runner=build)
                cached = run_baseline(first, config, ['module'], fx.root / 'run2', runner=build)
                self.assertTrue(cached['cache_hit'])
                Path(config['runner']).write_text('#!/bin/sh\n# changed runner contract\nexit 0\n')
                second = environment_identity(environment, config, {'repo': fx.target})
                fresh = run_baseline(second, config, ['module'], fx.root / 'run3', runner=build)
            self.assertEqual(first['source_view'], second['source_view'])
            self.assertNotEqual(first['environment_id'], second['environment_id'])
            self.assertFalse(fresh['cache_hit'])
            self.assertEqual(len(calls), 2)

    def test_legacy_view_retains_full_vector_audit_without_provider(self):
        with GitFixture() as fx:
            _, _, legacy, clean, _ = self.fixture(fx)
            with patch(VERIFY, side_effect=AssertionError('legacy must not use base'), create=True), \
                    patch('aosp_agent.discovery.local_git', wraps=local_git) as calls:
                observed = _source_snapshot(legacy, receipt_path=fx.root / 'legacy.json')
            self.assertEqual(observed, clean)
            self.assertEqual(len(calls.call_args_list), 14)
            receipt = json.loads((fx.root / 'legacy.json').read_text())
            self.assertEqual(receipt['audit_mode'], 'legacy_full_vector')
            self.assertEqual(receipt['inherited_repositories'], [])
            self.assertEqual(set(receipt['inspected_repositories']), {'repo', 'readonly'})

    def test_each_audit_rejects_runtime_git_redirection_to_a_clean_decoy(self):
        for immutable in (False, True):
            with self.subTest(immutable=immutable), GitFixture() as fx:
                config, environment, legacy, _, proof = self.fixture(fx)
                with patch(VERIFY, return_value=proof, create=True):
                    identity = environment_identity(environment, config, {'repo': fx.target}) if immutable else legacy
                    _source_snapshot(identity)
                    decoy = fx.root / 'clean-decoy'
                    shutil.copytree(fx.repo, decoy, ignore=shutil.ignore_patterns('.git'))
                    (fx.repo / 'counter.py').write_text('builder changed the real controlled source\n')
                    git(fx.repo, 'config', 'core.worktree', str(decoy))
                    self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
                    with self.assertRaisesRegex(RecoveryBlocked, 'Git paths escape'):
                        _source_snapshot(identity, receipt_path=fx.root / 'redirected.json')
                receipt = json.loads((fx.root / 'redirected.json').read_text())
                self.assertEqual(receipt['status'], 'UNVERIFIED')
                self.assertEqual(receipt['repository_git_bindings']['repo']['worktree'], str(decoy))
                self.assertIn('builder changed', (fx.repo / 'counter.py').read_text())

    def test_each_audit_rejects_index_flags_that_hide_changed_source(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag), GitFixture() as fx:
                config, environment, _, _, proof = self.fixture(fx)
                with patch(VERIFY, return_value=proof, create=True):
                    identity = environment_identity(environment, config, {'repo': fx.target})
                    _source_snapshot(identity)
                    git(fx.repo, 'update-index', flag, 'counter.py')
                    (fx.repo / 'counter.py').write_text('hidden source modification\n')
                    self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
                    with self.assertRaisesRegex(RecoveryBlocked, 'assume-unchanged/skip-worktree'):
                        _source_snapshot(identity, receipt_path=fx.root / 'flags.json')
                self.assertEqual(json.loads((fx.root / 'flags.json').read_text())['status'], 'UNVERIFIED')
                self.assertEqual((fx.repo / 'counter.py').read_text(), 'hidden source modification\n')

    def test_controlled_session_requests_candidate_work_layers_before_materialization(self):
        with GitFixture() as fx:
            controller = test_controlled_build.ControlledBuildTest().controller(fx)
            prepared = controller.prepared_case
            vector = prepared.environment['project_pins']
            prepared.environment['source_view'] = descriptor(vector, ['repo', 'repo2'])
            events = []
            prepared.ensure_writable = lambda keys: events.append(('writable', sorted(keys)))
            prepared.materialize_all = lambda: events.append(('materialize', None))
            proof = {'base_id': 'b' * 64, 'base_receipt_sha256': 'c' * 64,
                'repositories': {}, 'writable_repositories': ['repo', 'repo2'],
                'runtime_mount_proof': {'fixture_provider_not_kernel': True}}
            with patch(VERIFY, return_value=proof, create=True):
                with controlled_build_session(controller) as build:
                    self.assertEqual(build.identity['source_view'], prepared.environment['source_view'])
            self.assertEqual(events, [('writable', ['repo', 'repo2']), ('materialize', None)])
            self.assertEqual(controller.record['build_environment']['source_scope'],
                             'immutable_base_with_project_work_layers')


if __name__ == '__main__':
    unittest.main()
