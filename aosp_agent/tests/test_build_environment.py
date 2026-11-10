"""Controlled build cache isolation, source restoration and failure attribution."""
import copy
import json
from pathlib import Path
import sys
import unittest

from aosp_agent.build_environment import (BuildEnvironmentBlocked, canonical_hash,
    environment_identity, select_validation_vector, validate_build_config,
    run_baseline, classify_build_failure, verify_environment_identity)
from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.validation_process import VerifierCleanupBlocked
from engine_fixtures import GitFixture, git


def config_for(fx):
    script = fx.root / 'builder.sh'; script.write_text('#!/bin/sh\nexit 0\n'); script.chmod(0o755)
    return validate_build_config({'enabled': True, 'runner': str(script),
        'product': 'fixture_product', 'variant': 'userdebug', 'arch': 'x86_64',
        'build_system': 'pinned fixture build system', 'toolchain': 'pinned fixture compiler',
        'host': {'kind': 'host', 'identity': 'fixture controlled host', 'tools': {'python': sys.executable}},
        'output_root': str(fx.root / 'out'), 'tmp_root': str(fx.root / 'tmp'),
        'baseline_cache': str(fx.root / 'baseline-cache')})


def identity_for(fx, config):
    return environment_identity({'source_root': str(fx.source_root), 'project_pins': {'repo': fx.target},
        'manifest': {'manifest_commit': 'a' * 40, 'manifest_name': 'fixture.xml'}}, config, {'repo': fx.target})


class BuildEnvironmentTest(unittest.TestCase):
    def test_manifest_root_copy_and_directory_link_are_part_of_environment_and_restoration(self):
        for kind in ('copyfile', 'linkfile'):
            with self.subTest(kind=kind), GitFixture() as fx:
                config = config_for(fx)
                destination = fx.source_root / 'root-input'
                if kind == 'copyfile':
                    destination.write_bytes((fx.repo / 'counter.py').read_bytes())
                else:
                    destination.symlink_to('repo')
                operations = [{'kind': kind, 'project': 'repo',
                               'src': 'counter.py' if kind == 'copyfile' else '.', 'dest': 'root-input'}]
                identity = environment_identity({'source_root': str(fx.source_root),
                    'project_pins': {'repo': fx.target}, 'manifest': {'manifest_commit': 'a'*40},
                    'manifest_files': operations}, config, {'repo': fx.target})
                self.assertIn('root-input', identity['manifest_files'])
                def change_root(*args, **kwargs):
                    if kind == 'copyfile':
                        destination.write_text('builder modified a manifest copy outside every project')
                    else:
                        destination.unlink()
                        destination.mkdir()
                    return '', '', 0
                with self.assertRaises(RecoveryBlocked):
                    run_baseline(identity, config, ['module'], fx.root / 'run', runner=change_root)
                with self.assertRaises(RecoveryBlocked):
                    verify_environment_identity(identity, config)
                receipt = json.loads(next((fx.root / 'run').glob('source-after-*.json')).read_text())
                self.assertEqual(receipt['status'], 'UNVERIFIED')
                self.assertFalse(list((Path(config['baseline_cache']) / identity['environment_id']).glob('*.json')))

    def test_full_source_audit_rejects_staged_worktree_and_ignored_changes_with_receipts(self):
        for mutation in ('staged', 'worktree', 'ignored'):
            with self.subTest(mutation=mutation), GitFixture() as fx:
                config = config_for(fx); identity = identity_for(fx, config)
                if mutation == 'ignored':
                    (fx.repo / '.git/info/exclude').write_text('ignored.bin\n')
                    (fx.repo / 'ignored.bin').write_text('uncontrolled source input')
                else:
                    (fx.repo / 'counter.py').write_text('uncontrolled tracked change\n')
                    if mutation == 'staged':
                        git(fx.repo, 'add', 'counter.py')
                with self.assertRaises((RecoveryBlocked, BuildEnvironmentBlocked)):
                    run_baseline(identity, config, ['module'], fx.root / 'run',
                        runner=lambda *a, **k: self.fail('dirty source must never reach the builder'))
                receipt = json.loads(next((fx.root / 'run').glob('source-before-*.json')).read_text())
                row = receipt['repositories']['repo']
                self.assertEqual(receipt['status'], 'UNVERIFIED')
                self.assertEqual(row['index_check_returncode'], 1 if mutation == 'staged' else 0)
                self.assertEqual(row['worktree_check_returncode'], 0 if mutation == 'ignored' else 1)
                if mutation == 'ignored':
                    self.assertEqual(row['undeclared_ignored_files'], ['ignored.bin'])
                self.assertFalse(list((Path(config['baseline_cache']) / identity['environment_id']).glob('*.json')))

    def test_private_home_cannot_be_overridden_with_an_untracked_user_profile(self):
        with GitFixture() as fx:
            config = config_for(fx)
            config['environment']['HOME'] = str(fx.root / 'real-user-home')
            with self.assertRaisesRegex(ValueError, 'private'):
                validate_build_config(config)

    def test_success_cache_reuses_only_same_environment_and_module_scope(self):
        with GitFixture() as fx:
            config = config_for(fx); identity = identity_for(fx, config); calls = []
            def build(argv, cwd, env, **kw):
                calls.append(argv)
                self.assertEqual(env['AOSP_AGENT_BASELINE_ACTIVE'], '1')
                self.assertNotIn('AOSP_AGENT_PATCH_FILE', env)
                self.assertEqual(cwd, str(fx.source_root))
                return 'built\n', '', 0
            one = run_baseline(identity, config, ['moduleA'], fx.root / 'run1', runner=build)
            two = run_baseline(identity, config, ['moduleA'], fx.root / 'run2', runner=build)
            three = run_baseline(identity, config, ['moduleA', 'moduleB'], fx.root / 'run3', runner=build)
            self.assertEqual(len(calls), 2)
            self.assertTrue(two['cache_hit'])
            self.assertEqual(three['modules'], ['moduleB'])
            self.assertEqual(three['requested_modules'], ['moduleA', 'moduleB'])
            self.assertEqual(one['source_restoration'], 'PASS')
            changed = {**config, 'variant': 'eng'}
            other = identity_for(fx, changed)
            self.assertNotEqual(identity['environment_id'], other['environment_id'])
            run_baseline(other, changed, ['moduleA'], fx.root / 'run4', runner=build)
            self.assertEqual(len(calls), 3)

    def test_changed_runner_cannot_reuse_a_stale_identity(self):
        with GitFixture() as fx:
            config = config_for(fx); identity = identity_for(fx, config)
            Path(config['runner']).write_text('#!/bin/sh\nexit 1\n')
            with self.assertRaisesRegex(BuildEnvironmentBlocked, 'input changed'):
                run_baseline(identity, config, ['module'], fx.root / 'run', runner=lambda *a,**k: self.fail('must not build'))

    def test_baseline_failure_is_not_cached_and_does_not_request_patch_repairs(self):
        with GitFixture() as fx:
            config = config_for(fx); identity = identity_for(fx, config); calls = []
            def fail(*args, **kw):
                calls.append(1)
                return 'error: repo/Android.bp:1:1: depends on undefined module "dependency"', '', 1
            for i in range(2):
                result = run_baseline(identity, config, ['module'], fx.root / ('run' + str(i)), runner=fail)
                self.assertEqual(result['classification']['status'], 'BUILD_ENVIRONMENT_BLOCKED')
                self.assertFalse(result['classification']['repair_candidate'])
            self.assertEqual(len(calls), 2)

    def test_baseline_mutation_and_unverified_cleanup_pause_without_cleaning(self):
        with GitFixture() as fx:
            config = config_for(fx); identity = identity_for(fx, config)
            def dirty(*args, **kw):
                (fx.repo / 'user.txt').write_text('preserve unexpected write')
                return '', '', 0
            with self.assertRaises(RecoveryBlocked):
                run_baseline(identity, config, ['module'], fx.root / 'run', runner=dirty)
            self.assertEqual((fx.repo / 'user.txt').read_text(), 'preserve unexpected write')
        with GitFixture() as fx:
            config = config_for(fx); identity = identity_for(fx, config)
            def orphan(*args, **kw):
                raise VerifierCleanupBlocked('unknown remaining writer')
            with self.assertRaises(RecoveryBlocked):
                run_baseline(identity, config, ['module'], fx.root / 'run', runner=orphan)
            receipt = json.loads(next((fx.root / 'run').glob('baseline-*.json')).read_text())
            self.assertEqual(receipt['source_restoration'], 'UNVERIFIED')

    def test_compatibility_mapping_requires_exact_full_vector_and_preserves_tested_pins(self):
        original = {'repo': 'a' * 40, 'dependency': 'b' * 40}
        selected = {'repo': 'a' * 40, 'dependency': 'c' * 40}
        rule = {'id': 'trusted-release-map', 'target_vector_sha256': canonical_hash(original),
                'validation_pins': selected, 'basis': 'operator supplied fixed upstream manifest'}
        result = select_validation_vector(original, {'repo': 'a' * 40}, [rule])
        self.assertEqual(result['original_project_pins'], original)
        self.assertEqual(result['project_pins'], selected)
        self.assertEqual(result['evidence_revalidation_required'], ['dependency'])
        self.assertEqual(select_validation_vector(original, {'repo': 'a' * 40})['project_pins'], original)
        rule['validation_pins']['repo'] = 'd' * 40
        with self.assertRaisesRegex(BuildEnvironmentBlocked, 'tested repository'):
            select_validation_vector(original, {'repo': 'a' * 40}, [rule])

    def test_candidate_errors_need_matching_baseline_scope_and_specific_diagnostic(self):
        base = {'returncode': 0, 'environment_id': 'env1', 'modules': ['mod']}
        candidate = {'returncode': 1, 'environment_id': 'env1', 'modules': ['mod'],
                     'source_restoration': 'PASS', 'stderr': 'repo/code.cpp:4:2: error: missing name'}
        self.assertTrue(classify_build_failure(candidate, phase='candidate', baseline=base,
                                                changed_paths=['repo/code.cpp'])['repair_candidate'])
        candidate['stderr'] = 'unrelated/path.cpp:4:2: error: missing name'
        self.assertEqual(classify_build_failure(candidate, phase='candidate', baseline=base,
                            changed_paths=['repo/code.cpp'])['status'], 'BUILD_FAILURE_UNATTRIBUTED')
        candidate['environment_id'] = 'different'
        self.assertEqual(classify_build_failure(candidate, phase='candidate', baseline=base)['status'], 'BASELINE_UNVERIFIED')
        candidate['stderr'] = 'No space left on device'
        self.assertTrue(classify_build_failure(candidate, phase='candidate', baseline=base)['pause_batch'])
        candidate.update(returncode=0, stderr='')
        self.assertEqual(classify_build_failure(candidate, phase='candidate', baseline=base,
                                                coverage='partial')['status'], 'PASS_PARTIAL')


if __name__ == '__main__':
    unittest.main()
