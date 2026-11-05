import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from aosp_agent.build_transaction import transaction
from aosp_agent.discovery import local_git
from aosp_agent.validation_process import run_check
from engine_fixtures import BASELINE, FIXED, GitFixture, git


class BundleTransactionTest(unittest.TestCase):
    def contract(self, fx, dependency=False):
        run = fx.root / 'bundle-run'
        workspace = run / 'workspace'
        workspace.mkdir(parents=True)
        second = fx.source_root / 'repo2'
        git(fx.source_root, 'clone', '-q', '--no-hardlinks', str(fx.repo), str(second))
        git(second, 'checkout', '--detach', '-q', fx.target)
        entries = []
        for key, repo in [('repo', fx.repo), ('repo2', second)]:
            candidate = workspace / key
            git(repo, 'worktree', 'add', '--detach', str(candidate), fx.target)
            receipt = run / 'repositories' / key
            receipt.mkdir(parents=True)
            patch_file = receipt / 'backport.patch'
            content = git(repo, 'diff', fx.target, fx.donor) + '\n'
            patch_file.write_text(content)
            entries.append({'key': key, 'target_repo': str(repo), 'target_commit': fx.target,
                            'worktree': str(candidate), 'patch_file': str(patch_file),
                            'sha256': hashlib.sha256(content.encode()).hexdigest()})
        bundle = {'version': 1, 'repositories': entries, 'dependencies': []}
        if dependency:
            dep = fx.source_root / 'dependency'
            git(fx.source_root, 'clone', '-q', '--no-hardlinks', str(fx.repo), str(dep))
            git(dep, 'checkout', '--detach', '-q', fx.target)
            bundle['dependencies'].append({'key': 'dependency', 'target_repo': str(dep),
                                           'target_commit': fx.target})
        env = dict(os.environ, AOSP_AGENT_RUN_DIR=str(run), AOSP_AGENT_WORKTREE=str(workspace),
                   AOSP_AGENT_PATCH_BUNDLE=str(run / 'bundle.json'))
        self.save_bundle(bundle, env)
        return bundle, env

    def save_bundle(self, bundle, env):
        content = json.dumps(bundle).encode()
        Path(env['AOSP_AGENT_PATCH_BUNDLE']).write_bytes(content)
        env['AOSP_AGENT_BUNDLE_SHA256'] = hashlib.sha256(content).hexdigest()

    def execute(self, fx, env, script):
        return transaction(fx.source_root, fx.root / 'shared.lock', [sys.executable, '-c', script], env)

    def assert_sources_restored(self, bundle):
        for entry in bundle['repositories']:
            self.assertEqual((Path(entry['target_repo']) / 'counter.py').read_text(), BASELINE)
            self.assertEqual(git(Path(entry['target_repo']), 'status', '--porcelain'), '')

    def test_builder_sees_all_patches_simultaneously_then_both_restore(self):
        for code in (0, 7):
            with self.subTest(code=code), GitFixture() as fx:
                bundle, env = self.contract(fx)
                paths = [str(Path(e['target_repo']) / 'counter.py') for e in bundle['repositories']]
                script = f'from pathlib import Path; import sys; assert all(Path(p).read_text() == {FIXED!r} for p in {paths!r}); sys.exit({code})'
                self.assertEqual(self.execute(fx, env, script), code)
                self.assert_sources_restored(bundle)
                report = json.loads((Path(env['AOSP_AGENT_RUN_DIR']) / 'module-build-restore/bundle.json').read_text())
                self.assertEqual(report['restore'], 'PASS')
                self.assertEqual(report['before'], report['after'])

    def test_all_preflight_checks_finish_before_first_apply(self):
        for problem in ('dirty', 'hash', 'duplicate', 'dependency'):
            with self.subTest(problem=problem), GitFixture() as fx:
                bundle, env = self.contract(fx, dependency=problem == 'dependency')
                second = Path(bundle['repositories'][1]['target_repo'])
                if problem == 'dirty':
                    (second / 'user.txt').write_text('keep')
                elif problem == 'hash':
                    bundle['repositories'][1]['sha256'] = 'bad'
                elif problem == 'duplicate':
                    bundle['repositories'][1]['target_repo'] = str(fx.repo)
                else:
                    bundle['dependencies'][0]['target_commit'] = 'bad'
                self.save_bundle(bundle, env)
                with self.assertRaises(ValueError):
                    self.execute(fx, env, 'raise AssertionError("builder must not run")')
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
                self.assertEqual((second / 'counter.py').read_text(), BASELINE)
                if problem == 'dirty':
                    self.assertEqual((second / 'user.txt').read_text(), 'keep')

    def test_later_apply_failure_unwinds_earlier_repository(self):
        with GitFixture() as fx:
            bundle, env = self.contract(fx)
            second = Path(bundle['repositories'][1]['target_repo'])
            observed = []
            def failing_git(repo, *args, **kwargs):
                if Path(repo) == second and args[:2] == ('apply', '--binary'):
                    observed.append((fx.repo / 'counter.py').read_text())
                    raise subprocess.CalledProcessError(1, ['git', 'apply'])
                return local_git(repo, *args, **kwargs)
            with patch('aosp_agent.build_transaction.local_git', side_effect=failing_git):
                self.assertEqual(self.execute(fx, env, 'raise AssertionError("builder must not run")'), 120)
            self.assertEqual(observed, [FIXED])
            self.assert_sources_restored(bundle)

    def test_dependency_mutation_is_preserved_and_fails_joint_restore(self):
        with GitFixture() as fx:
            bundle, env = self.contract(fx, dependency=True)
            path = Path(bundle['dependencies'][0]['target_repo']) / 'counter.py'
            script = f'from pathlib import Path; Path({str(path)!r}).write_text("unexpected dependency edit")'
            self.assertEqual(self.execute(fx, env, script), 119)
            self.assert_sources_restored(bundle)
            self.assertEqual(path.read_text(), 'unexpected dependency edit')

    def test_timeout_unwinds_every_applied_repository(self):
        with GitFixture() as fx:
            bundle, env = self.contract(fx)
            project = str(Path(__file__).resolve().parents[2])
            env['PYTHONPATH'] = project
            started = fx.root / 'builder-started'
            script = f'from pathlib import Path; import time; Path({str(started)!r}).touch(); time.sleep(60)'
            command = [sys.executable, '-m', 'aosp_agent.build_transaction',
                       '--source-root', str(fx.source_root), '--lock', str(fx.root / 'shared.lock'),
                       '--', sys.executable, '-c', script]
            stdout, stderr, code = run_check(command, project, env, timeout=3, grace=15)
            self.assertEqual(code, 124, stdout + stderr)
            self.assertTrue(started.exists())
            self.assert_sources_restored(bundle)

    def test_manifest_tampering_is_rejected_before_source_changes(self):
        with GitFixture() as fx:
            bundle, env = self.contract(fx)
            Path(env['AOSP_AGENT_PATCH_BUNDLE']).write_text('{}')
            with self.assertRaisesRegex(ValueError, 'bundle hash'):
                self.execute(fx, env, 'pass')
            self.assert_sources_restored(bundle)
