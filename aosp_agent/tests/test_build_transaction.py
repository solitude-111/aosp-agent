import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest

from aosp_agent.build_transaction import transaction
from aosp_agent.validation_process import run_check
from engine_fixtures import BASELINE, FIXED, GitFixture, git


class BuildTransactionTest(unittest.TestCase):
    def setup_contract(self, fx):
        worktree = fx.root / 'candidate'
        git(fx.repo, 'worktree', 'add', '--detach', str(worktree), fx.target)
        run = fx.root / 'receipt'
        run.mkdir()
        patch = git(fx.repo, 'diff', fx.target, fx.donor) + '\n'
        patch_path = run / 'backport.patch'
        patch_path.write_text(patch)
        env = dict(os.environ)
        env.update({'AOSP_AGENT_PATCH_FILE': str(patch_path),
                    'AOSP_AGENT_PATCH_SHA256': hashlib.sha256(patch.encode()).hexdigest(),
                    'AOSP_AGENT_TARGET_REPO': str(fx.repo), 'AOSP_AGENT_TARGET_COMMIT': fx.target,
                    'AOSP_AGENT_WORKTREE': str(worktree), 'AOSP_AGENT_RUN_DIR': str(run)})
        return env, run

    def execute(self, fx, env, script):
        return transaction(fx.source_root, fx.root / 'build.lock', [sys.executable, '-c', script], env)

    def test_success_and_build_failure_both_restore_original(self):
        for code in (0, 7):
            with self.subTest(code=code), GitFixture() as fx:
                env, run = self.setup_contract(fx)
                script = (f'from pathlib import Path; import sys; '
                          f'assert Path({str(fx.repo / "counter.py")!r}).read_text() == {FIXED!r}; sys.exit({code})')
                self.assertEqual(self.execute(fx, env, script), code)
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
                self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
                self.assertEqual(json.loads((run / 'module-build-restore/transaction.json').read_text())['restore'], 'PASS')

    def test_dirty_source_is_rejected_without_cleaning_user_files(self):
        with GitFixture() as fx:
            env, run = self.setup_contract(fx)
            (fx.repo / 'counter.py').write_text('user changes\n')
            (fx.repo / 'user.txt').write_text('keep\n')
            with self.assertRaisesRegex(ValueError, 'dirty'):
                self.execute(fx, env, 'raise AssertionError("must not run")')
            self.assertEqual((fx.repo / 'counter.py').read_text(), 'user changes\n')
            self.assertTrue((fx.repo / 'user.txt').is_file())
            self.assertEqual(json.loads((run / 'module-build-restore/transaction.json').read_text())['restore'], 'NOT_NEEDED')

    def test_hash_head_and_source_scope_are_checked(self):
        for field, value in [('PATCH_SHA256', 'bad'), ('TARGET_COMMIT', '0' * 40), ('TARGET_REPO', '/tmp')]:
            with self.subTest(field=field), GitFixture() as fx:
                env, _ = self.setup_contract(fx)
                env['AOSP_AGENT_' + field] = value
                with self.assertRaises(ValueError):
                    self.execute(fx, env, 'raise AssertionError("must not run")')
                self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_unrelated_build_output_is_preserved_and_fails_restoration(self):
        with GitFixture() as fx:
            env, run = self.setup_contract(fx)
            script = f'from pathlib import Path; Path({str(fx.repo / "unrelated.txt")!r}).write_text("keep")'
            self.assertEqual(self.execute(fx, env, script), 119)
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertEqual((fx.repo / 'unrelated.txt').read_text(), 'keep')

    def test_only_patch_created_files_and_directories_are_removed(self):
        with GitFixture() as fx:
            env, run = self.setup_contract(fx)
            patch = (run / 'backport.patch').read_text() + (
                'diff --git a/new/helper.txt b/new/helper.txt\nnew file mode 100644\n'
                '--- /dev/null\n+++ b/new/helper.txt\n@@ -0,0 +1 @@\n+helper\n')
            (run / 'backport.patch').write_text(patch)
            env['AOSP_AGENT_PATCH_SHA256'] = hashlib.sha256(patch.encode()).hexdigest()
            self.assertEqual(self.execute(fx, env, 'pass'), 0)
            self.assertFalse((fx.repo / 'new').exists())

    def test_build_mutating_patch_path_is_preserved_as_restore_failure(self):
        with GitFixture() as fx:
            env, run = self.setup_contract(fx)
            script = f'from pathlib import Path; Path({str(fx.repo / "counter.py")!r}).write_text("unexpected edit")'
            self.assertEqual(self.execute(fx, env, script), 119)
            self.assertEqual((fx.repo / 'counter.py').read_text(), 'unexpected edit')
            report = json.loads((run / 'module-build-restore/transaction.json').read_text())
            self.assertEqual(report['unexpected_patch_changes'], ['counter.py'])

    def test_orphan_builder_is_stopped_before_source_restoration(self):
        with GitFixture() as fx:
            env, _ = self.setup_contract(fx)
            late_output = fx.root / 'late-output'
            child = f'import time; from pathlib import Path; time.sleep(0.5); Path({str(late_output)!r}).write_text("late")'
            script = f'import subprocess, sys; subprocess.Popen([sys.executable, "-c", {child!r}])'
            self.assertEqual(self.execute(fx, env, script), 0)
            time.sleep(0.6)
            self.assertFalse(late_output.exists())
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_timeout_terminates_builder_and_restores_before_return(self):
        with GitFixture() as fx:
            env, run = self.setup_contract(fx)
            project = str(Path(__file__).resolve().parents[2])
            env['PYTHONPATH'] = project
            command = [sys.executable, '-m', 'aosp_agent.build_transaction',
                       '--source-root', str(fx.source_root), '--lock', str(fx.root / 'build.lock'),
                       '--', sys.executable, '-c', 'import time; time.sleep(60)']
            _, _, code = run_check(command, project, env, timeout=1, grace=10)
            self.assertEqual(code, 124)
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            report = json.loads((run / 'module-build-restore/transaction.json').read_text())
            self.assertEqual(report['restore'], 'PASS')
