"""Legacy API barriers and durable resumption history; no real model or CVE."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.engine import AospBackportAgent
from aosp_agent.lifecycle import LeaseBusy, RecoveryBlocked, source_guard, source_lease
from aosp_agent.mapped_run import from_case
from aosp_agent.project_first import ProjectFirstAgent
from aosp_agent.resume import resume_project, resume_batch
from aosp_agent.runtime_batch import RuntimeBatch
from engine_fixtures import GitFixture, BASELINE, FIXED
from test_diff_workflow import diff, QueueRuntime
from test_lifecycle import interrupt
import test_lifecycle as lifecycle_tests
import test_project_first as routing
import test_runtime_entrypoints as entry


class ExecutionGuardTest(unittest.TestCase):
    def test_legacy_constructor_and_dataset_adapter_block_before_source_reads(self):
        with GitFixture() as fx, source_lease(fx.source_root):
            with patch.object(DiffBackportAgent, '_inventory', side_effect=AssertionError('read while leased')):
                with self.assertRaises(LeaseBusy):
                    DiffBackportAgent(diff('counter.py', BASELINE, FIXED).encode(), fx.repo, fx.run_root)
            with patch('aosp_agent.mapped_run.local_git', side_effect=AssertionError('read while leased')):
                with self.assertRaises(LeaseBusy):
                    from_case(fx.case(), fx.source_root, fx.run_root)
            self.assertFalse(fx.run_root.exists())

    def test_direct_run_prepare_and_verify_cannot_bypass_other_owner(self):
        with GitFixture() as fx:
            legacy = DiffBackportAgent(diff('counter.py', BASELINE, FIXED).encode(), fx.repo, fx.run_root)
            child = AospBackportAgent(fx.source_root, fx.run_root, fx.case())
            with source_lease(fx.source_root):
                for action in (lambda: legacy.run(inspect_only=True), child.prepare,
                               lambda: child.run(use_codex=False), child.verify):
                    with self.subTest(action=action), self.assertRaises(LeaseBusy):
                        action()
            self.assertFalse(legacy._started)
            self.assertFalse(child.run_dir.exists())

    def test_drift_between_constructor_and_run_fails_before_discovery(self):
        with GitFixture() as fx:
            legacy = DiffBackportAgent(diff('counter.py', BASELINE, FIXED).encode(), fx.repo, fx.run_root)
            (fx.repo / 'counter.py').write_text(FIXED)
            with patch('aosp_agent.diff_engine.Locator', side_effect=AssertionError('discovery on drifted source')):
                with self.assertRaisesRegex(RuntimeError, 'original repository changed'):
                    legacy.run(inspect_only=True)
            self.assertEqual((fx.repo / 'counter.py').read_text(), FIXED)

    def test_same_owner_recurses_but_other_thread_or_owner_must_acquire(self):
        class Controller:
            def __init__(self, root): self.root = root
            @source_guard('root')
            def execute(self, callback=lambda: None): return callback()
        with GitFixture() as fx:
            owner, other = Controller(fx.source_root), Controller(fx.source_root)
            def nested():
                owner.execute()
                with self.assertRaises(LeaseBusy): other.execute()
                with ThreadPoolExecutor(max_workers=1) as pool:
                    with self.assertRaises(LeaseBusy): pool.submit(owner.execute).result()
            owner.execute(nested)
            other.execute()  # released on return

    def test_legacy_cli_reports_contention_as_blocked(self):
        with GitFixture() as fx, source_lease(fx.source_root):
            source = fx.root / 'input.patch'; source.write_text(diff('counter.py', BASELINE, FIXED))
            result = subprocess.run([sys.executable, '-m', 'aosp_agent', 'diff', '--patch', str(source),
                '--target-root', str(fx.repo), '--run-root', str(fx.run_root),
                '--exhaustive-discovery', '--inspect-only'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'BLOCKED')


class AttemptChainTest(unittest.TestCase):
    def complete(self, path):
        runtime = QueueRuntime([(routing.ProjectFirstTest().assessment(), None)])
        result = resume_project(path, runtime_factory=runtime.factory)
        self.assertEqual(result['status'], 'AFFECTED', result)
        return result

    def test_completed_descendant_prevents_reexecuting_original(self):
        with GitFixture() as fx:
            old = lifecycle_tests.LifecycleTest().cancelled(fx)
            latest = self.complete(old.run_dir / 'run.json')
            self.assertEqual(json.loads((old.run_dir / 'run.json').read_text())['resumed_to'], latest['record'])
            with patch.object(ProjectFirstAgent, 'run', side_effect=AssertionError('duplicate model work')):
                with self.assertRaisesRegex(RecoveryBlocked, 'latest task attempt is already terminal'):
                    resume_project(old.run_dir / 'run.json')

    def test_original_follows_multiple_cancelled_attempts(self):
        with GitFixture() as fx:
            old = lifecycle_tests.LifecycleTest().cancelled(fx)
            runtime = QueueRuntime([(routing.ProjectFirstTest().assessment(), interrupt)])
            cancelled = resume_project(old.run_dir / 'run.json', runtime_factory=runtime.factory)
            self.assertEqual(cancelled['status'], 'CANCELLED')
            final = self.complete(old.run_dir / 'run.json')
            self.assertEqual(final['resumed_from'], cancelled['record'])
            self.assertEqual(json.loads(Path(cancelled['record']).read_text())['resumed_to'], final['record'])

    def test_prepared_child_survives_callback_failure_without_losing_pins(self):
        with GitFixture() as fx:
            old = lifecycle_tests.LifecycleTest().cancelled(fx)
            def fail(_): raise OSError('parent publication interrupted')
            with self.assertRaisesRegex(OSError, 'publication interrupted'):
                resume_project(old.run_dir / 'run.json', _on_prepared=fail)
            prepared = Path(json.loads((old.run_dir / 'run.json').read_text())['resumed_to'])
            saved = json.loads(prepared.read_text())
            self.assertIn('run_options', saved)
            self.assertIn('catalog_sha256', saved)
            final = self.complete(old.run_dir / 'run.json')
            self.assertEqual(final['resumed_from'], str(prepared))
            self.assertEqual(final['pinned_targets']['repo']['head'], fx.target)

    def test_broken_chain_never_falls_back_to_ancestor(self):
        for mode in ('missing', 'cycle', 'backlink', 'input'):
            with self.subTest(mode=mode), GitFixture() as fx:
                old = lifecycle_tests.LifecycleTest().cancelled(fx)
                latest = self.complete(old.run_dir / 'run.json')
                path = Path(latest['record']); saved = json.loads(path.read_text())
                if mode == 'missing': path.unlink()
                else:
                    if mode == 'cycle': saved['resumed_to'] = str(old.run_dir / 'run.json')
                    if mode == 'backlink': saved['resumed_from'] = str(fx.root / 'unrelated.json')
                    if mode == 'input': saved['input_patch_sha256'] = '0' * 64
                    path.write_text(json.dumps(saved))
                with patch.object(ProjectFirstAgent, 'run', side_effect=AssertionError('stale ancestor rerun')):
                    with self.assertRaises(RecoveryBlocked): resume_project(old.run_dir / 'run.json')

    def test_batch_uses_completed_standalone_descendant_and_cannot_repeat(self):
        with GitFixture() as fx:
            entry.manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text(json.dumps(entry.row(fx)))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entry.ORIGIN: str(fx.repo)})
            with patch.object(ProjectFirstAgent, '_prepare', side_effect=KeyboardInterrupt('stop')):
                initial = runner.run(inspect_only=True)
            standalone = resume_project(initial['rows'][0]['execution_record'])
            self.assertEqual(standalone['status'], 'DISCOVERED')
            with patch.object(ProjectFirstAgent, 'run', side_effect=AssertionError('completed row repeated')):
                final = resume_batch(runner.run_dir / 'batch-status.json')
                self.assertEqual(final['status'], 'COMPLETED', final)
                self.assertEqual(final['rows'][0]['execution_record'], standalone['record'])
                with self.assertRaisesRegex(RecoveryBlocked, 'latest batch attempt is already completed'):
                    resume_batch(runner.run_dir / 'batch-status.json')
