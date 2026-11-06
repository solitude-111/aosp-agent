import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest

from aosp_agent.lifecycle import process_state, run_lease, source_lease, LeaseBusy, RecoveryBlocked
from aosp_agent.project_first import ProjectFirstAgent
from aosp_agent.resume import resume_project
from aosp_agent.resume import resume_batch
from aosp_agent.runtime_batch import RuntimeBatch
from engine_fixtures import GitFixture, BASELINE, FIXED
from test_diff_workflow import diff, QueueRuntime
import test_project_first as routing
import test_runtime_entrypoints as entry
from unittest.mock import patch


def interrupt(_):
    raise KeyboardInterrupt('test cancellation')


class LifecycleTest(unittest.TestCase):
    def test_damaged_restore_receipt_blocks_before_a_fresh_attempt(self):
        with GitFixture() as fx:
            old = self.cancelled(fx)
            receipt = old.run_dir / 'rounds/r01/module-build-restore/transaction.json'
            receipt.parent.mkdir(); receipt.write_text('{"restore":')
            with self.assertRaisesRegex(RecoveryBlocked, 'cannot verify prior source restoration'):
                resume_project(old.run_dir / 'run.json')
            self.assertFalse((old.run_dir / 'resumptions').exists())

    def test_late_unexpected_resume_error_is_a_batch_barrier(self):
        import aosp_agent.resume as resumption
        with GitFixture() as fx:
            entry.manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text('\n'.join([json.dumps(entry.row(fx))] * 2))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entry.ORIGIN: str(fx.repo)})
            with patch.object(ProjectFirstAgent, '_prepare', side_effect=KeyboardInterrupt('stop')):
                runner.run(inspect_only=True)
            with patch.object(resumption, 'resume_project', side_effect=OSError('checkpoint became unreadable')):
                result = resume_batch(runner.run_dir / 'batch-status.json')
            self.assertEqual(result['status'], 'BLOCKED', result)
            self.assertEqual(result['remaining_rows'], 1)
            self.assertEqual(result['rows'][0]['completion_blocked_by'], 'RESUMPTION_PRECONDITION_FAILED')
            self.assertFalse((Path(result['record']).parent / 'row-0002').exists())

    def test_late_source_drift_during_batch_resume_stops_remaining_rows(self):
        import aosp_agent.resume as resumption
        with GitFixture() as fx:
            entry.manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text('\n'.join([json.dumps(entry.row(fx))] * 2))
            runtime = QueueRuntime([(routing.ProjectFirstTest().assessment(), interrupt)])
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entry.ORIGIN: str(fx.repo)}, agent_options={'repository_keys': ['repo']},
                runtime_factory=runtime.factory)
            initial = runner.run(impact_only=True)
            self.assertEqual(initial['status'], 'CANCELLED', initial)
            original, calls = resumption.verify_stopped_sources, []
            def drift(root):
                calls.append(root)
                if len(calls) == 2:
                    (fx.repo / 'counter.py').write_text(FIXED)  # Uncooperative external writer.
                return original(root)
            with patch.object(resumption, 'verify_stopped_sources', side_effect=drift):
                result = resume_batch(runner.run_dir / 'batch-status.json')
            self.assertEqual(result['status'], 'BLOCKED', result)
            self.assertEqual(result['counts'], {'BLOCKED': 1})
            self.assertEqual(result['remaining_rows'], 1)
            self.assertFalse((Path(result['record']).parent / 'row-0002').exists())
            self.assertEqual((fx.repo / 'counter.py').read_text(), FIXED)  # Never auto-restore external changes.

    def test_cli_resume_reports_source_contention_as_blocked(self):
        with GitFixture() as fx:
            old = self.cancelled(fx)
            with source_lease(fx.source_root):
                result = subprocess.run([sys.executable, '-m', 'aosp_agent', 'resume', '--record',
                    str(old.run_dir / 'run.json')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 4, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['status'], 'BLOCKED')

    def test_batch_resume_rejects_active_child_before_any_new_row(self):
        with GitFixture() as fx:
            entry.manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text('\n'.join([json.dumps(entry.row(fx))] * 2))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entry.ORIGIN: str(fx.repo)})
            with patch.object(ProjectFirstAgent, '_prepare', side_effect=KeyboardInterrupt('stop')):
                result = runner.run(inspect_only=True)
            child = Path(result['rows'][0]['execution_record'])
            with run_lease(child.parent):
                with self.assertRaisesRegex(LeaseBusy, 'already active'):
                    resume_batch(runner.run_dir / 'batch-status.json')
            self.assertFalse((runner.run_dir / 'resumptions').exists())
            self.assertEqual(json.loads((runner.run_dir / 'batch-status.json').read_text()), result)

    def test_source_lease_blocks_different_tasks_and_parent_child_aliases(self):
        with GitFixture() as fx:
            alias = fx.root / 'alias'; alias.symlink_to(fx.source_root, target_is_directory=True)
            with source_lease(fx.source_root) as held:
                for root in (fx.source_root, fx.repo, alias, fx.root):
                    with self.subTest(root=root), self.assertRaises(LeaseBusy):
                        with source_lease(root):
                            self.fail('overlapping tree admitted')
                with source_lease(fx.repo, held):
                    pass  # A serial child explicitly inherits its parent's lease.
                agent = ProjectFirstAgent(routing.ProjectFirstTest().source(), fx.source_root,
                    fx.run_root, task_id='different-task', repository_keys=['repo'])
                with patch.object(agent, '_prepare', side_effect=AssertionError('blocked run read source')):
                    result = agent.run(inspect_only=True)
                self.assertEqual(result['status'], 'BLOCKED')
                with source_lease(fx.root / 'independent'):
                    pass
            with source_lease(fx.source_root):
                pass

    def test_batch_source_lease_contention_starts_no_rows(self):
        with GitFixture() as fx:
            path = fx.root / 'input.jsonl'; path.write_text(json.dumps(entry.row(fx)))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors')
            with source_lease(fx.source_root):
                result = runner.run(inspect_only=True)
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(result['rows'], [])
            self.assertEqual(result['remaining_rows'], 1)

    def test_verifier_inherits_source_lease_descriptor(self):
        from aosp_agent.validation_process import run_check
        with GitFixture() as fx, source_lease(fx.source_root):
            code = ('import json,os; from aosp_agent.lifecycle import SOURCE_LEASE_FD; '
                    'print(json.loads(os.pread(int(os.environ[SOURCE_LEASE_FD]),16384,0))["root"])')
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
            stdout, stderr, result = run_check([sys.executable, '-c', code], fx.root, env)
            self.assertEqual(result, 0, stderr)
            self.assertEqual(stdout.strip(), str(fx.source_root))

    def test_live_builder_keeps_source_lease_after_controller_crash(self):
        with GitFixture() as fx:
            started, release, finished, pidfile = (fx.root / name for name in ('started', 'release', 'finished', 'child-pid'))
            child = fx.root / 'child.py'
            child.write_text('import os,time\nfrom pathlib import Path\n'
                f'Path({str(pidfile)!r}).write_text(str(os.getpid()))\n'
                f'Path({str(started)!r}).touch()\n'
                f'while not Path({str(release)!r}).exists(): time.sleep(.02)\n'
                f'Path({str(finished)!r}).touch()\n')
            parent = fx.root / 'parent.py'
            parent.write_text('import os,sys,subprocess\n'
                'from aosp_agent.lifecycle import source_lease,source_subprocess_contract\n'
                f'with source_lease({str(fx.source_root)!r}):\n'
                ' env,fds=source_subprocess_contract(os.environ)\n'
                f' subprocess.Popen([sys.executable,{str(child)!r}],env=env,pass_fds=fds,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                ' os._exit(0)\n')
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
            process = subprocess.Popen([sys.executable, str(parent)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr)
                deadline = time.monotonic() + 5
                while not started.exists() and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(started.exists())
                with self.assertRaises(LeaseBusy):
                    with source_lease(fx.source_root):
                        self.fail('live inherited builder lease lost')
                release.touch()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        with source_lease(fx.source_root):
                            break
                    except LeaseBusy:
                        time.sleep(.02)
                else:
                    self.fail('source lease did not release after builder exit')
                self.assertTrue(finished.exists())
            finally:
                release.touch()
                if process.poll() is None:
                    process.kill(); process.communicate()

    def cancelled(self, fx, during_migration=False):
        replies = [(routing.ProjectFirstTest().assessment(), None if during_migration else interrupt)]
        if during_migration:
            def edit_and_stop(cwd):
                (cwd / 'repo/counter.py').write_text(FIXED)
                interrupt(cwd)
            replies.append(({}, edit_and_stop))
        runtime = QueueRuntime(replies)
        agent = ProjectFirstAgent(diff('counter.py', BASELINE, FIXED).encode(), fx.source_root, fx.run_root,
            catalog=routing.ProjectFirstTest().catalog(fx), repository_keys=['repo'], runtime_factory=runtime.factory,
            auto_validation=False, validation={'repo': [[sys.executable, '-B', 'verify_contract.py']]})
        result = agent.run(max_attempts=1, verify=True, impact_only=not during_migration)
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertEqual(result['cancellation_source_guard'], 'PASS')
        self.assertEqual(process_state(agent.run_dir), 'NO_ACTIVE_LEASE')
        return agent

    def test_cancelled_task_is_durable_and_resume_uses_fresh_candidate(self):
        with GitFixture() as fx:
            old = self.cancelled(fx, during_migration=True)
            old_candidate = old.run_dir / 'rounds/r01/workspace/repo/counter.py'
            self.assertEqual(old_candidate.read_text(), FIXED)
            def edit(cwd):
                candidate = cwd / 'repo/counter.py'
                self.assertEqual(candidate.read_text(), BASELINE)
                candidate.write_text(FIXED)
            coverage = {'summary': 'Bound count', 'limitations': [], 'coverage': [{
                'id': 'f001-h001', 'status': 'implemented', 'explanation': 'Both bounds implemented',
                'evidence': [{'path': 'repo/counter.py', 'line_start': 1, 'line_end': 2, 'excerpt': FIXED.strip()}]}]}
            runtime = QueueRuntime([(routing.ProjectFirstTest().assessment(), None), (coverage, edit)])
            result = resume_project(old.run_dir / 'run.json', runtime_factory=runtime.factory)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)
            self.assertNotEqual(Path(result['record']).parent, old.run_dir)
            self.assertEqual(json.loads((old.run_dir / 'run.json').read_text())['status'], 'CANCELLED')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertEqual(result['pinned_targets']['repo']['head'], fx.target)

    def test_live_lease_prevents_resume_and_status_detects_actual_lease(self):
        with GitFixture() as fx:
            old = self.cancelled(fx)
            with run_lease(old.run_dir):
                self.assertEqual(process_state(old.run_dir), 'ACTIVE_LEASE')
                with self.assertRaisesRegex(RuntimeError, 'already active'):
                    resume_project(old.run_dir / 'run.json')
            self.assertEqual(process_state(old.run_dir), 'NO_ACTIVE_LEASE')

    def test_changed_original_or_pending_restore_blocks_resume(self):
        for changed_source in (True, False):
            with self.subTest(changed_source=changed_source), GitFixture() as fx:
                old = self.cancelled(fx)
                if changed_source:
                    (fx.repo / 'counter.py').write_text(FIXED)
                    reason = 'original checkout changed'
                else:
                    path = old.run_dir / 'rounds/r01/module-build-restore/transaction.json'
                    path.parent.mkdir(); path.write_text(json.dumps({'restore': 'PENDING'}))
                    reason = 'restoration is not verified'
                with self.assertRaisesRegex(ValueError, reason):
                    resume_project(old.run_dir / 'run.json')

    def test_modified_resume_inputs_are_rejected(self):
        with GitFixture() as fx:
            old = self.cancelled(fx)
            (old.run_dir / 'input.patch').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'input patch changed'):
                resume_project(old.run_dir / 'run.json')

    def test_batch_cancellation_preserves_unstarted_rows(self):
        with GitFixture() as fx:
            entry.manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text('\n'.join([json.dumps(entry.row(fx))] * 2))
            runtime = QueueRuntime([({}, interrupt)])
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entry.ORIGIN: str(fx.repo)}, runtime_factory=runtime.factory)
            result = runner.run()
            self.assertEqual(result['status'], 'CANCELLED')
            self.assertEqual(result['remaining_rows'], 1)
            self.assertEqual(result['rows'][0]['status'], 'CANCELLED')
            self.assertFalse((runner.run_dir / 'row-0002').exists())

    def test_batch_resume_preserves_terminal_rows_and_runs_only_remaining_rows(self):
        from aosp_agent.runtime_input import resolve_sources
        with GitFixture() as fx:
            entry.manifest(fx)
            path = fx.root / 'input.jsonl'; path.write_text('\n'.join([json.dumps(entry.row(fx))] * 3))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors', donor_map={entry.ORIGIN: str(fx.repo)})
            calls = []
            def resolve(*args, **kwargs):
                calls.append(1)
                if len(calls) == 2:
                    raise KeyboardInterrupt('stop after first row')
                return resolve_sources(*args, **kwargs)
            with patch('aosp_agent.runtime_batch.resolve_sources', side_effect=resolve):
                initial = runner.run(inspect_only=True)
            self.assertEqual(initial['status'], 'CANCELLED')
            self.assertEqual(initial['rows'][0]['status'], 'DISCOVERED')
            with patch('aosp_agent.runtime_batch.resolve_sources', wraps=resolve_sources) as reads:
                result = resume_batch(runner.run_dir / 'batch-status.json')
            self.assertEqual(result['status'], 'COMPLETED', result)
            self.assertEqual(result['counts'], {'DISCOVERED': 3})
            self.assertEqual(reads.call_count, 2)
            self.assertEqual(result['rows'][0]['reused_terminal_record'], initial['rows'][0]['record'])
            self.assertEqual(json.loads((runner.run_dir / 'batch-status.json').read_text())['status'], 'CANCELLED')

    def test_sigterm_reaches_verifier_and_allows_graceful_cleanup(self):
        with GitFixture() as fx:
            started, restored, stopped = (fx.root / name for name in ('started', 'restored', 'parent-stopped'))
            child = fx.root / 'child.py'
            child.write_text('import signal,time\nfrom pathlib import Path\n'
                f'def stop(*args):\n Path({str(restored)!r}).write_text("restored")\n raise SystemExit(0)\n'
                f'signal.signal(signal.SIGTERM, stop)\nPath({str(started)!r}).write_text("started")\nwhile True: time.sleep(.05)\n')
            parent = fx.root / 'parent.py'
            parent.write_text('import os,sys\nfrom pathlib import Path\nfrom aosp_agent.lifecycle import cancellation_signals\n'
                'from aosp_agent.validation_process import run_check\n'
                f'try:\n with cancellation_signals(): run_check([sys.executable,{str(child)!r}], Path({str(fx.root)!r}), dict(os.environ), grace=3)\n'
                f'except KeyboardInterrupt: Path({str(stopped)!r}).write_text("stopped")\n')
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2]))
            process = subprocess.Popen([sys.executable, str(parent)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not started.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertTrue(started.exists())
                process.send_signal(signal.SIGTERM)
                _, stderr = process.communicate(timeout=6)
                self.assertEqual(process.returncode, 0, stderr)
                self.assertTrue(restored.exists())
                self.assertTrue(stopped.exists())
            finally:
                if process.poll() is None:
                    process.kill(); process.communicate()
