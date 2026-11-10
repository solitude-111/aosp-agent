"""OS SIGTERM reaches real batch/view/runtime finally blocks without a model."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.lifecycle import run_lease, source_lease
from aosp_agent.preparation import write_receipt
from aosp_agent.runtime_children import verify_run_children
from aosp_agent.server_config import validate_config, config_digest
from aosp_agent.unattended import CANCELLATION_CLEANUP_SECONDS, main
from engine_fixtures import GitFixture, git
from test_preparation import setup


WORKER = r'''
import asyncio, json, subprocess, sys, time, types
from pathlib import Path
from unittest.mock import patch
from test_preparation import MemoryMounts
from test_sdk_runtime import FakeCodex, FakeHandle
from aosp_agent.sdk_runtime import CodexRuntime
from aosp_agent.runtime_batch import RuntimeBatch
from aosp_agent.unattended import main

request = Path(sys.argv[1]); root = request.parent
class Views(MemoryMounts):
 def __init__(self, *args): super().__init__()
 def command(self, args): pass
 def unmount(self, root_path):
  super().unmount(root_path)
  (root / 'view-released').write_text(root_path)

class OfflineTransport(FakeCodex):
 def __init__(self, config):
  super().__init__(config, 'completed')
  child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  self._client = types.SimpleNamespace(_sync=types.SimpleNamespace(_proc=child))
 async def close(self):
  child = self._client._sync._proc
  child.terminate(); child.wait(timeout=5)
  await super().close()
  (root / 'sdk-closed').write_text(str(child.pid))

async def waiting(handle):
 (root / 'ready').write_text('waiting inside runtime turn')
 try:
  await asyncio.sleep(60)
 finally:
  await asyncio.sleep(.03)
  (root / 'async-cleaned').write_text('the turn finally completed')
  if sys.argv[2] == 'cleanup_failure':
   raise RuntimeError('offline cleanup could not establish its postcondition')
 if False: yield None

original_init = RuntimeBatch.__init__
def batch_init(self, *args, **kwargs):
 # Offline transport exercises the real runtime's cancellation and child
 # cleanup. No source/model tool is invoked, so this test needs no SDK sandbox.
 kwargs['runtime_factory'] = lambda **options: CodexRuntime(**{**options, 'read_scope': None})
 original_init(self, *args, **kwargs)

with patch('aosp_agent.unattended.LinuxOverlays', Views), \
     patch.object(RuntimeBatch, '__init__', batch_init), \
     patch('openai_codex.AsyncCodex', OfflineTransport), \
     patch.object(FakeHandle, 'stream', waiting):
 raise SystemExit(main(['--worker-request', str(request)]))
'''


class UnattendedCancellationTest(unittest.TestCase):
    def test_sigterm_saves_cancelled_and_closes_runtime_view_and_leases(self):
        self.exercise_signal()

    def test_sigterm_cleanup_error_blocks_instead_of_reporting_cancelled(self):
        self.exercise_signal(cleanup_failure=True)

    def exercise_signal(self, cleanup_failure=False):
        with GitFixture() as fixture:
            raw, row = setup(fixture)
            raw['batch_limits'] = {'min_free_bytes': 1}
            config = validate_config(raw)
            input_path = fixture.root / 'input.jsonl'
            input_path.write_text(json.dumps(row) + '\n')
            request = fixture.run_root / 'launch-request.json'
            write_receipt(request, {'config': config, 'config_sha256': config_digest(config),
                'parent_namespace': 'test', 'input': str(input_path), 'inspect_only': False})
            process = subprocess.Popen([sys.executable, '-c', WORKER, str(request),
                'cleanup_failure' if cleanup_failure else 'clean'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                deadline = time.monotonic() + 20
                while not (fixture.run_root / 'ready').is_file():
                    if process.poll() is not None:
                        out, err = process.communicate()
                        self.fail('worker exited before signal: ' + out + err)
                    if time.monotonic() > deadline:
                        self.fail('worker did not reach offline runtime')
                    time.sleep(.02)
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 4 if cleanup_failure else 130, out + err)
                expected_status = 'BLOCKED' if cleanup_failure else 'CANCELLED'
                launcher = json.loads((fixture.run_root / 'launcher-status.json').read_text())
                self.assertEqual(launcher['state'], expected_status, launcher)
                batch_path = Path(launcher['batch_record'])
                batch = json.loads(batch_path.read_text())
                self.assertEqual(batch['status'], expected_status, batch)
                result = batch['rows'][0]
                self.assertEqual(result['status'], expected_status, result)
                execution = json.loads(Path(result['execution_record']).read_text())
                self.assertEqual(execution['status'], expected_status, execution)
                if cleanup_failure:
                    self.assertEqual(execution['completion_blocked_by'], 'BACKGROUND_CLEANUP_FAILED')
                accounting = json.loads((Path(result['execution_record']).parent / 'execution-budget.json').read_text())
                self.assertFalse(accounting['active_operations'], err)
                self.assertIsNone(accounting['active_session'], err)
                self.assertEqual(accounting['io_reserved'], 0)
                self.assertEqual(accounting['reservations'], {})
                self.assertNotIn('Task was destroyed but it is pending', err)
                self.assertNotIn('created in a different Context', err)
                preparation = json.loads(Path(result['preparation_receipt']).read_text())
                self.assertEqual((preparation['state'], preparation['restoration']), ('RELEASED', 'PASS'))
                self.assertTrue((fixture.run_root / 'sdk-closed').is_file())
                self.assertTrue((fixture.run_root / 'async-cleaned').is_file())
                self.assertTrue((fixture.run_root / 'view-released').is_file())
                verify_run_children(batch_path.parent)
                with run_lease(batch_path.parent), source_lease(fixture.source_root):
                    self.assertEqual(git(fixture.repo, 'status', '--porcelain'), '')
                    ledger = ExecutionBudget(Path(result['execution_record']).parent,
                                             accounting['input_sha256'], existing=True)
                    ledger.recover_stopped()
                    self.assertEqual(ledger.snapshot()['execution_ms'], accounting['execution_ms'])
                    self.assertEqual(ledger.snapshot()['recovery_settlements'], accounting['recovery_settlements'])
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=5)

    def test_launcher_sigkill_only_after_finite_cleanup_deadline(self):
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out), GitFixture() as fixture:
                raw, row = setup(fixture)
                config_path = fixture.root / 'server.json'
                config_path.write_text(json.dumps(raw))
                input_path = fixture.root / 'input.jsonl'
                input_path.write_text(json.dumps(row) + '\n')
                process = Mock(pid=98765)
                process.poll.return_value = None
                process.wait.side_effect = ([KeyboardInterrupt(),
                    subprocess.TimeoutExpired('namespace worker', CANCELLATION_CLEANUP_SECONDS), -9]
                    if timed_out else [KeyboardInterrupt(), 130])
                with patch('aosp_agent.unattended.sys.platform', 'linux'), \
                     patch('aosp_agent.unattended.shutil.which', return_value='/usr/bin/unshare'), \
                     patch('aosp_agent.unattended.os.readlink', return_value='mnt:test'), \
                     patch('aosp_agent.unattended.subprocess.Popen', return_value=process), \
                     patch('aosp_agent.unattended.os.killpg') as kill, \
                     patch('aosp_agent.unattended._code_identity', return_value={}):
                    code = main([str(input_path), '--config', str(config_path)])
                self.assertEqual(code, -9 if timed_out else 130)
                self.assertLessEqual(process.wait.call_args_list[1].kwargs['timeout'],
                                     CANCELLATION_CLEANUP_SECONDS)
                self.assertGreater(process.wait.call_args_list[1].kwargs['timeout'],
                                   CANCELLATION_CLEANUP_SECONDS - 1)
                self.assertEqual(kill.call_args_list[0].args, (98765, signal.SIGTERM))
                self.assertEqual(kill.call_count, 2 if timed_out else 1)
                if timed_out:
                    self.assertEqual(kill.call_args_list[1].args, (98765, signal.SIGKILL))

    def test_exited_wrapper_waits_for_worker_receipt_without_refreshing_deadline_or_kill(self):
        for finishes, wrapper_code in ((False, -signal.SIGTERM), (False, 0), (True, -signal.SIGTERM)):
            with self.subTest(finishes=finishes, wrapper_code=wrapper_code), GitFixture() as fixture:
                raw, row = setup(fixture)
                config = validate_config(raw)
                config_path = fixture.root / 'server.json'
                config_path.write_text(json.dumps(raw))
                input_path = fixture.root / 'input.jsonl'
                input_path.write_text(json.dumps(row) + '\n')
                clock = [0.0]
                saved = {}
                process = Mock(pid=98765)
                process.poll.return_value = wrapper_code
                def spawn(command, **kwargs):
                    saved['path'] = Path(command[-1]).parent / 'launcher-status.json'
                    write_receipt(saved['path'], {'state': 'RUNNING', 'process_id': 12345,
                                                 'config_sha256': config_digest(config)})
                    return process
                def wrapper_wait(**kwargs):
                    if not kwargs:
                        raise KeyboardInterrupt()
                    self.assertEqual(kwargs['timeout'], CANCELLATION_CLEANUP_SECONDS)
                    clock[0] = CANCELLATION_CLEANUP_SECONDS - 1
                    return wrapper_code
                process.wait.side_effect = wrapper_wait
                sleeps = []
                def worker_cleanup(seconds):
                    clock[0] += seconds
                    sleeps.append(seconds)
                    if finishes and len(sleeps) == 2:
                        write_receipt(saved['path'], {'state': 'CANCELLED', 'process_id': 12345,
                                                     'config_sha256': config_digest(config)})
                with patch('aosp_agent.unattended.sys.platform', 'linux'), \
                     patch('aosp_agent.unattended.shutil.which', return_value='/usr/bin/unshare'), \
                     patch('aosp_agent.unattended.os.readlink', return_value='mnt:test'), \
                     patch('aosp_agent.unattended.subprocess.Popen', side_effect=spawn), \
                     patch('aosp_agent.unattended.os.killpg') as kill, \
                     patch('aosp_agent.unattended._code_identity', return_value={}), \
                     patch('aosp_agent.unattended.time.monotonic', side_effect=lambda: clock[0]), \
                     patch('aosp_agent.unattended.time.sleep', side_effect=worker_cleanup):
                    code = main([str(input_path), '--config', str(config_path)])
                status = json.loads(saved['path'].read_text())
                self.assertEqual(status['state'], 'CANCELLED' if finishes else 'INTERRUPTED')
                self.assertEqual(code, 130 if finishes else (wrapper_code or 4))
                kill.assert_called_once_with(98765, signal.SIGTERM)
                self.assertLessEqual(sum(sleeps), 1.001)
                if not finishes:
                    self.assertEqual(status['cleanup'], 'UNVERIFIED')
                    self.assertEqual(status['completion_blocked_by'], 'CANCELLATION_CLEANUP_UNVERIFIED')
                    self.assertEqual(clock[0], CANCELLATION_CLEANUP_SECONDS)


if __name__ == '__main__':
    unittest.main()
