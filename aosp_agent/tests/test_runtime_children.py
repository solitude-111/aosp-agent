from pathlib import Path
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.runtime_children import RuntimeChild, identity_state, process_identity, require_stopped, verify_run_children


class RuntimeChildrenTest(unittest.TestCase):
    def test_runtime_timeout_persists_exit_receipt_for_its_actual_process_handle(self):
        from aosp_agent.sdk_runtime import CodexRuntime, CodexRuntimeError
        from test_sdk_runtime import FakeCodex
        class ChildCodex(FakeCodex):
            def __init__(self, config):
                super().__init__(config, 'timeout')
                self.child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self._client = SimpleNamespace(_sync=SimpleNamespace(_proc=self.child))

            async def close(self):
                await super().close()
                self.child.stdin.close()
                self.child.wait(timeout=10)
                self._client._sync._proc = None  # Mirrors the inspected SDK close contract.

        with tempfile.TemporaryDirectory() as directory, patch('openai_codex.AsyncCodex', ChildCodex):
            root = Path(directory)
            runtime = CodexRuntime(root / 'sdk-events.jsonl', turn_timeout=.05)
            with self.assertRaises(CodexRuntimeError) as caught:
                with runtime:
                    runtime.start(root, 'fixture')
                    runtime.run('fixture')
            self.assertEqual(caught.exception.kind, 'TIMEOUT')
            reference = runtime.recovery_child()
            receipt = json.loads(Path(reference['record']).read_text())
            self.assertEqual(receipt['cleanup'], 'EXITED')
            self.assertEqual(require_stopped(reference, root)['status'], 'EXITED')

    def test_live_exact_child_blocks_and_waited_exit_allows_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                tracker = RuntimeChild(Path(directory) / 'sdk-events.jsonl', process)
                reference = tracker.reference()
                self.assertEqual(identity_state(reference['identity']), 'ALIVE')
                with self.assertRaisesRegex(RecoveryBlocked, 'ALIVE'):
                    require_stopped(reference, directory)
                # This also guards read-only sessions, which never register a
                # candidate attempt and therefore cannot rely on salvage scans.
                with self.assertRaisesRegex(RecoveryBlocked, 'ALIVE'):
                    verify_run_children(directory)
                process.stdin.close()
                process.wait(timeout=10)
                self.assertEqual(tracker.finish(), 'EXITED')
                self.assertEqual(require_stopped(reference, directory)['status'], 'EXITED')
                self.assertEqual(len(verify_run_children(directory)['children']), 1)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                if not process.stdin.closed:
                    process.stdin.close()

    def test_unknown_transport_cannot_claim_safe_interruption_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            tracker = RuntimeChild(Path(directory) / 'sdk-events.jsonl', None)
            self.assertEqual(tracker.finish(), 'UNKNOWN')
            with self.assertRaisesRegex(RecoveryBlocked, 'UNKNOWN'):
                require_stopped(tracker.reference(), directory)
            with self.assertRaisesRegex(RecoveryBlocked, 'UNKNOWN'):
                verify_run_children(directory)

    def test_reused_pid_is_not_the_recorded_runtime_and_identity_errors_are_unknown(self):
        import os
        identity = process_identity(os.getpid())
        reused = {**identity, 'start_ticks' if identity['platform'] == 'linux' else 'start_usec': 0}
        with patch('aosp_agent.runtime_children.process_identity', return_value=reused):
            self.assertEqual(identity_state(identity), 'EXITED_ID_REUSED')
        with patch('aosp_agent.runtime_children.process_identity', side_effect=PermissionError('cannot inspect')):
            self.assertEqual(identity_state(identity), 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
