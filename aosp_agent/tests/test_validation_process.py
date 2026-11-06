"""Real process lifecycle checks, independent of build-receipt fixtures."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aosp_agent.validation_process import run_check, VerifierCleanupBlocked


class ValidationProcessTest(unittest.TestCase):
    def test_combined_output_limit_keeps_draining_during_restoration(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / 'restored'
            script = ('import os,signal,sys\nfrom pathlib import Path\n'
                      'def restore(*args):\n'
                      '    os.write(1, b"restoration-log" * 10000)\n'
                      f'    Path({str(marker)!r}).touch()\n'
                      '    print("RESTORED", flush=True)\n    sys.exit(0)\n'
                      'signal.signal(signal.SIGTERM, restore)\n'
                      'while True:\n    os.write(1, b"x"*8192)\n    os.write(2, b"y"*8192)\n')
            start = time.monotonic()
            out, err, code = run_check([sys.executable, '-c', script], raw, dict(os.environ),
                                      timeout=5, grace=2, output_limit=32768)
            self.assertEqual(code, 125)
            self.assertIn('output limit exceeded', err)
            self.assertTrue(marker.exists())
            self.assertIn('RESTORED', out)
            self.assertLess(len(out), 1100000)
            self.assertLess(len(err), 1100000)
            self.assertLess(time.monotonic() - start, 4)

    def test_fast_successful_producer_over_limit_is_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            out, err, code = run_check([sys.executable, '-c',
                'import os; os.write(1,b"a"*12000); os.write(2,b"b"*12000)'], raw,
                dict(os.environ), timeout=5, output_limit=20000)
            self.assertEqual(code, 125)
            self.assertIn('output limit exceeded', err)

    def test_capture_start_failure_still_cleans_process_group(self):
        with tempfile.TemporaryDirectory() as raw:
            marker = Path(raw) / 'late'
            script = f'import time; from pathlib import Path; time.sleep(.4); Path({str(marker)!r}).touch()'
            with patch('aosp_agent.output_capture.OutputCapture.start', side_effect=RuntimeError('reader unavailable')):
                with self.assertRaisesRegex(RuntimeError, 'reader unavailable'):
                    run_check([sys.executable, '-c', script], raw, dict(os.environ), timeout=5, grace=.1)
            time.sleep(.5)
            self.assertFalse(marker.exists())

    def test_redirected_and_inherited_children_stop_on_success_and_failure(self):
        for redirect in (False, True):
            for code in (0, 7):
                with self.subTest(redirect=redirect, code=code), tempfile.TemporaryDirectory() as raw:
                    root = Path(raw)
                    ready, marker = root / 'ready', root / 'late-write'
                    child = ('import time; from pathlib import Path; '
                             f'Path({str(ready)!r}).touch(); time.sleep(.6); '
                             f'Path({str(marker)!r}).write_text("late")')
                    kwargs = ', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL' if redirect else ''
                    parent = ('import subprocess,sys,time; from pathlib import Path\n'
                              f'subprocess.Popen([sys.executable,"-c",{child!r}]{kwargs})\n'
                              f'while not Path({str(ready)!r}).exists(): time.sleep(.01)\n'
                              f'print("parent output", flush=True)\nraise SystemExit({code})\n')
                    stdout, stderr, result = run_check([sys.executable, '-c', parent], root, dict(os.environ), timeout=5, grace=.2)
                    self.assertEqual(result, code, stderr)
                    self.assertIn('parent output', stdout)
                    self.assertTrue(ready.exists())
                    time.sleep(.7)
                    self.assertFalse(marker.exists(), 'child wrote after verifier completion')

    def test_timeout_escalates_when_term_is_ignored(self):
        with tempfile.TemporaryDirectory() as raw:
            started = time.monotonic()
            script = 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print("started",flush=True); time.sleep(30)'
            stdout, stderr, code = run_check([sys.executable, '-c', script], raw, dict(os.environ), timeout=.3, grace=.1)
            self.assertEqual(code, 124)
            self.assertIn('started', stdout)
            self.assertIn('timed out', stderr)
            self.assertLess(time.monotonic() - started, 5)

    def test_output_is_bounded_with_explicit_truncation_and_both_ends(self):
        with tempfile.TemporaryDirectory() as raw:
            script = 'import sys; print("BEGIN" + "x" * 2000000 + "END"); print("error",file=sys.stderr); sys.exit(7)'
            stdout, stderr, code = run_check([sys.executable, '-c', script], raw, dict(os.environ), timeout=5)
            self.assertEqual(code, 7)
            self.assertTrue(stdout.startswith('BEGIN'))
            self.assertTrue(stdout.endswith('END\n'))
            self.assertIn('output truncated', stdout)
            self.assertLess(len(stdout), 1100000)
            self.assertEqual(stderr, 'error\n')

    def test_cleanup_failure_cannot_return_success(self):
        with tempfile.TemporaryDirectory() as raw, patch('aosp_agent.validation_process.stop_group', side_effect=RuntimeError('unverified group')):
            with self.assertRaisesRegex(VerifierCleanupBlocked, 'cannot confirm verifier'):
                run_check([sys.executable, '-c', 'pass'], raw, dict(os.environ), timeout=5)
