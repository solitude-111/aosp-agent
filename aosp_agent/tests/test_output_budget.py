"""Managed-output exhaustion must stop work without preventing restoration."""
from contextlib import ExitStack
from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aosp_agent.output_budget import (STATE, LOCK, OutputBudget, OutputBudgetExceeded,
    OutputBudgetUnavailable, create_budget, find_budget, write_bytes, write_json, write_text)
from aosp_agent.sdk_runtime import CodexRuntime
from engine_fixtures import BASELINE, FIXED, GitFixture
from scoped_provider_fixture import ScriptedProvider
from aosp_agent.sandbox_scope import ModelScope
from test_sdk_runtime import FakeCodex
import test_runtime_entrypoints as entrypoints


class OutputBudgetTest(unittest.TestCase):
    def test_nested_replacement_reservations_and_compact_terminal_are_persistent(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); budget = create_budget(root, 131072)
            child = root / 'rounds/r01'; child.mkdir(parents=True)
            inherited = create_budget(child, 8 * 1024 * 1024)
            self.assertEqual(inherited.root, root)
            limit = budget.data()['normal_limit']
            write_bytes(child / 'log', b'x' * (limit // 2))
            write_bytes(child / 'log', b'y' * (limit - limit // 2))
            record = {'status': 'VALIDATED', 'evidence': 'large' * 10000}
            with self.assertRaises(OutputBudgetExceeded):
                write_json(child / 'run.json', record, control=True)
            saved = json.loads((child / 'run.json').read_text())
            self.assertEqual(saved['status'], 'BLOCKED')
            self.assertEqual(saved['impact_decision'], 'UNKNOWN')
            self.assertNotIn('evidence', saved)
            self.assertEqual(record['status'], 'BLOCKED')
            with self.assertRaises(OutputBudgetExceeded): OutputBudget(root).check()
            with self.assertRaises(OutputBudgetExceeded): create_budget(child)
            with self.assertRaises(OutputBudgetExceeded): write_text(child / 'new', 'no')
            self.assertFalse((child / 'new').exists())
            # Even after the control reserve is spent, the quota marker blocks
            # a stale successful record and resume without depending on logs.
            while write_json(child / 'run.json', record, control=True): pass
            self.assertLessEqual(sum(p.stat().st_size for p in root.rglob('*') if p.is_file()), 131072)

    def test_separate_processes_cannot_overspend_shared_budget(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); budget = create_budget(root, 131072)
            code = ('from pathlib import Path\nimport sys\n'
                    'from aosp_agent.output_budget import write_bytes, OutputBudgetExceeded\n'
                    'try: write_bytes(Path(sys.argv[1])/sys.argv[2], b"x"*20000)\n'
                    'except OutputBudgetExceeded: raise SystemExit(4)\n')
            children = [subprocess.Popen([sys.executable, '-c', code, str(root), str(n)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE) for n in range(12)]
            for child in children:
                _, error = child.communicate(timeout=10)
                self.assertIn(child.returncode, (0, 4), error)
            self.assertEqual(sum(c.returncode == 0 for c in children), 5)
            state = budget.data()
            self.assertEqual(state['normal_reserved'], 100000)
            self.assertTrue(state['exhausted'])

    def test_corrupt_metadata_and_symlink_escape_fail_closed(self):
        variants = ['{', '[]', '{"version":1}', json.dumps(dict(version=1, limit=131072,
                    normal_limit=999999, normal_reserved=0, control_reserved=0, exhausted=False))]
        for value in variants:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); budget = create_budget(root, 131072)
                (root / STATE).write_text(value)
                with self.assertRaises(OutputBudgetUnavailable): budget.check()
                with self.assertRaises(OutputBudgetUnavailable): write_text(root / 'output', 'bad')
                self.assertFalse((root / 'output').exists())
        with tempfile.TemporaryDirectory() as raw, tempfile.TemporaryDirectory() as outside:
            root = Path(raw).resolve(); create_budget(root, 131072)
            (root / 'escape').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OutputBudgetUnavailable): write_text(root / 'escape/output', 'bad')
            self.assertFalse((Path(outside) / 'output').exists())
            (root / STATE).unlink(); (root / STATE).symlink_to(Path(outside) / 'missing')
            self.assertIsNotNone(find_budget(root / 'output'))
            with self.assertRaises(OutputBudgetUnavailable): write_text(root / 'output', 'bad')

    def test_lock_wait_is_bounded_and_failed_write_keeps_reservation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); budget = create_budget(root, 131072)
            fd = os.open(root / LOCK, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                start = time.monotonic()
                with self.assertRaises(OutputBudgetUnavailable): budget.check()
                self.assertLess(time.monotonic() - start, 4)
            finally: os.close(fd)
            with patch('aosp_agent.output_budget._atomic', side_effect=OSError('disk unavailable')):
                with self.assertRaises(OutputBudgetUnavailable): write_bytes(root / 'output', b'12345')
            self.assertEqual(budget.data()['normal_reserved'], 5)
            self.assertFalse((root / 'output').exists())

    def test_status_and_resume_cannot_reuse_stale_success_or_missing_record(self):
        from aosp_agent.resume import locked_attempt_chain
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); budget = create_budget(root, 131072)
                record = root / 'run.json'
                if not missing: write_json(record, {'status': 'VALIDATED'})
                with self.assertRaises(OutputBudgetExceeded): write_bytes(root / 'too-large', b'x' * 131072)
                output = subprocess.run([sys.executable, '-m', 'aosp_agent', 'status', '--record', str(record)],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(output.returncode, 0, output.stderr)
                state = json.loads(output.stdout)
                self.assertEqual(state['effective_status'], 'BLOCKED')
                self.assertEqual(state['completion_blocked_by'], 'OUTPUT_BUDGET_EXHAUSTED')
                with ExitStack() as leases, self.assertRaises(OutputBudgetExceeded):
                    locked_attempt_chain(record, leases)

    def test_cli_limit_reaches_both_default_and_exhaustive_diff(self):
        from test_diff_workflow import diff
        with GitFixture() as fx:
            source = fx.root / 'input.patch'; source.write_text(diff('counter.py', BASELINE, FIXED))
            for mode in ('default', 'exhaustive'):
                command = [sys.executable, '-m', 'aosp_agent', 'diff', '--patch', str(source),
                           '--target-root', str(fx.repo), '--run-root', str(fx.run_root / mode),
                           '--inspect-only', '--max-output-bytes', str(8 * 1024 * 1024)]
                if mode == 'exhaustive': command.append('--exhaustive-discovery')
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                record = Path(json.loads(result.stdout)['record'])
                self.assertEqual(find_budget(record).data()['limit'], 8 * 1024 * 1024)

    def test_actual_sdk_exhaustion_prevents_next_provider_request(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); create_budget(root, 131072)
            with ScriptedProvider(tool_calls=[]) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                with CodexRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                                  turn_timeout=20, read_scope=Scope((root,), ())) as runtime:
                    runtime.start(root, 'Harmless output budget test.')
                    with self.assertRaises(OutputBudgetExceeded): write_bytes(root / 'flood', b'x' * 131072)
                    with self.assertRaises(OutputBudgetExceeded): runtime.run('Do not execute.')
                    self.assertTrue(runtime._closed)
                self.assertEqual(provider.calls, 0)

    def test_actual_sdk_stream_exhaustion_is_not_returned_as_success(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); create_budget(root, 131072)
            meta = root / 'meta'; write_text(meta, 'harmless metadata')
            with ScriptedProvider(tool_calls=[('aosp_read_file', {'path': 'meta', 'start': 1, 'end': 1})],
                                  final_responses=['ordinary diagnostic ' * 12000]) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                with CodexRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                                  turn_timeout=20, read_scope=Scope((root,), ())) as runtime:
                    runtime.start(root, 'Harmless bounded output test.')
                    with self.assertRaises(OutputBudgetExceeded): runtime.run('Read metadata and report.')
                    self.assertTrue(runtime._closed)
                    self.assertTrue(runtime._broker.cancelled.is_set())
                self.assertGreater(provider.calls, 0)
                self.assertEqual(provider.tool_index, 1)
                self.assertLessEqual((root / 'events.jsonl').stat().st_size, 131072)

    def test_log_io_failure_does_not_prevent_sdk_close(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); create_budget(root, 131072); fake = FakeCodex(None, 'completed')
            with patch('openai_codex.AsyncCodex', return_value=fake):
                with CodexRuntime(root / 'events.jsonl') as runtime:
                    runtime.start(root, 'test')
                    with patch('aosp_agent.output_budget.write_text', side_effect=OSError('disk unavailable')):
                        with self.assertRaises(OutputBudgetUnavailable): runtime.run('test')
                        self.assertTrue(fake.closed)
                        self.assertTrue(runtime._closed)

    def test_optional_wrapper_log_only_tolerates_permission_denial(self):
        from aosp_agent.agent_tools import _optional_log
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); create_budget(root, 131072)
            for error in (PermissionError('readonly sandbox'), OSError(errno.EROFS, 'read-only mount')):
                with self.subTest(error=error), patch('aosp_agent.output_budget.os.open', side_effect=error):
                    _optional_log(root / 'usage', 'ordinary marker')
            for code in (errno.ENOSPC, errno.EIO, errno.ENOENT):
                with self.subTest(errno=code), patch('aosp_agent.output_budget.os.open', side_effect=OSError(code, 'storage failure')):
                    with self.assertRaises(OutputBudgetUnavailable): _optional_log(root / 'usage', 'marker')
            with self.assertRaises(OutputBudgetExceeded): _optional_log(root / 'usage', 'x' * 131072)
            self.assertFalse((root / 'usage').exists())

    def test_batch_exhaustion_stops_remaining_rows_and_preserves_original_source(self):
        from aosp_agent.runtime_batch import RuntimeBatch
        with GitFixture() as fx:
            entrypoints.manifest(fx)
            path = fx.root / 'input.jsonl'
            path.write_text('\n'.join(json.dumps(entrypoints.row(fx)) for _ in range(2)))
            def factory(**kwargs):
                write_bytes(kwargs['events_path'], b'x' * (8 * 1024 * 1024))
                self.fail('exhausted model should not be created')
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entrypoints.ORIGIN: str(fx.repo)}, runtime_factory=factory,
                agent_options={'repository_keys': ['repo'], 'max_output_bytes': 4 * 1024 * 1024})
            result = runner.run()
            self.assertEqual(result['status'], 'BLOCKED')
            self.assertEqual(len(result['rows']), 1)
            self.assertEqual(result['rows'][0]['status'], 'BLOCKED')
            self.assertFalse((runner.run_dir / 'row-0002').exists())
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertEqual(json.loads((runner.run_dir / 'batch-status.json').read_text())['status'], 'BLOCKED')

    def test_real_build_restores_before_verification_log_exhausts_budget(self):
        from aosp_agent.engine import AospBackportAgent
        from aosp_agent.validation_process import run_check
        with GitFixture() as fx:
            builder = fx.root / 'builder.py'
            builder.write_text('import os, sys\nfrom pathlib import Path\n'
                + f'sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})\n'
                + 'from aosp_agent.build_transaction import transaction\n'
                + 'if "--build-only" not in sys.argv:\n'
                + f' raise SystemExit(transaction({str(fx.source_root)!r}, {str(fx.root / "build.lock")!r}, '
                  '[sys.executable, __file__, "--build-only"]))\n'
                + f'assert (Path(os.environ["AOSP_AGENT_TARGET_REPO"]) / "counter.py").read_text() == {FIXED!r}\n'
                + 'print("ordinary build diagnostic")\n')
            check = {'stage': 'android_module_build', 'argv': [sys.executable, '-B', str(builder)]}
            agent = AospBackportAgent(fx.source_root, fx.run_root,
                replace(fx.case(), validation_checks=(check,)), max_output_bytes=4 * 1024 * 1024)
            agent.prepare(); (agent.worktree / 'counter.py').write_text(FIXED); agent.export_patch(1)
            def fill_after_build(*args, **kwargs):
                result = run_check(*args, **kwargs)
                self.assertEqual(result[2], 0)
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
                state = agent.output_budget.data()
                write_bytes(agent.run_dir / 'fill', b'x' * (state['normal_limit'] - state['normal_reserved']))
                return result
            with patch('aosp_agent.engine.run_check', side_effect=fill_after_build):
                with self.assertRaises(OutputBudgetExceeded): agent.verify()
            receipt = json.loads((agent.run_dir / 'module-build-restore/transaction.json').read_text())
            self.assertEqual(receipt['restore'], 'PASS')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertNotEqual(agent.record['status'], 'VALIDATED')
            with patch('aosp_agent.engine.run_check') as another_build:
                with self.assertRaises(OutputBudgetExceeded): agent.verify()
                another_build.assert_not_called()

    def test_inheritance_result_overflow_cannot_return_inherit_verdict(self):
        from aosp_agent.inherit import analyze_inheritance
        with GitFixture() as fx:
            with patch('aosp_agent.inherit._analyze_inheritance', return_value={
                    'verdict': 'INHERIT', 'reasoning': 'x' * 131072}):
                with self.assertRaises(OutputBudgetExceeded) as caught:
                    analyze_inheritance('ordinary-fixture', fx.root / 'fix.patch', fx.source_root,
                        'repo', ['counter.py'], fx.target, fx.target, run_root=fx.run_root,
                        max_output_bytes=131072)
            record = json.loads(Path(caught.exception.inheritance_result_file).read_text())
            self.assertEqual(record['status'], 'BLOCKED')
            self.assertEqual(record['verdict'], 'ERROR')


if __name__ == '__main__': unittest.main()
