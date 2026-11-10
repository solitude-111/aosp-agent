import contextlib
import io
import json
import subprocess
from pathlib import Path
from unittest import TestCase, mock

from engine_fixtures import GitFixture
from test_preparation import setup, MemoryMounts
from aosp_agent.preparation import PreparationManager, PreparationBlocked, write_receipt
from aosp_agent.server_config import validate_config, config_digest
from aosp_agent.runtime_batch import RuntimeBatch
from aosp_agent.unattended import main, _worker, _code_identity


class UnattendedTest(TestCase):
    def test_resumed_execution_retains_isolation_requirement(self):
        from aosp_agent.resume import resume_batch, resume_project
        from aosp_agent.lifecycle import RecoveryBlocked
        with GitFixture() as f:
            raw, row = setup(f); raw['batch_limits'] = {'min_free_bytes': 1}
            path = f.root / 'input.jsonl'; path.write_text(json.dumps(row) + '\n')
            manager = PreparationManager(raw, overlays=MemoryMounts())
            runner = RuntimeBatch(path, f.source_root, f.run_root, raw['donor_root'], preparer=manager,
                runtime_factory=lambda **kw: self.fail('inspection started a model'))
            result = runner.run(inspect_only=True)
            execution_path = Path(result['rows'][0]['execution_record'])
            execution = json.loads(execution_path.read_text())
            self.assertEqual(execution['status'], 'DISCOVERED')
            execution['status'] = 'CANCELLED'
            write_receipt(execution_path, execution)
            result['status'] = 'CANCELLED'; result['rows'][0]['status'] = 'CANCELLED'
            batch_path = runner.run_dir / 'batch-status.json'; write_receipt(batch_path, result)
            resumed = resume_batch(batch_path, preparer=PreparationManager(raw, overlays=MemoryMounts()),
                runtime_factory=lambda **kw: self.fail('resumed inspection started a model'))
            self.assertEqual(resumed['rows'][0]['status'], 'DISCOVERED', resumed)
            child_path = Path(resumed['rows'][0]['execution_record'])
            child = json.loads(child_path.read_text())
            self.assertEqual(child['preparation_receipt'], execution['preparation_receipt'])
            child['status'] = 'CANCELLED'; write_receipt(child_path, child)
            with self.assertRaisesRegex(RecoveryBlocked, 'run-patches --resume'):
                resume_project(child_path)

    def test_archive_commit_requires_matching_deployment_identity(self):
        with GitFixture() as f:
            module = f.root / 'aosp_agent/unattended.py'; module.parent.mkdir(); module.touch()
            path = f.root / 'deployment.json'
            path.write_text(json.dumps({'commit': '1' * 40, 'code_sha256': 'a' * 64}))
            with mock.patch('aosp_agent.unattended.__file__', str(module)), \
                 mock.patch('aosp_agent.unattended.subprocess.run', return_value=subprocess.CompletedProcess([], 128, '', '')), \
                 mock.patch('aosp_agent.checkpoint.code_identity', return_value='a' * 64):
                self.assertEqual(_code_identity()['commit'], '1' * 40)
                path.write_text(json.dumps({'commit': '1' * 40, 'code_sha256': 'b' * 64}))
                self.assertIsNone(_code_identity()['commit'])

    def test_print_config_never_starts_namespace_or_model(self):
        with GitFixture() as f:
            raw, _ = setup(f)
            path = f.root / 'server.json'; path.write_text(json.dumps(raw))
            with mock.patch('aosp_agent.unattended.subprocess.Popen') as spawn, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(['--config', str(path), '--print-config', '--model', 'explicit']), 0)
            spawn.assert_not_called()
            self.assertEqual(json.loads(out.getvalue())['agent']['model'], 'explicit')

    def test_namespace_failure_writes_terminal_launch_receipt(self):
        with GitFixture() as f:
            raw, _ = setup(f); config = validate_config(raw)
            path = f.run_root / 'launch-request.json'
            write_receipt(path, {'config': config, 'config_sha256': config_digest(config), 'parent_namespace': 'test'})
            with mock.patch('aosp_agent.unattended.LinuxOverlays.check_namespace',
                            side_effect=PreparationBlocked('ISOLATION_UNAVAILABLE', 'no namespace')):
                with self.assertRaises(PreparationBlocked): _worker(path)
            result = json.loads((path.parent / 'launcher-status.json').read_text())
            self.assertEqual(result['state'], 'BLOCKED')
            self.assertEqual(result['error']['kind'], 'ISOLATION_UNAVAILABLE')

    def test_real_batch_prepares_two_valid_rows_and_retains_invalid_row(self):
        with GitFixture() as f:
            raw, row = setup(f); raw['batch_limits'] = {'min_free_bytes': 1}
            path = f.root / 'input.jsonl'
            path.write_text(json.dumps(row) + '\ninvalid\n' + json.dumps(row))
            mounts = MemoryMounts(); preparer = PreparationManager(raw, overlays=mounts)
            runner = RuntimeBatch(path, f.source_root, f.run_root, raw['donor_root'], preparer=preparer,
                runtime_factory=lambda **kw: self.fail('inspect-only started a model'))
            outcome = runner.run(inspect_only=True)
            self.assertEqual(outcome['status'], 'COMPLETED', outcome)
            self.assertEqual([r['status'] for r in outcome['rows']], ['DISCOVERED', 'FAILED', 'DISCOVERED'], outcome)
            self.assertEqual(outcome['batch_budget']['model_calls'], 0)
            self.assertFalse(mounts.mounted)
            self.assertNotEqual(mounts.calls[0][1], mounts.calls[1][1])
            for row in (outcome['rows'][0], outcome['rows'][2]):
                self.assertEqual(json.loads(Path(row['preparation_receipt']).read_text())['restoration'], 'PASS')
                self.assertEqual(json.loads(Path(row['execution_record']).read_text())['preparation_receipt'], row['preparation_receipt'])
            self.assertTrue(Path(outcome['preparation_frozen_receipt']).is_file())
