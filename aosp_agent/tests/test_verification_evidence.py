"""Regressions for skipped checks, stale outputs and exact build receipts."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from aosp_agent.build_transaction import transaction
from aosp_agent.engine import AospBackportAgent
from engine_fixtures import BASELINE, FIXED, GitFixture, ScriptedRuntime, write_counter


class VerificationEvidenceTest(unittest.TestCase):
    def test_output_exhaustion_preserves_actual_transaction_restoration(self):
        from aosp_agent.validation_process import run_check as actual_run_check
        with GitFixture() as fx:
            builder = fx.root / 'noisy-builder.py'
            builder.write_text('import os, sys\nfrom pathlib import Path\n'
                + f'sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})\n'
                + 'from aosp_agent.build_transaction import transaction\n'
                + 'if "--build-only" not in sys.argv:\n'
                + f' raise SystemExit(transaction({str(fx.source_root)!r}, {str(fx.root / "build.lock")!r}, '
                  '[sys.executable, __file__, "--build-only"]))\n'
                + f'assert (Path(os.environ["AOSP_AGENT_TARGET_REPO"]) / "counter.py").read_text() == {FIXED!r}\n'
                + 'while True: os.write(1, b"ordinary build diagnostic\\n"*1024)\n')
            agent = self.agent(fx, [self.check('android_module_build', str(builder))])
            def limited(*args, **kwargs):
                return actual_run_check(*args, **kwargs, output_limit=32768, grace=3)
            with patch('aosp_agent.engine.run_check', side_effect=limited):
                result = agent.verify()
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['sufficient_for_validated'])
            self.assertEqual(result['commands'][0]['returncode'], 125)
            receipt = json.loads((agent.run_dir / 'module-build-restore/transaction.json').read_text())
            self.assertEqual(receipt['restore'], 'PASS')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def agent(self, fx, checks):
        agent = AospBackportAgent(fx.source_root, fx.run_root, replace(fx.case(), validation_checks=tuple(checks)))
        agent.prepare()
        (agent.worktree / 'counter.py').write_text(FIXED)
        agent.export_patch(1)
        return agent

    def check(self, stage, name='check_lower.py', artifacts=()):
        return {'stage': stage, 'argv': [sys.executable, '-B', name], 'artifacts': list(artifacts)}

    def test_generic_noop_and_arbitrary_stage_pass_do_not_satisfy_production_policy(self):
        for stage in ('configured', 'custom_security_test', 'source_extracted_jvm', 'android_runtime'):
            with self.subTest(stage=stage), GitFixture() as fx:
                script = fx.root / 'noop.py'; script.write_text('pass\n')
                agent = self.agent(fx, [self.check(stage, str(script))])
                result = agent.verify()
                self.assertEqual(result['status'], 'PASS')
                self.assertFalse(result['sufficient_for_validated'])
                self.assertEqual(result['policy']['missing_build_repositories'], ['repo'])
                self.assertFalse(result['runtime_security_proven'])

    def test_full_workflow_requires_build_receipt_and_all_configured_checks(self):
        # A real temporary build transaction with a normal Python compilation
        # exercises the acceptance path. It is not an Android build claim.
        for fail_check in (False, True):
            with self.subTest(fail_check=fail_check), GitFixture() as fx:
                builder = fx.root / 'builder.py'
                builder.write_text('import os, sys\nfrom pathlib import Path\n'
                    + f'sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})\n'
                    + 'from aosp_agent.build_transaction import transaction\n'
                    + 'if "--build-only" not in sys.argv:\n'
                    + f'    raise SystemExit(transaction({str(fx.source_root)!r}, {str(fx.root / "build.lock")!r}, '
                      '[sys.executable, __file__, "--build-only"]))\n'
                    + 'target = Path(os.environ["AOSP_AGENT_TARGET_REPO"]) / "counter.py"\n'
                    + 'compile(target.read_text(), str(target), "exec")\n')
                checks = [self.check('android_module_build', str(builder)), self.check('configured', 'verify_contract.py')]
                if fail_check:
                    failing = fx.root / 'failing.py'; failing.write_text('raise SystemExit(7)\n')
                    checks.append(self.check('configured', str(failing)))
                runtime = ScriptedRuntime(fx.assessment(), [write_counter(FIXED)])
                agent = AospBackportAgent(fx.source_root, fx.run_root,
                    replace(fx.case(), validation_checks=tuple(checks)), runtime_factory=runtime.factory)
                result = agent.run(verify=True, max_attempts=1)
                self.assertEqual(result['status'], 'VALIDATION_FAILED' if fail_check else 'VALIDATED')
                verification = result['final_verification']
                self.assertTrue(verification['commands'][0]['build_receipt_verified'])
                self.assertEqual(verification['policy']['satisfied'], not fail_check)
                self.assertFalse(verification['runtime_security_proven'])
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_unreached_check_with_same_stage_is_not_cached(self):
        with GitFixture() as fx:
            checks = [self.check('source_contract'), self.check('configured', 'verify_contract.py'),
                      self.check('source_contract', 'check_upper.py')]
            agent = self.agent(fx, checks)
            executed, middle = [], []
            def run(argv, *args):
                name = argv[-1]; executed.append(name)
                if name == 'verify_contract.py':
                    middle.append(1)
                    return '', '', 1 if len(middle) == 1 else 0
                return '', '', 7 if name == 'check_upper.py' else 0
            with patch('aosp_agent.engine.run_check', side_effect=run):
                self.assertEqual(agent.verify()['status'], 'FAIL')
                self.assertNotIn('source_contract', agent.record['verification_memory']['passed_stages'])
                result = agent.verify()
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['sufficient_for_validated'])
            self.assertEqual(executed, ['check_lower.py', 'verify_contract.py',
                                        'check_lower.py', 'verify_contract.py', 'check_upper.py'])

    def test_external_check_content_change_invalidates_cache(self):
        with GitFixture() as fx:
            script = fx.root / 'check.py'; script.write_text('pass\n')
            agent = self.agent(fx, [self.check('configured', str(script))])
            with patch('aosp_agent.engine.run_check', return_value=('', '', 0)) as run:
                agent.verify(); agent.verify()
                self.assertEqual(run.call_count, 2)
                script.write_text('raise RuntimeError("changed")\n')
                agent.verify()
                self.assertEqual(run.call_count, 3)

    def test_imported_helper_change_cannot_reuse_pass(self):
        with GitFixture() as fx:
            helper = fx.root / 'helper.py'; helper.write_text('OK = True\n')
            script = fx.root / 'external_check.py'
            script.write_text('from helper import OK\nassert OK\n')
            agent = self.agent(fx, [self.check('configured', str(script))])
            self.assertEqual(agent.verify()['status'], 'PASS')
            helper.write_text('OK = False\n')
            result = agent.verify()
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['sufficient_for_validated'])
            self.assertFalse(result['commands'][0].get('skipped_passed'))

    def test_stale_artifact_is_archived_and_cannot_satisfy_new_check(self):
        with GitFixture() as fx:
            agent = self.agent(fx, [self.check('configured', artifacts=['out-artifacts/result.bin'])])
            artifact = agent.worktree / 'out-artifacts/result.bin'
            artifact.parent.mkdir(); artifact.write_bytes(b'old-output')
            with patch('aosp_agent.engine.run_check', return_value=('', '', 0)):
                result = agent.verify()
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['commands'][0]['artifacts'][0]['exists'])
            self.assertEqual((agent.run_dir / 'previous-artifacts/1-1/out-artifacts/result.bin').read_bytes(), b'old-output')

    def test_build_requires_fresh_receipt_even_when_command_returns_zero(self):
        with GitFixture() as fx:
            agent = self.agent(fx, [self.check('android_module_build')])
            with patch('aosp_agent.engine.run_check', return_value=('', '', 0)):
                result = agent.verify()
            self.assertEqual(result['status'], 'FAIL')
            self.assertIn('fresh successful', result['commands'][0]['stderr'])

    def test_real_transaction_receipt_passes_and_build_is_never_reused(self):
        with GitFixture() as fx:
            agent = self.agent(fx, [self.check('android_module_build')])
            def build(argv, cwd, env):
                code = transaction(fx.source_root, fx.root / 'build.lock', [sys.executable, '-c', 'pass'], env)
                return '', '', code
            with patch('aosp_agent.engine.run_check', side_effect=build) as run:
                result = agent.verify()
                self.assertEqual(result['status'], 'PASS')
                self.assertTrue(result['sufficient_for_validated'])
                self.assertEqual(result['policy']['build_covered_repositories'], ['repo'])
                self.assertTrue(result['commands'][0]['build_receipt_verified'])
                first = json.loads((agent.run_dir / 'module-build-restore/transaction.json').read_text())
                self.assertEqual(agent.verify()['status'], 'PASS')
                second = json.loads((agent.run_dir / 'module-build-restore/transaction.json').read_text())
            self.assertEqual(run.call_count, 2)
            self.assertNotEqual(first['validation_id'], second['validation_id'])
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_old_receipt_cannot_be_reused_on_next_invocation(self):
        with GitFixture() as fx:
            agent = self.agent(fx, [self.check('android_module_build')])
            def build(argv, cwd, env):
                return '', '', transaction(fx.source_root, fx.root / 'build.lock', [sys.executable, '-c', 'pass'], env)
            with patch('aosp_agent.engine.run_check', side_effect=build):
                self.assertEqual(agent.verify()['status'], 'PASS')
            with patch('aosp_agent.engine.run_check', return_value=('', '', 0)):
                self.assertEqual(agent.verify()['status'], 'FAIL')

    def test_artifact_cannot_remove_tracked_source(self):
        with GitFixture() as fx:
            agent = self.agent(fx, [self.check('configured', artifacts=['counter.py'])])
            with self.assertRaisesRegex(RuntimeError, 'tracked source'):
                agent.verify()
            self.assertEqual((agent.worktree / 'counter.py').read_text(), FIXED)
