"""Real controller Git, durable hard limits and audit-only recovery grace."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.discovery import local_git, Repository
from aosp_agent.execution_budget import (AUDIT_GRACE_OPERATIONS, ExecutionBudget,
                                        controller_audit, _audit_read_command)
from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.retrieval import BudgetExceeded, ReadBudget, suspend_investigation_budget
from aosp_agent.tool_io import ACTIVE_TOOL_IO, ToolIO
from engine_fixtures import GitFixture
from aosp_agent.engine import AospBackportAgent


@controller_audit('diff._originals_unchanged')
def integrity_read(repo):
    return local_git(repo, 'status', '--porcelain').stdout


@controller_audit('engine.audit_diff')
def forbidden_write(repo):
    return local_git(repo, 'config', 'audit.mutated', 'yes')


class ControllerAuditBudgetTest(unittest.TestCase):
    def test_grace_cat_file_is_only_fixed_object_type_inspection(self):
        prefix = ['git', '-c', 'core.hooksPath=/dev/null', 'cat-file']
        self.assertTrue(_audit_read_command(prefix + ['-t', 'a' * 40]))
        for args in (['-p', 'a' * 40], ['--batch'], ['--batch-command'], ['-t', 'HEAD'],
                     ['-t', 'a' * 40 + ':path'], ['--filters', 'a' * 40]):
            self.assertFalse(_audit_read_command(prefix + args))

    def test_sdk_fallback_preserves_paused_investigation_clock_after_process_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = '''
import os, sys
from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.retrieval import ReadBudget, suspend_investigation_budget
from aosp_agent.sdk_runtime import CodexRuntime
ledger = ExecutionBudget(sys.argv[1], 'input')
with ledger.active(), ReadBudget(ledger=ledger).active():
 with suspend_investigation_budget():
  runtime = object.__new__(CodexRuntime)
  runtime.read_scope = None
  runtime._log = lambda *a, **k: None
  runtime.turn_timeout = 1
  fallback = runtime._make_broker().fallback
  fallback.remaining()
  fallback.command_timeout(1)
  fallback.claim_bytes(3, 'actual_read')
  with fallback.active(), ledger.operation('model', timeout=.05):
   assert ledger.snapshot()['investigation_clock']['active'] is False
   assert ledger.current_operation()['investigation'] is False
   os._exit(0)
'''
            subprocess.run([sys.executable, '-c', script, temporary], check=True)
            resumed = ExecutionBudget(temporary, 'input', existing=True)
            previous = resumed.snapshot()
            time.sleep(.06)
            resumed.recover_stopped()
            current = resumed.snapshot()
            self.assertEqual(current['investigation_ms'], previous['investigation_ms'])
            self.assertFalse(current['investigation_clock']['active'])
            self.assertGreater(current['execution_ms'], previous['execution_ms'])
            self.assertEqual(current['consumed']['tool_operations'], 1)
            self.assertEqual(current['io_consumed'], 3)

    def test_suspended_controller_git_is_charged_and_models_stop_at_tool_limit(self):
        with GitFixture() as fixture:
            budget = ExecutionBudget(fixture.run_root, 'input', limits={'tool_operations': 2})
            reads = ReadBudget(ledger=budget)
            with budget.active(), reads.active():
                local_git(fixture.repo, 'rev-parse', 'HEAD')
                with suspend_investigation_budget():
                    local_git(fixture.repo, 'rev-parse', 'HEAD')
                    with self.assertRaises(BudgetExceeded):
                        local_git(fixture.repo, 'rev-parse', 'HEAD')
                with self.assertRaises(BudgetExceeded):
                    budget.admit_model(read_only=False)
            state = budget.snapshot()
            self.assertEqual(state['consumed'], {'tool_operations': 2})
            self.assertEqual(state['io_consumed'], 0)  # controller capture is telemetry
            self.assertEqual(state['audit_grace']['operations'], 0)

    def test_engine_cleanup_audit_finishes_without_authorizing_more_work(self):
        with GitFixture() as fixture:
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case())
            agent.prepare()
            budget = ExecutionBudget(agent.run_dir, 'input', limits={'tool_operations': 1})
            with budget.active():
                result = agent.audit_diff(require_clean=True)
                self.assertTrue(result['original_checkout_unchanged'])
                with self.assertRaises(BudgetExceeded):
                    agent._git('rev-parse', 'HEAD')
                with self.assertRaises(BudgetExceeded):
                    budget.admit_model()
                from aosp_agent.validation_process import run_check
                with patch('aosp_agent.validation_process._run_check') as compiler:
                    with self.assertRaises(BudgetExceeded):
                        run_check(['unstarted-compiler'], str(fixture.repo), {})
                    compiler.assert_not_called()
            state = budget.snapshot()
            self.assertEqual(state['consumed']['tool_operations'], 1)
            self.assertGreater(state['audit_grace']['operations'], 0)

    def test_mapped_cleanup_finishes_ignored_file_and_peer_checks_after_tool_limit(self):
        with GitFixture() as fixture:
            child = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case())
            child.prepare()
            repo = Repository('repo', fixture.repo, fixture.target, {})
            controller = object.__new__(DiffBackportAgent)
            controller.repos = [repo]
            controller.before = {'repo': repo.state()}
            controller.protected = {}
            controller.children = {'repo': child}
            controller.workspace = fixture.root / 'controller-workspace'
            before = controller._candidate_hashes(except_key='other')
            budget = ExecutionBudget(child.run_dir, 'input', limits={'tool_operations': 1})
            with budget.active():
                local_git(fixture.repo, 'rev-parse', 'HEAD')
                controller._audit_peers('other', before)
                with self.assertRaises(BudgetExceeded):
                    budget.admit_model()
            state = budget.snapshot()
            self.assertEqual(state['consumed']['tool_operations'], 1)
            self.assertGreater(state['audit_grace']['by_phase']['diff._audit'], 0)
            self.assertGreater(state['audit_grace']['by_phase']['diff._audit_peers'], 0)

    def test_grace_deadline_and_command_count_survive_resume_without_renewal(self):
        with GitFixture() as fixture:
            budget = ExecutionBudget(fixture.run_root, 'input', limits={'tool_operations': 1})
            with budget.active():
                local_git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertEqual(integrity_read(fixture.repo), '')
            original = budget.snapshot()['audit_grace']
            resumed = ExecutionBudget(fixture.run_root, 'input', existing=True)
            resumed.recover_stopped()
            with resumed.active():
                integrity_read(fixture.repo)
                with patch('aosp_agent.execution_budget.time.time', return_value=original['deadline_at'] + 1):
                    with self.assertRaises(BudgetExceeded):
                        integrity_read(fixture.repo)
            current = resumed.snapshot()['audit_grace']
            self.assertEqual(current['started_at'], original['started_at'])
            self.assertEqual(current['deadline_at'], original['deadline_at'])
            self.assertEqual(current['operations'], 2)
            # A persisted terminal command count cannot be renewed by reopening.
            state = json.loads(budget.path.read_text())
            state['audit_grace']['operations'] = AUDIT_GRACE_OPERATIONS
            budget.path.write_text(json.dumps(state))
            reopened = ExecutionBudget(fixture.run_root, 'input', existing=True)
            with reopened.active(), self.assertRaises(BudgetExceeded):
                integrity_read(fixture.repo)

    def test_clock_rollback_blocks_grace_instead_of_extending_it(self):
        with GitFixture() as fixture:
            budget = ExecutionBudget(fixture.run_root, 'input', limits={'tool_operations': 1})
            with budget.active():
                local_git(fixture.repo, 'rev-parse', 'HEAD')
                integrity_read(fixture.repo)
                first = budget.snapshot()['audit_grace']['started_at']
                with patch('aosp_agent.execution_budget.time.time', return_value=first - 1):
                    with self.assertRaises(RecoveryBlocked):
                        integrity_read(fixture.repo)

    def test_grace_never_permits_git_writes_or_model_tool_scope(self):
        with GitFixture() as fixture:
            budget = ExecutionBudget(fixture.run_root, 'input', limits={'tool_operations': 1})
            with budget.active():
                local_git(fixture.repo, 'rev-parse', 'HEAD')
                with self.assertRaises(BudgetExceeded):
                    forbidden_write(fixture.repo)
                token = ACTIVE_TOOL_IO.set(object())
                try:
                    with self.assertRaises(BudgetExceeded):
                        integrity_read(fixture.repo)
                finally:
                    ACTIVE_TOOL_IO.reset(token)
                self.assertEqual(budget.snapshot()['audit_grace']['operations'], 0)
            result = subprocess.run(['git', 'config', '--get', 'audit.mutated'], cwd=fixture.repo,
                                    capture_output=True)
            self.assertEqual(result.returncode, 1)

    def test_model_tool_keeps_single_command_charge_and_actual_byte_accounting(self):
        with GitFixture() as fixture:
            budget = ExecutionBudget(fixture.run_root, 'input', limits={'tool_operations': 2})
            reads = ReadBudget(ledger=budget)
            io = ToolIO(reads, threading.Event(), time.monotonic() + 10)
            with budget.active(), reads.active():
                token = ACTIVE_TOOL_IO.set(io)
                try:
                    result = local_git(fixture.repo, 'rev-parse', 'HEAD')
                finally:
                    ACTIVE_TOOL_IO.reset(token)
            self.assertEqual(budget.snapshot()['consumed']['tool_operations'], 1)
            self.assertEqual(budget.snapshot()['io_consumed'], len(result.stdout.encode()))

    def test_controller_timeout_uses_case_deadline_then_finite_audit_deadline(self):
        with GitFixture() as fixture:
            budget = ExecutionBudget(fixture.run_root, 'input', limits={'execution_seconds': .03})
            with budget.active():
                with patch('aosp_agent.retrieval.subprocess.run', wraps=subprocess.run) as execute:
                    local_git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertLessEqual(execute.call_args.kwargs['timeout'], .03)
                time.sleep(.04)
                with self.assertRaises(BudgetExceeded):
                    local_git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertEqual(integrity_read(fixture.repo), '')
                with self.assertRaises(BudgetExceeded):
                    budget.admit_model()


if __name__ == '__main__':
    unittest.main()
