"""Persistent admissions, actual byte settlement and cross-attempt invariants."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.retrieval import BudgetExceeded


class ExecutionBudgetTest(unittest.TestCase):
    def test_reservation_actual_consumption_and_single_settlement(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input', limits={'io_bytes': 20})
            one = budget.reserve_io(12, 'git')
            two = budget.reserve_io(8, 'reply')
            with self.assertRaises(BudgetExceeded):
                budget.reserve_io(1, 'git')
            budget.settle_io(one, 2)
            budget.settle_io(two, 0)
            self.assertEqual(budget.remaining_io(), 18)
            with self.assertRaises(ValueError):
                budget.settle_io(one, 0)
            state = budget.snapshot()
            self.assertEqual((state['io_consumed'], state['io_reserved']), (2, 0))
            self.assertEqual(state['io_by_boundary'], {'git': 2, 'reply': 0})

    def test_six_writes_across_repositories_and_reopened_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input', limits={'candidate_turns': 6})
            for number in range(6):
                budget = ExecutionBudget(directory, 'input', existing=True)
                budget.admit_model(read_only=False, phase='migration', repository='repo-' + str(number % 2))
            state = budget.snapshot()
            with self.assertRaises(BudgetExceeded):
                budget.admit_model(read_only=False, repository='repo-2')
            self.assertEqual(budget.snapshot()['consumed'], state['consumed'])
            budget.admit_model(read_only=True, phase='review')
            self.assertEqual(budget.snapshot()['consumed'], {'candidate_turns': 6, 'model_calls': 7})
            self.assertEqual(state['by_repository']['repo-0']['candidate_turns'], 3)

    def test_failed_admission_persistence_prevents_model_work(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input')
            with patch('aosp_agent.execution_budget._atomic', side_effect=OSError('disk full')):
                with self.assertRaises(RecoveryBlocked):
                    budget.admit_model(read_only=False)
            self.assertEqual(budget.snapshot()['consumed'], {})

    def test_process_crash_preserves_admission_and_settles_unknown_reservation(self):
        with tempfile.TemporaryDirectory() as directory:
            code = '''
import os,sys
from aosp_agent.execution_budget import ExecutionBudget
b=ExecutionBudget(sys.argv[1], 'input', limits={'io_bytes':100})
with b.active():
 b.admit_model(read_only=False, repository='repo')
 with b.operation('model', timeout=.05):
  b.reserve_io(80,'git')
  os._exit(0)
'''
            subprocess.run([sys.executable, '-c', code, directory], check=True)
            budget = ExecutionBudget(directory, 'input', existing=True)
            with self.assertRaises(RecoveryBlocked):
                with budget.active():
                    self.fail('unsettled case must not run')
            time.sleep(.06)
            budget.recover_stopped()
            state = budget.snapshot()
            self.assertEqual(state['consumed']['candidate_turns'], 1)
            self.assertEqual((state['io_consumed'], state['io_reserved']), (80, 0))
            self.assertEqual(len(state['recovery_settlements']), 1)
            budget.recover_stopped()
            self.assertEqual(budget.snapshot()['io_consumed'], 80)
            with budget.active():
                budget.admit_model(read_only=False)
            self.assertEqual(budget.snapshot()['consumed']['candidate_turns'], 2)

    def test_fresh_process_clock_and_explicit_pause_do_not_reset_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input')
            with patch('aosp_agent.execution_budget.time.monotonic', return_value=100):
                with budget.active():
                    with patch('aosp_agent.execution_budget.time.monotonic', return_value=105):
                        budget.charge('tool_operations')
            before = budget.snapshot()['execution_ms']
            self.assertGreaterEqual(before, 5000)
            resumed = ExecutionBudget(directory, 'input', existing=True)
            with patch('aosp_agent.execution_budget.time.monotonic', return_value=8):
                with resumed.active():
                    with patch('aosp_agent.execution_budget.time.monotonic', return_value=10):
                        resumed.charge('tool_operations')
            self.assertGreaterEqual(resumed.snapshot()['execution_ms'], before + 2000)

    def test_policy_and_input_identity_cannot_change_on_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input')
            budget.configure(budget.limits, {'location_attempts': 3})
            with self.assertRaises(RecoveryBlocked):
                ExecutionBudget(directory, 'other', existing=True)
            with self.assertRaises(RecoveryBlocked):
                budget.configure({**budget.limits, 'candidate_turns': 60}, {'location_attempts': 3})

    def test_concurrent_reservations_share_one_hard_limit(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as directory:
            ExecutionBudget(directory, 'input', limits={'io_bytes': 30})
            def reserve(_):
                instance = ExecutionBudget(directory, 'input', existing=True)
                try:
                    return instance.reserve_io(10, 'file')
                except BudgetExceeded:
                    return None
            with ThreadPoolExecutor(max_workers=6) as pool:
                admitted = list(pool.map(reserve, range(10)))
            budget = ExecutionBudget(directory, 'input', existing=True)
            self.assertEqual(sum(x is not None for x in admitted), 3)
            self.assertEqual(budget.remaining_io(), 0)

    def test_extensions_need_new_grounded_progress_and_survive_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input', limits={'investigation_seconds': 100})
            budget.configure(budget.limits, {'extension_seconds': 20, 'max_stage_extensions': 1})
            self.assertEqual(budget.investigation_allowance(90, 'LOCATION'), 100)
            budget.record_progress('LOCATION', [{'path': 'A.java', 'pin': 'a', 'lines': [2, 3]}])
            self.assertEqual(budget.investigation_allowance(90, 'LOCATION'), 120)
            budget.record_progress('LOCATION', [{'path': 'A.java', 'pin': 'a', 'lines': [2, 3]}])
            resumed = ExecutionBudget(directory, 'input', existing=True)
            self.assertEqual(resumed.investigation_allowance(110, 'IMPACT'), 120)
            resumed.record_progress('IMPACT', [{'verified_decision': 'AFFECTED', 'pin': 'a'}])
            self.assertEqual(resumed.investigation_allowance(110, 'IMPACT'), 140)
            resumed.record_progress('LOCATION', [{'path': 'B.java', 'pin': 'a', 'lines': [2, 3]}])
            self.assertEqual(resumed.investigation_allowance(130, 'LOCATION'), 140)

    def test_error_signatures_preserve_subject_and_progress_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input')
            self.assertFalse(budget.repeated_error('REVIEW', 'MISSING', ['return']))
            self.assertFalse(budget.repeated_error('REVIEW', 'MISSING', ['cleanup']))
            self.assertTrue(budget.repeated_error('REVIEW', 'MISSING', ['cleanup']))
            budget.record_progress('REVIEW', [{'covered': 'cleanup'}])
            self.assertFalse(budget.repeated_error('REVIEW', 'MISSING', ['cleanup']))

    def test_batch_model_admission_occurs_after_case_precheck(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input', limits={'model_calls': 1})
            shared = Mock()
            shared.remaining_seconds.return_value = 100
            budget.batch_budget = shared
            budget.admit_model()
            shared.admit_model.assert_called_once()
            with self.assertRaises(BudgetExceeded): budget.admit_model()
            shared.admit_model.assert_called_once()

    def test_source_preparation_costs_import_once_and_survive_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = ExecutionBudget(directory, 'input')
            receipt = {'operations_used': 7, 'model_io_bytes_consumed': 19,
                'elapsed_seconds': 2.5, 'io_by_boundary': {'git': 19}}
            budget.import_preparation(receipt)
            resumed = ExecutionBudget(directory, 'input', existing=True)
            resumed.import_preparation(receipt)
            snapshot = resumed.snapshot()
            self.assertEqual(snapshot['consumed']['tool_operations'], 7)
            self.assertEqual(snapshot['io_consumed'], 19)
            self.assertEqual(snapshot['execution_ms'], 2500)
            self.assertEqual(snapshot['investigation_ms'], 2500)


if __name__ == '__main__':
    unittest.main()
