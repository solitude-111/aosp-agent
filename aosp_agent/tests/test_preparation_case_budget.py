"""Controller preparation admits each active-case Git process exactly once."""
import json
import threading
import time
from unittest import TestCase, mock

from engine_fixtures import GitFixture
from test_preparation import MemoryMounts, setup
from aosp_agent import agent_tools
from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.preparation import PreparationManager, PreparationBlocked
from aosp_agent.retrieval import ReadBudget, BudgetExceeded
from aosp_agent.tool_io import ToolIO, ACTIVE_TOOL_IO


class PreparationCaseBudgetTest(TestCase):
    def test_success_failure_and_normal_tool_io_each_charge_once(self):
        with GitFixture() as fixture:
            config, _ = setup(fixture)
            manager = PreparationManager(config, overlays=MemoryMounts())
            ledger = ExecutionBudget(fixture.run_root / 'case', 'input', limits={'tool_operations': 5})
            with ledger.active():
                self.assertEqual(manager._git(fixture.repo, 'rev-parse', 'HEAD').returncode, 0)
                self.assertEqual(ledger.snapshot()['consumed']['tool_operations'], 1)
                self.assertNotEqual(manager._git(fixture.repo, 'rev-parse', '--verify', 'missing-ref').returncode, 0)
                self.assertEqual(ledger.snapshot()['consumed']['tool_operations'], 2)
                # Normal agent_tools Git already admits at its caller boundary;
                # the shared ToolIO implementation must not debit it again.
                budget = ReadBudget(seconds=10, ledger=ledger, tracks_investigation=False)
                io = ToolIO(budget, threading.Event(), time.monotonic() + 10)
                token = ACTIVE_TOOL_IO.set(io)
                try:
                    with budget.active():
                        self.assertEqual(agent_tools._git(['-C', str(fixture.repo)], 'rev-parse', 'HEAD').returncode, 0)
                finally:
                    ACTIVE_TOOL_IO.reset(token)
                state = ledger.snapshot()
                self.assertEqual(state['consumed']['tool_operations'], 3)
                self.assertGreater(state['io_consumed'], 0)
                self.assertEqual(state['io_reserved'], 0)

    def test_exhaustion_prevents_process_watcher_and_preparation_reservation(self):
        with GitFixture() as fixture:
            config, _ = setup(fixture)
            manager = PreparationManager(config, overlays=MemoryMounts())
            manager._load_accounting(fixture.run_root / 'preparation-budget.json')
            ledger = ExecutionBudget(fixture.run_root / 'case', 'input', limits={'tool_operations': 1})
            with ledger.active():
                ledger.charge('tool_operations')
                with mock.patch('aosp_agent.tool_io.subprocess.Popen') as process, \
                        mock.patch('aosp_agent.preparation.threading.Thread') as watcher:
                    with self.assertRaises(BudgetExceeded): manager._git(fixture.repo, 'rev-parse', 'HEAD', online=True)
                    process.assert_not_called()
                    watcher.assert_not_called()
            preparation = json.loads(manager.accounting_path.read_text())
            self.assertEqual(preparation['seconds_used'], 0)
            self.assertEqual(preparation['reserved_seconds'], 0)
            self.assertEqual(ledger.snapshot()['consumed']['tool_operations'], 1)
            self.assertEqual(ledger.snapshot()['io_reserved'], 0)

    def test_without_case_ledger_preparation_keeps_its_own_time_limit(self):
        with GitFixture() as fixture:
            config, _ = setup(fixture)
            manager = PreparationManager(config, overlays=MemoryMounts())
            self.assertEqual(manager._git(fixture.repo, 'rev-parse', 'HEAD').returncode, 0)
            self.assertGreater(manager.seconds_used, 0)
            manager.seconds_used = manager.policy['max_seconds']
            with mock.patch('aosp_agent.tool_io.subprocess.Popen') as process:
                with self.assertRaises(PreparationBlocked) as caught: manager._git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertEqual(caught.exception.kind, 'PREPARATION_TIME_LIMIT')
                process.assert_not_called()
