import asyncio
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from aosp_agent.agent_tools import _git
from aosp_agent.project_first import ModelTurnLimit
from aosp_agent.retrieval import ReadBudget, BudgetExceeded
from aosp_agent.sdk_runtime import CodexRuntime, CodexRuntimeError
from engine_fixtures import GitFixture
from test_sdk_runtime import FakeCodex, FakeHandle


class RuntimeBudgetsTest(unittest.TestCase):
    def test_controlled_tools_obey_in_process_budget(self):
        with GitFixture() as fx:
            budget = ReadBudget(seconds=10, operations=1)
            with budget.active():
                _git([], 'rev-parse', 'HEAD', cwd=fx.repo)
                with self.assertRaises(BudgetExceeded):
                    _git([], 'rev-parse', 'HEAD', cwd=fx.repo)
            self.assertEqual(budget.used, 1)

    def test_sdk_schema_correction_spends_actual_model_turn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = FakeCodex(None, 'fix_once')
            limit = ModelTurnLimit(limit=1)
            with patch('openai_codex.AsyncCodex', return_value=fake):
                with limit(events_path=root / 'events.jsonl') as runtime:
                    runtime.start(root, 'test')
                    with self.assertRaises(BudgetExceeded):
                        runtime.run('test', output_schema={'type': 'object', 'required': ['verdict']})
            self.assertEqual(len(fake.thread.calls), 1)
            self.assertEqual(limit.used, 1)
            self.assertTrue(limit.exhausted)
            self.assertTrue(fake.closed)

    def test_sdk_tools_are_counted_and_over_budget_turn_is_interrupted(self):
        async def tools(handle):
            for number in range(2):
                yield types.SimpleNamespace(method='item/started', payload={
                    'item': {'id': str(number), 'type': 'commandExecution', 'command': 'git show'}})
            async for event in original(handle):
                yield event
        original = FakeHandle.stream
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fake = FakeCodex(None, 'completed')
            budget = ReadBudget(seconds=10, operations=1)
            with patch('openai_codex.AsyncCodex', return_value=fake), patch.object(FakeHandle, 'stream', tools):
                with budget.active(), CodexRuntime(root / 'events.jsonl') as runtime:
                    runtime.start(root, 'test')
                    with self.assertRaises(BudgetExceeded):
                        runtime.run('test')
            self.assertEqual(budget.used, 1)
            self.assertTrue(fake.thread.handle.interrupted)
            self.assertTrue(fake.closed)

    def test_correction_shares_call_deadline(self):
        original = FakeHandle.stream
        async def slow(handle):
            await asyncio.sleep(.08)
            async for event in original(handle):
                yield event
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fake = FakeCodex(None, 'fix_once')
            with patch('openai_codex.AsyncCodex', return_value=fake), patch.object(FakeHandle, 'stream', slow):
                with CodexRuntime(root / 'events.jsonl', turn_timeout=.12) as runtime:
                    runtime.start(root, 'test')
                    with self.assertRaises(CodexRuntimeError) as raised:
                        runtime.run('test', output_schema={'type': 'object', 'required': ['verdict']})
            self.assertEqual(raised.exception.kind, 'TIMEOUT')
            self.assertTrue(fake.thread.handle.interrupted)

    def test_global_deadline_interrupts_even_with_larger_turn_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fake = FakeCodex(None, 'timeout')
            budget = ReadBudget(seconds=.1, operations=20)
            with patch('openai_codex.AsyncCodex', return_value=fake):
                with budget.active(), CodexRuntime(root / 'events.jsonl', turn_timeout=10) as runtime:
                    runtime.start(root, 'test')
                    with self.assertRaises(BudgetExceeded):
                        runtime.run('test')
            self.assertTrue(fake.thread.handle.interrupted)
