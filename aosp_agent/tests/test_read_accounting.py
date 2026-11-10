"""Real subprocess and Git checks for settled case-wide source-tool accounting."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aosp_agent.agent_tools import RunContext
from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.object_cache import ObjectCache
from aosp_agent.patches import split_hunks
from aosp_agent.retrieval import ReadBudget, BudgetExceeded
from aosp_agent.sandbox_scope import ModelScope
from aosp_agent.tool_broker import ToolBroker
from aosp_agent.tool_io import ToolIO, QueryOutputLimit
from engine_fixtures import GitFixture
from test_tool_broker import call, response


class ReadAccountingTest(unittest.TestCase):
    def test_short_reads_eof_and_exact_query_limit_release_unused_reservation(self):
        budget = ReadBudget(seconds=20, output_bytes=100000)
        io = ToolIO(budget, threading.Event(), time.monotonic() + 20, max_output=3)
        for code, output in [('pass', ''), ('import os; os.write(1, b"x")', 'x'),
                             ('import os; os.write(1, b"abc")', 'abc')]:
            self.assertEqual(io.run([sys.executable, '-c', code]).stdout, output)
            self.assertEqual(budget.bytes_reserved, 0)
        self.assertEqual(budget.bytes_used, 4)

    def test_partial_capture_is_charged_on_cancel_or_read_error(self):
        for mode in ('cancel', 'error'):
            with self.subTest(mode=mode):
                budget = ReadBudget(seconds=10)
                cancelled = threading.Event()
                io = ToolIO(budget, cancelled, time.monotonic() + 10)
                timer = threading.Timer(.2, cancelled.set)
                original = os.read
                reads = []
                def read(fd, count):
                    if mode == 'error' and reads:
                        raise OSError('injected read failure')
                    data = original(fd, count)
                    if data == b'abc':
                        reads.append(data)
                        if mode == 'error':
                            # A second selectable write triggers the failing read.
                            pass
                    return data
                if mode == 'cancel':
                    timer.start()
                try:
                    with patch('aosp_agent.tool_io.os.read', read):
                        with self.assertRaises(BudgetExceeded if mode == 'cancel' else OSError):
                            io.run([sys.executable, '-c',
                                'import os,time; os.write(1,b"abc"); time.sleep(.1); '
                                + ('time.sleep(20)' if mode == 'cancel' else 'os.write(1,b"d")')])
                finally:
                    if mode == 'cancel': timer.join()
                self.assertEqual(budget.bytes_used, 3)
                self.assertEqual(budget.bytes_reserved, 0)

    def test_concurrent_admission_and_double_settlement_cannot_refund_twice(self):
        budget = ReadBudget(seconds=10, output_bytes=100)
        start = threading.Barrier(3)
        receipts, failures = [], []
        def reserve():
            start.wait()
            try: receipts.append(budget.reserve_bytes(80, 'test'))
            except BudgetExceeded as exc: failures.append(exc)
        workers = [threading.Thread(target=reserve) for _ in range(2)]
        for worker in workers: worker.start()
        start.wait()
        for worker in workers: worker.join()
        self.assertEqual((len(receipts), len(failures)), (1, 1))
        budget.settle_bytes(receipts[0], 7)
        with self.assertRaises(KeyError): budget.settle_bytes(receipts[0], 0)
        self.assertEqual((budget.bytes_used, budget.bytes_reserved, budget.remaining_bytes()), (7, 0, 93))

    def test_new_runtime_and_reloaded_ledger_do_not_reset_consumption(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = ExecutionBudget(directory, 'input', limits={'io_bytes': 100})
            with ledger.active():
                first = ReadBudget(seconds=10)
                first.claim_bytes(60, 'model_reply')
                second = ReadBudget(seconds=10)
                self.assertIs(second.ledger, ledger)
                with self.assertRaises(BudgetExceeded): second.claim_bytes(41)
            restored = ExecutionBudget(directory, 'input', existing=True)
            with restored.active():
                final = ReadBudget(seconds=10)
                self.assertEqual(final.remaining_bytes(), 40)
                final.claim_bytes(40)
                with self.assertRaises(BudgetExceeded): final.claim_bytes(1)

    def test_donor_defaults_respect_step_and_side_without_empty_whole_tree_fallback(self):
        entries = {name: {'source_parent': name + 'old', 'source_commit': name + 'new'} for name in ('s001', 's002')}
        ctx = RunContext(Path.cwd(), record={'tool_source_repositories': entries}, inspection={'hunks': [
            {'id': 'one', 'source_id': 's001', 'old_path': 'src/old.c', 'new_path': 'src/new.c'},
            {'id': 'two', 'source_id': 's001', 'old_path': None, 'new_path': 'src/added.c'},
            {'id': 'three', 'source_id': 's002', 'old_path': 'other/deleted.c', 'new_path': None}]})
        self.assertEqual(ctx.donor_search_paths('donor:s001', 's001old')[0], ['src/old.c'])
        self.assertEqual(ctx.donor_search_paths('donor:s001', 's001new')[0], ['src/added.c', 'src/new.c'])
        self.assertEqual(ctx.donor_search_paths('donor:s002', 's002new'), ([], ['other']))

    def broker(self, fixture, budget):
        scope = ModelScope((fixture.repo,), tool_repositories={
            'repo': {'root': str(fixture.repo), 'head': fixture.target}})
        broker = ToolBroker(scope, lambda *a, **kw: None, budget=budget)
        broker.begin('thread', fixture.repo, True, 20)
        self.addCleanup(broker.close)
        return broker

    def test_donor_query_defaults_to_changed_files_and_explicit_path_expands(self):
        with GitFixture() as fixture:
            context = fixture.root / 'context'; context.mkdir()
            (context / 'run.json').write_text(json.dumps({'donor_git': str(fixture.repo / '.git'),
                'source_parent': fixture.target, 'source_commit': fixture.donor}))
            content = subprocess.check_output(['git', '-C', str(fixture.repo), 'diff',
                fixture.target, fixture.donor], text=True)
            (context / 'inspection.json').write_text(json.dumps({'hunks': split_hunks(content)}))
            scope = ModelScope((fixture.root,), tool_context=str(context))
            broker = ToolBroker(scope, lambda *a, **kw: None)
            broker.begin('thread', context, True, 20)
            self.addCleanup(broker.close)
            args = {'operation': 'search', 'repo': 'donor', 'ref': fixture.target, 'query': 'normalize_count'}
            first = response(call(broker, 'aosp_source', args))
            self.assertEqual(first['requested_paths'], ['counter.py'])
            self.assertNotIn('verify_contract.py', first['text'])
            second = response(call(broker, 'aosp_source', {**args, 'path': 'verify_contract.py'}, 'expanded'))
            self.assertEqual(second['scope_origin'], 'explicit')
            self.assertIn('verify_contract.py', second['text'])

    def test_query_limit_allows_a_smaller_query_but_case_limit_is_fatal(self):
        with GitFixture() as fixture:
            budget = ReadBudget(seconds=20)
            broker = self.broker(fixture, budget)
            args = {'operation': 'search', 'repo': 'target:repo', 'ref': fixture.target, 'query': 'normalize_count'}
            with patch('aosp_agent.tool_broker.MAX_QUERY_OUTPUT', 10):
                failed = response(call(broker, 'aosp_source', args))
            self.assertEqual(failed['status'], 'SEARCH_INCOMPLETE')
            self.assertEqual(failed['reason'], 'OUTPUT_LIMIT')
            self.assertFalse(failed['completed_scope_known'])
            self.assertIsNone(broker.failure)
            smaller = call(broker, 'aosp_source', {**args, 'path': 'counter.py'}, 'smaller')
            self.assertTrue(smaller['success'], smaller)
            self.assertEqual(budget.bytes_reserved, 0)
            budget.claim_bytes(budget.remaining_bytes())
            fatal = response(call(broker, 'aosp_source', args, 'fatal'))
            self.assertEqual(fatal['status'], 'BUDGET_EXHAUSTED')
            self.assertIsInstance(broker.failure, BudgetExceeded)

    def test_shared_cache_hits_still_charge_reply_and_cache_reads(self):
        with GitFixture() as fixture:
            ledger = ExecutionBudget(fixture.root / 'ledger', 'input')
            ledger.object_cache = ObjectCache(fixture.root / 'cache')
            args = {'operation': 'search', 'repo': 'target:repo', 'ref': fixture.target,
                    'query': 'normalize_count', 'path': 'counter.py'}
            with ledger.active():
                first = self.broker(fixture, ReadBudget(seconds=20))
                one = call(first, 'aosp_source', args)
                self.assertTrue(one['success'], one)
                first.close()
                before = ledger.snapshot()
                second = self.broker(fixture, ReadBudget(seconds=20))
                with patch('aosp_agent.agent_tools._git', side_effect=AssertionError('must reuse query')):
                    two = call(second, 'aosp_source', args)
                self.assertTrue(two['success'], two)
                after = ledger.snapshot()
                self.assertGreater(after['io_by_boundary']['model_reply'], before['io_by_boundary']['model_reply'])
                self.assertGreater(after['io_by_boundary']['cache_file_read'], 0)
                self.assertEqual(after['io_by_boundary']['git_capture'], before['io_by_boundary']['git_capture'])
                self.assertEqual(after['io_reserved'], 0)

    def test_unavailable_durable_accounting_stops_before_candidate_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ledger = ExecutionBudget(root / 'ledger', 'input')
            with ledger.active():
                broker = ToolBroker(ModelScope((root,), (root / 'candidate',)), lambda *a, **kw: None)
                broker.begin('thread', root, False, 20)
                self.addCleanup(broker.close)
                with patch.object(ledger, 'reserve_io', side_effect=RecoveryBlocked('checkpoint unavailable')):
                    denied = call(broker, 'aosp_write_file', {'path': 'candidate', 'expected_sha256': 'ABSENT',
                        'content': 'must not appear', 'operation': 'write'})
                self.assertEqual(response(denied)['status'], 'RECOVERY_BLOCKED')
                self.assertIsInstance(broker.failure, RecoveryBlocked)
                self.assertTrue(broker.cancelled.is_set())
                self.assertFalse((root / 'candidate').exists())


if __name__ == '__main__':
    unittest.main()
