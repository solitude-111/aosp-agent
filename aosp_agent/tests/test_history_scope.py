import contextlib
import io
import json
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aosp_agent import agent_tools
from aosp_agent.retrieval import ReadBudget, ACTIVE_BUDGET, BudgetExceeded
from aosp_agent.tool_io import ToolIO, ACTIVE_TOOL_IO
from test_agent_tools import ThreeCommitRun


class HistoryScopeTest(unittest.TestCase):
    def show(self, run, hunk=True):
        args = ['--run-dir', str(run.run_dir), 'show-commit', '--sha', run.parent]
        if hunk: args += ['--hunk-id', 'f001-h001']
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(agent_tools.main(args), 0)
        receipt = json.loads((run.run_dir / 'tool-usage.jsonl').read_text().splitlines()[-1])
        return output.getvalue(), receipt

    def test_large_unrelated_commit_never_consumes_output_budget(self):
        with ThreeCommitRun(bulk_history=True) as run:
            budget = ReadBudget(seconds=30, output_bytes=256 * 1024)
            io_guard = ToolIO(budget, threading.Event(), time.monotonic() + 30, max_output=32768)
            a = ACTIVE_BUDGET.set(budget); b = ACTIVE_TOOL_IO.set(io_guard)
            try:
                output, receipt = self.show(run)
                self.assertIn('+beta', output)
                self.assertNotIn('unrelated.txt', output)
                self.assertEqual(receipt['path_scope'], 'widget.py')
                self.assertTrue(receipt['diff_complete'])
                self.assertLess(budget.bytes_used, 256 * 1024)
            finally:
                ACTIVE_TOOL_IO.reset(b); ACTIVE_BUDGET.reset(a)

    def test_metadata_request_does_not_read_any_patch(self):
        with ThreeCommitRun(bulk_history=True) as run:
            output, receipt = self.show(run, hunk=False)
            self.assertEqual(receipt['read_status'], 'METADATA_ONLY')
            self.assertNotIn('diff --git', output)

    def test_shallow_boundary_with_available_parent_is_not_an_addition(self):
        with ThreeCommitRun(bulk_history=True) as run:
            donor = Path(run.agent.record['donor_git'])
            (donor / 'shallow').write_text(run.parent + '\n')
            output, receipt = self.show(run)
            self.assertEqual(receipt['read_status'], 'HISTORY_INCOMPLETE')
            self.assertEqual(receipt['commit_parents'], [run.target])
            self.assertNotIn('diff --git', output)
            self.assertIn('No introduction or absence conclusion', output)
            history = io.StringIO()
            with contextlib.redirect_stdout(history):
                self.assertEqual(agent_tools.main(['--run-dir', str(run.run_dir),
                    'hunk-history', '--hunk-id', 'f001-h001']), 0)
            self.assertIn('HISTORY_INCOMPLETE', history.getvalue())
            self.assertNotIn('Added-line ratio', history.getvalue())

    def test_large_selected_blob_defers_diff_without_claiming_absence(self):
        with ThreeCommitRun() as run:
            original = agent_tools._git
            def large(repo, *args, **kwargs):
                result = original(repo, *args, **kwargs)
                if args and args[0] == 'ls-tree':
                    result.stdout = '100644 blob ' + 'a' * 40 + ' 600000\twidget.py\n'
                return result
            with patch.object(agent_tools, '_git', side_effect=large):
                output, receipt = self.show(run)
            self.assertEqual(receipt['read_status'], 'SCOPED_DIFF_DEFERRED')
            self.assertFalse(receipt['absence_proven'])
            self.assertNotIn('diff --git', output)

    def test_process_budget_exhaustion_is_not_swallowed(self):
        with ThreeCommitRun() as run, patch.object(agent_tools, '_git', side_effect=BudgetExceeded('test limit')):
            with self.assertRaises(BudgetExceeded): self.show(run)
