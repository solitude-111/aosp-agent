# Executor regression fixtures explicitly select the legacy exhaustive adapter.
# Default project-first entrypoints are covered by test_runtime_entrypoints.py.
"""Negative exits and tool failures must retain their actual evidence scope."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent.agent_tools import RunContext, ToolError, cmd_view_code
from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.engine import AospBackportAgent
from aosp_agent.mapped_run import from_case
from engine_fixtures import GitFixture, git
import test_diff_workflow as workflow
import test_exclusion_review as exclusions


class ResultBoundariesTest(unittest.TestCase):
    def test_multi_repository_tools_have_no_arbitrary_default(self):
        with GitFixture() as fx:
            other = fx.source_root / 'aaa-unrelated'; other.mkdir()
            git(other, 'init', '-q'); (other / 'other.txt').write_text('unrelated\n')
            git(other, 'add', '.'); git(other, 'commit', '-qm', 'unrelated')
            agent = from_case(fx.case(), fx.source_root, fx.run_root, auto_validation=False, exhaustive_discovery=True)
            agent.run(inspect_only=True)
            ctx = RunContext(agent.run_dir)
            with self.assertRaisesRegex(ToolError, 'ambiguous'):
                ctx.repo_selection('target')
            self.assertEqual(ctx.repo_selection('target:repo')[1], fx.repo)
            self.assertEqual(ctx.check_ref(fx.target, 'target:repo'), fx.target)
            with self.assertRaises(ToolError):
                ctx.check_ref(git(other, 'rev-parse', 'HEAD'), 'target:repo')
            with self.assertRaisesRegex(ToolError, 'target-repo'):
                ctx.bind_history_target()
            ctx.bind_history_target('repo')
            self.assertEqual(ctx.record['target_commit'], fx.target)

    def test_git_failure_is_not_reported_as_missing_file(self):
        with GitFixture() as fx:
            agent = from_case(fx.case(), fx.source_root, fx.run_root, auto_validation=False, exhaustive_discovery=True)
            agent.run(inspect_only=True)
            ctx = RunContext(agent.run_dir)
            args = argparse.Namespace(repo='target:repo', ref=fx.target, path='counter.py', start=1, end=2)
            for failure in (subprocess.CompletedProcess([], 128, '', 'fatal: cannot read object'),
                            subprocess.TimeoutExpired(['git'], 1)):
                options = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
                output = io.StringIO()
                with patch('aosp_agent.agent_tools._git', **options), contextlib.redirect_stdout(output):
                    code = cmd_view_code(ctx, args)
                self.assertEqual(code, 3)
                self.assertIn('READ_FAILED', output.getvalue())
                self.assertNotIn('PATH_ABSENT', output.getvalue())

    def test_existing_tree_entry_with_unavailable_blob_is_not_absent(self):
        with GitFixture() as fx:
            agent = from_case(fx.case(), fx.source_root, fx.run_root, auto_validation=False, exhaustive_discovery=True)
            agent.run(inspect_only=True)
            args = argparse.Namespace(repo='target:repo', ref=fx.target, path='counter.py', start=1, end=2)
            replies = [subprocess.CompletedProcess([], 128, '', 'missing blob'),
                       subprocess.CompletedProcess([], 0, '100644 blob abc\tcounter.py\0', '')]
            with patch('aosp_agent.agent_tools._git', side_effect=replies), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cmd_view_code(RunContext(agent.run_dir), args), 3)

    def test_already_fixed_requires_review_and_unknown_blocks_exit(self):
        with GitFixture() as fx:
            helper = workflow.DiffWorkflowTest(); agent = helper.agent(fx)
            raw = helper.assessment(agent, 'ALREADY_FIXED')
            raw['units'][0]['absence_basis'] = 'equivalent_protection'
            reviews = exclusions.ExclusionReviewTest()
            mapping, review, _ = reviews.wire(agent, [raw], [reviews.review(agent)])
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(len(review.calls), 1)
            self.assertFalse(agent.workspace.exists())

    def test_backend_negative_cannot_overwrite_affected_mapping(self):
        for status in ('NOT_AFFECTED', 'ALREADY_FIXED'):
            with self.subTest(status=status), GitFixture() as fx:
                agent = from_case(fx.case(), fx.source_root, fx.run_root, auto_validation=False, exhaustive_discovery=True)
                agent.factory = workflow.QueueRuntime([(workflow.DiffWorkflowTest().assessment(agent), None)]).factory
                with patch.object(AospBackportAgent, 'run', return_value={'status': status}):
                    result = agent.run(max_attempts=1)
                self.assertEqual(result['status'], 'INCONCLUSIVE')
                self.assertEqual(result['impact_decision'], 'UNKNOWN')
                self.assertEqual(result['replan_required'], 'BACKEND_MAPPING_CONFLICT')
