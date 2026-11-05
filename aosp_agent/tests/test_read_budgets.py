"""Bounded, offline read retries; timeout injection never sleeps in tests."""
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent import discovery
from aosp_agent.diff_engine import DiffBackportAgent
from engine_fixtures import BASELINE, FIXED, GitFixture, git
import test_diff_workflow as workflow


class ReadBudgetTest(unittest.TestCase):
    def test_tree_timeout_retries_same_revision_and_discards_partial_output(self):
        with GitFixture() as fx:
            original, calls, events = discovery.local_git, [], []
            def read(root, *args, **kwargs):
                if args[0] == 'ls-tree':
                    calls.append((args, kwargs['timeout']))
                    if len(calls) == 1:
                        raise subprocess.TimeoutExpired(['git', *args], kwargs['timeout'],
                            output='100644 blob broken\tPARTIAL_MUST_NOT_BE_PARSED\0')
                return original(root, *args, **kwargs)
            issues = []
            with patch.object(discovery, 'local_git', side_effect=read):
                repos = discovery.repositories(fx.repo, issues=issues, read_events=events.append)
            self.assertEqual([c[1] for c in calls], [45, 120])
            self.assertEqual(calls[0][0], calls[1][0])
            self.assertEqual(repos[0].head, fx.target)
            self.assertIn('counter.py', repos[0].files)
            self.assertNotIn('PARTIAL_MUST_NOT_BE_PARSED', repos[0].files)
            self.assertEqual(issues, [])
            terminal = [e for e in events if e['stage'] == 'read_tree' and e['status'] != 'STARTED']
            self.assertEqual([e['status'] for e in terminal], ['TIMED_OUT', 'SUCCEEDED'])
            self.assertEqual([e['attempt'] for e in terminal], [1, 2])

    def test_permanent_tree_timeout_keeps_attempt_details_and_no_partial_inventory(self):
        with GitFixture() as fx:
            original, calls = discovery.local_git, []
            def read(root, *args, **kwargs):
                if args[0] == 'ls-tree':
                    calls.append(kwargs['timeout'])
                    raise subprocess.TimeoutExpired(['git', *args], kwargs['timeout'])
                return original(root, *args, **kwargs)
            issues = []
            with patch.object(discovery, 'local_git', side_effect=read):
                repos = discovery.repositories(fx.repo, issues=issues)
            self.assertEqual(repos, [])
            self.assertEqual(calls, [45, 120])
            self.assertEqual(issues[0]['stage'], 'read_tree')
            self.assertEqual([a['timeout_seconds'] for a in issues[0]['attempts']], calls)

    def test_explicit_timeout_is_single_attempt(self):
        with patch.object(discovery, 'local_git', side_effect=subprocess.TimeoutExpired(['git'], 7)) as read:
            with self.assertRaises(subprocess.TimeoutExpired):
                discovery.read_git(Path('.'), 'ls-tree', 'HEAD', stage='read_tree', timeout=7)
            self.assertEqual(read.call_count, 1)
            self.assertEqual(read.call_args.kwargs['timeout'], 7)

    def test_non_timeout_failures_never_retry(self):
        for error in (subprocess.CalledProcessError(128, ['git'], stderr='missing object'),
                      FileNotFoundError('git executable missing'), PermissionError('repository denied')):
            with self.subTest(error=type(error).__name__), patch.object(discovery, 'local_git', side_effect=error) as read:
                events = []
                with self.assertRaises(type(error)):
                    discovery.read_git(Path('.'), 'rev-parse', 'HEAD', stage='resolve_commit', progress=events.append)
                self.assertEqual(read.call_count, 1)
                self.assertEqual(events[-1]['status'], 'ERROR')

    def test_grep_no_match_is_not_retried(self):
        result = subprocess.CompletedProcess(['git', 'grep'], 1, stdout='', stderr='')
        with patch.object(discovery, 'local_git', return_value=result) as read:
            actual = discovery.read_git(Path('.'), 'grep', 'symbol', stage='identifier_search', check=False)
            self.assertIs(actual, result)
            self.assertEqual(read.call_count, 1)
            self.assertFalse(read.call_args.kwargs['check'])

    def test_commit_resolution_has_a_smaller_budget_than_tree_scan(self):
        calls = []
        def timeout(root, *args, **kwargs):
            calls.append(kwargs['timeout'])
            raise subprocess.TimeoutExpired(['git', *args], kwargs['timeout'])
        with patch.object(discovery, 'local_git', side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                discovery.read_git(Path('.'), 'rev-parse', 'HEAD^{commit}', stage='resolve_commit')
        self.assertEqual(calls, [15, 45])
        self.assertLess(sum(calls), sum(discovery.READ_BUDGETS['read_tree']))

    def test_initial_state_retry_does_not_repeat_completed_steps(self):
        with GitFixture() as fx:
            repo = discovery.repositories(fx.repo)[0]
            original, calls = discovery.local_git, []
            def read(root, *args, **kwargs):
                calls.append((args[0], kwargs['timeout']))
                if args[0] == 'status' and sum(c[0] == 'status' for c in calls) == 1:
                    raise subprocess.TimeoutExpired(['git', *args], kwargs['timeout'])
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=read):
                state = repo.state(timeout=None)
            self.assertEqual(calls, [('rev-parse', 10), ('status', 45), ('status', 120), ('diff', 45)])
            self.assertEqual(state['head'], fx.target)
            self.assertEqual(state['status'], '')

    def test_later_audit_keeps_single_attempt_and_never_refreshes_baseline(self):
        with GitFixture() as fx:
            repo = discovery.repositories(fx.repo)[0]
            with patch.object(discovery, 'local_git', side_effect=subprocess.TimeoutExpired(['git'], 45)) as read:
                with self.assertRaises(subprocess.TimeoutExpired):
                    repo.state()
                self.assertEqual(read.call_count, 1)
                self.assertEqual(read.call_args.kwargs['timeout'], 45)

    def test_blob_size_timeout_recovers_before_reading_content(self):
        with GitFixture() as fx:
            repo = discovery.repositories(fx.repo)[0]
            original, calls = discovery.local_git, []
            def read(root, *args, **kwargs):
                calls.append((args[0], kwargs['timeout']))
                if len(calls) == 1:
                    raise subprocess.TimeoutExpired(['git', *args], kwargs['timeout'], output='99999999')
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=read):
                self.assertEqual(repo.read('counter.py'), BASELINE)
            self.assertEqual(calls, [('cat-file', 15), ('cat-file', 45), ('show', 30)])

    def test_attempts_persist_and_recovered_inventory_is_complete(self):
        with GitFixture() as fx:
            original, calls = discovery.local_git, []
            def read(root, *args, **kwargs):
                if args[0] == 'ls-tree':
                    calls.append(kwargs['timeout'])
                    if len(calls) == 1:
                        raise subprocess.TimeoutExpired(['git', *args], kwargs['timeout'])
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=read):
                agent = DiffBackportAgent(workflow.diff('counter.py', BASELINE, FIXED).encode(),
                                          fx.repo, fx.run_root)
                result = agent.run(inspect_only=True)
            self.assertEqual(result['inventory_status'], 'COMPLETE')
            self.assertEqual(result['status'], 'DISCOVERED')
            self.assertEqual(result['inventory_issues'], [])
            log = [json.loads(line) for line in (agent.run_dir / result['git_read_attempts']).read_text().splitlines()]
            tree = [e for e in log if e['stage'] == 'read_tree' and e['status'] != 'STARTED']
            self.assertEqual([e['status'] for e in tree], ['TIMED_OUT', 'SUCCEEDED'])
            self.assertTrue(all(e['repository'] == 'repo' for e in log))
            self.assertEqual(json.loads((agent.run_dir / 'run.json').read_text()), result)
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_repository_event_callbacks_keep_their_owner_after_inventory(self):
        with GitFixture() as fx:
            git(fx.source_root, 'clone', '-q', str(fx.repo), str(fx.source_root / 'peer'))
            events = []
            repos = discovery.repositories(fx.source_root, read_events=events.append)
            events.clear()
            for repo in repos:
                repo.read('counter.py')
            owners = [e['repository'] for e in events if e['stage'] == 'blob_read' and e['status'] == 'SUCCEEDED']
            self.assertEqual(owners, ['peer', 'repo'])

    def test_invalid_or_unbounded_explicit_budgets_are_rejected(self):
        for value in (0, -1, float('inf'), float('nan'), True):
            with self.subTest(value=value), patch.object(discovery, 'local_git') as read:
                with self.assertRaises(ValueError):
                    discovery.read_git(Path('.'), 'ls-tree', 'HEAD', stage='read_tree', timeout=value)
                read.assert_not_called()
