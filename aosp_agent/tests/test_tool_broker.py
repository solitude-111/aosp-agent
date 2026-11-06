"""Real local Git/SDK probes for before-execution admission and candidate edits."""
import hashlib
import dataclasses
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from aosp_agent.engine import AospBackportAgent
from aosp_agent.retrieval import BudgetExceeded, ReadBudget
from aosp_agent.sandbox_scope import ModelScope, source_scope
from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.sdk_runtime import CodexRuntime
from aosp_agent.tool_broker import ToolBroker
from aosp_agent.tool_io import ToolIO
from engine_fixtures import GitFixture, git
from scoped_provider_fixture import ScriptedProvider
from test_diff_workflow import diff
from engine_fixtures import BASELINE, FIXED


def response(row):
    return json.loads(row['contentItems'][0]['text'])


def call(broker, tool, args, ident='one', turn='turn'):
    return broker.handle('item/tool/call', dict(threadId='thread', turnId=turn,
                         callId=ident, tool=tool, arguments=args))


def digest(text): return hashlib.sha256(text.encode()).hexdigest()


class ToolBrokerTest(unittest.TestCase):
    def broker(self, root, *, scope=None, budget=None, read_only=False):
        broker = ToolBroker(scope or ModelScope((root,), (root / 'candidate',)), lambda *a, **k: None,
                            budget=budget)
        broker.begin('thread', root, read_only, 10)
        self.addCleanup(broker.end)
        return broker

    def test_operation_limit_denies_write_before_side_effect_and_is_shared(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); (root / 'metadata').write_text('catalogue')
            budget = ReadBudget(seconds=10, operations=1)
            broker = self.broker(root, budget=budget)
            self.assertTrue(call(broker, 'aosp_read_file', {'path': 'metadata', 'start': 1, 'end': 3})['success'])
            denied = call(broker, 'aosp_write_file', {'path': 'candidate', 'expected_sha256': 'ABSENT',
                            'operation': 'write', 'content': 'must not appear'}, 'two')
            self.assertFalse(denied['success']); self.assertIsInstance(broker.failure, BudgetExceeded)
            self.assertFalse((root / 'candidate').exists())
            self.assertEqual(budget.used, 1)

    def test_large_file_rejected_before_read_bytes_and_special_files_denied(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); (root / 'metadata').write_bytes(b'x' * 10000)
            budget = ReadBudget(seconds=10, operations=10, output_bytes=70000)
            broker = self.broker(root, budget=budget)
            denied = call(broker, 'aosp_read_file', {'path': 'metadata', 'start': 1, 'end': 1})
            self.assertFalse(denied['success']); self.assertLess(budget.bytes_used, 70000)
            self.assertGreaterEqual(budget.bytes_used, 65536)  # Reply reservation succeeded; data reservation did not.
            self.assertIsInstance(broker.failure, BudgetExceeded)

    def test_only_exact_candidate_writes_with_current_hash_no_symlink_or_peer(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); candidate = root / 'candidate'; candidate.write_text('original\n')
            peer = root / 'peer'; peer.write_text('peer')
            broker = self.broker(root)
            args = dict(path='candidate', expected_sha256=digest('original\n'), operation='write', content='changed\n')
            self.assertTrue(call(broker, 'aosp_write_file', args)['success'])
            self.assertEqual(candidate.read_text(), 'changed\n')
            self.assertFalse(call(broker, 'aosp_write_file', args, 'stale')['success'])
            self.assertFalse(call(broker, 'aosp_write_file', {**args, 'path': 'peer', 'expected_sha256': digest('peer')}, 'peer')['success'])
            candidate.unlink(); candidate.symlink_to(peer)
            self.assertFalse(call(broker, 'aosp_write_file', {**args, 'expected_sha256': digest('peer')}, 'link')['success'])
            self.assertEqual(peer.read_text(), 'peer')

    def test_phase_transition_revokes_edits_and_replays_or_old_turns(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); broker = self.broker(root)
            args = dict(path='candidate', expected_sha256='ABSENT', operation='write', content='one')
            self.assertTrue(call(broker, 'aosp_write_file', args)['success'])
            self.assertFalse(call(broker, 'aosp_write_file', args)['success'])
            broker.end(); broker.begin('thread', root, True, 10)
            args.update(expected_sha256=digest('one'), content='two')
            self.assertFalse(call(broker, 'aosp_write_file', args, 'old-turn')['success'])
            self.assertFalse(call(broker, 'aosp_write_file', args, 'new', turn='second')['success'])
            self.assertEqual((root / 'candidate').read_text(), 'one')
            self.assertEqual(broker.handle('item/commandExecution/requestApproval', {})['decision'], 'decline')

    def test_unique_replace_delete_and_new_parent_creation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); target = root / 'nested/file.py'
            broker = self.broker(root, scope=ModelScope((root,), (target,)))
            self.assertTrue(call(broker, 'aosp_write_file', dict(path=str(target), expected_sha256='ABSENT',
                operation='write', content='return old\n'))['success'])
            change = dict(path=str(target), expected_sha256=digest('return old\n'), old='old', new='new')
            self.assertTrue(call(broker, 'aosp_replace_text', change, 'replace')['success'])
            self.assertEqual(target.read_text(), 'return new\n')
            self.assertTrue(call(broker, 'aosp_write_file', dict(path=str(target), expected_sha256=digest('return new\n'),
                operation='delete', content=''), 'delete')['success'])
            self.assertFalse(target.exists())

    def test_scoped_metadata_cannot_read_repo_or_symlink_even_when_git_root_is_admitted(self):
        with GitFixture() as fx:
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case()); agent.prepare(); agent.inspect()
            broker = self.broker(agent.run_dir, scope=agent.model_scope())
            for ident, path in [('original', fx.repo / 'counter.py'), ('git', fx.repo / '.git/config')]:
                with self.subTest(path=path):
                    self.assertFalse(call(broker, 'aosp_read_file', {'path': str(path), 'start': 1, 'end': 2}, ident)['success'])
            (agent.run_dir / 'alias').symlink_to(fx.repo / 'counter.py')
            self.assertFalse(call(broker, 'aosp_read_file', {'path': 'alias', 'start': 1, 'end': 2}, 'alias')['success'])

    def test_source_tools_use_pinned_git_and_count_internal_commands(self):
        with GitFixture() as fx:
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case()); agent.prepare(); agent.inspect()
            broker = self.broker(agent.run_dir, scope=agent.model_scope())
            args = dict(operation='view', repo='target', ref=fx.target, path='counter.py', start=1, end=2)
            result = call(broker, 'aosp_source', args)
            self.assertTrue(result['success'], result)
            self.assertIn('return value', json.dumps(response(result)))
            self.assertEqual(broker.budget.used, 2)  # request and real Git subprocess
            self.assertGreater(broker.budget.bytes_used, 0)
            self.assertFalse(call(broker, 'aosp_source', {**args, 'ref': fx.donor}, 'wrong-ref')['success'])
            self.assertFalse(call(broker, 'aosp_source', {**args, 'repo': 'target:unadmitted'}, 'wrong-repo')['success'])
            search = call(broker, 'aosp_source', dict(operation='search', repo='target', ref=fx.target, query='normalize_count'), 'search')
            self.assertTrue(search['success'], search)
            self.assertIn('counter.py', response(search)['text'])

    def test_output_limit_and_cancel_reap_actual_subprocess(self):
        for mode in ('output', 'cancel'):
            with self.subTest(mode=mode):
                cancelled = threading.Event(); budget = ReadBudget(seconds=10, operations=100)
                io = ToolIO(budget, cancelled, time.monotonic() + 10, max_output=1024)
                processes = []; original = subprocess.Popen
                def tracked(*args, **kwargs):
                    process = original(*args, **kwargs); processes.append(process); return process
                timer = threading.Timer(.1, cancelled.set) if mode == 'cancel' else None
                if timer: timer.start()
                try:
                    with patch('aosp_agent.tool_io.subprocess.Popen', tracked), self.assertRaises(BudgetExceeded):
                        io.run([sys.executable, '-c', 'import time; ' +
                                ('time.sleep(20)' if mode == 'cancel' else 'print("x" * 10000); time.sleep(20)')])
                finally:
                    if timer: timer.join()
                self.assertIsNotNone(processes[0].poll())
                self.assertTrue(processes[0].stdout.closed)

    def test_actual_sdk_typed_reads_edits_and_no_native_execution(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); file = root / 'candidate'; file.write_text('original')
            marker = root / 'native-marker'
            calls = [
                ('aosp_read_file', {'path': 'candidate', 'start': 1, 'end': 2}),
                ('aosp_replace_text', {'path': 'candidate', 'expected_sha256': digest('original'), 'old': 'original', 'new': 'changed'}),
                ('aosp_write_file', {'path': 'candidate', 'expected_sha256': digest('changed'), 'operation': 'write', 'content': 'forbidden'}),
                ('exec_command', {'cmd': 'touch ' + shlex.quote(str(marker))}),
            ]
            with ScriptedProvider(tool_calls=calls) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                with CodexRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                                  turn_timeout=20, read_scope=Scope((root,), (file, marker))) as runtime:
                    runtime.start(root, 'Harmless controller tools test.')
                    for read_only in (True, False, True, False):
                        runtime.run('Execute the requested test tool.', read_only=read_only)
                    self.assertEqual(file.read_text(), 'changed')
                    self.assertFalse(marker.exists())
                    self.assertGreater(runtime._broker.budget.used, 0)
                for names in provider.tool_names:
                    self.assertIn('aosp_source', names)
                    self.assertFalse(set(names) & {'exec_command', 'apply_patch', 'shell', 'web_search', 'view_image'})
                output = json.dumps(provider.tool_outputs)
                self.assertIn('original', output)
                self.assertIn('this phase cannot modify', output)

    def test_actual_sdk_shared_budget_prevents_second_turn_write(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); (root / 'meta').write_text('catalogue'); candidate = root / 'candidate'
            with ScriptedProvider(tool_calls=[
                ('aosp_read_file', {'path': 'meta', 'start': 1, 'end': 2}),
                ('aosp_write_file', {'path': 'candidate', 'expected_sha256': 'ABSENT', 'content': 'bad', 'operation': 'write'})]) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                budget = ReadBudget(seconds=20, operations=1)
                with budget.active(), CodexRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                        turn_timeout=20, read_scope=Scope((root,), (candidate,))) as runtime:
                    runtime.start(root, 'Harmless admission test.')
                    runtime.run('Read metadata.')
                    with self.assertRaises(BudgetExceeded): runtime.run('Attempt edit.', read_only=False)
                    self.assertTrue(runtime._closed)
                self.assertFalse(candidate.exists()); self.assertEqual(budget.used, 1)

    def test_actual_sdk_text_diff_source_context_and_unavailable_history(self):
        with GitFixture() as fx:
            controller = DiffBackportAgent(diff('counter.py', BASELINE, FIXED).encode(), fx.repo, fx.run_root,
                                           repository_keys=['repo'], lazy_reads=True)
            controller.run(inspect_only=True)
            base = controller.model_scope()
            calls = [('aosp_source', dict(operation='view', repo='target:repo', ref=fx.target,
                                         path='counter.py', start=1, end=2)),
                     ('aosp_source', dict(operation='history', hunk_id='f001-h001'))]
            with ScriptedProvider(tool_calls=calls) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                scope = Scope(base.readable, base.writable, base.denied, base.tool_readable,
                              base.tool_context, base.tool_repositories)
                with CodexRuntime(controller.run_dir / 'sdk-probe.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                                  turn_timeout=20, read_scope=scope) as runtime:
                    runtime.start(controller.run_dir, 'Read benign fixed source.')
                    runtime.run('Read source.'); runtime.run('Check history availability.')
                output = json.dumps(provider.tool_outputs)
                self.assertIn('return value', output)
                self.assertIn('NOT_AVAILABLE', output)
                self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_explicit_revision_context_never_logs_into_original_repository(self):
        with GitFixture() as fx:
            patch = fx.root / 'input.patch'; patch.write_text('ordinary metadata')
            scope = source_scope(patch, [fx.repo], tool_repositories={
                'before': {'root': str(fx.repo), 'head': fx.target},
                'after': {'root': str(fx.repo), 'head': fx.donor}})
            broker = self.broker(fx.repo, scope=scope, read_only=True)
            for number, (key, sha, expected) in enumerate((('before', fx.target, 'return value'),
                                                         ('after', fx.donor, 'return max'))):
                result = call(broker, 'aosp_source', dict(operation='view', repo='target:' + key,
                               ref=sha, path='counter.py', start=1, end=2), str(number))
                self.assertTrue(result['success'], result)
                self.assertIn(expected, json.dumps(response(result)))
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
            self.assertFalse((fx.repo / 'tool-usage.jsonl').exists())

    def test_actual_sdk_agent_flow_reads_edits_verifies_and_reviews_benign_counter(self):
        with GitFixture() as fx:
            calls = [
                ('aosp_source', dict(operation='view', repo='target', ref=fx.target, path='counter.py', start=1, end=2)),
                ('aosp_replace_text', dict(path='counter.py', expected_sha256=digest(BASELINE), old=BASELINE, new=FIXED)),
                ('aosp_read_file', dict(path='counter.py', start=1, end=2)),
            ]
            review = dict(overall_risk='low', affected_callers=['ordinary counter callers'],
                behavior_changes=['counter values are bounded'], compatibility_risks=[], performance_notes=[],
                test_recommendations=['run the normal counter checks'], reasoning='Benign scripted review fixture.')
            with ScriptedProvider(tool_calls=calls, final_responses=[fx.assessment(),
                    'HUNK-RESULT f001-h001 implemented adapted the donor fix to the target baseline.', review]) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                def factory(**kwargs):
                    kwargs.update(model='gpt-5.1-codex', model_provider='scope_probe', turn_timeout=20,
                                  read_scope=Scope(**dataclasses.asdict(kwargs['read_scope'])))
                    return CodexRuntime(**kwargs)
                agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case(validation=True), runtime_factory=factory)
                result = agent.run(verify=True, max_attempts=1, mechanical=False)
                self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)  # No Android production build.
                self.assertEqual(result['final_verification']['status'], 'PASS')
                self.assertEqual(result['post_fix_review']['status'], 'COMPLETED')
                self.assertEqual((agent.worktree / 'counter.py').read_text(), FIXED)
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
                self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
                self.assertEqual(provider.response_index, 3)
                events = [json.loads(s) for s in (agent.run_dir / 'sdk-events.jsonl').read_text().splitlines()]
                self.assertEqual(sum(e['event'] == 'broker_tool' and e['success'] for e in events), 3)
