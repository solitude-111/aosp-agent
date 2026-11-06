import asyncio
import json
from pathlib import Path
import shlex
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aosp_agent.sandbox_scope import ModelScope, ScopeUnavailable, git_read_roots, source_scope, start_scoped_thread
from aosp_agent.sdk_runtime import CodexRuntime, CodexRuntimeError
from aosp_agent.project_first import ProjectFirstAgent
from aosp_agent.engine import AospBackportAgent
from aosp_agent.agent_tools import _write_wrappers
from engine_fixtures import GitFixture, git
from test_diff_workflow import QueueRuntime
import test_project_first as routing
from scoped_provider_fixture import ScriptedProvider, command_output


class NativeDiagnosticRuntime(CodexRuntime):
    """Exercise OS profiles independently; production never exposes this adapter."""
    def _make_broker(self): return None


class NativeDiagnosticScope(ModelScope):
    def config_overrides(self):
        return super().config_overrides() + ('features.shell_tool=true',)


class ModelScopeTest(unittest.TestCase):
    def test_scope_rejects_broad_root_and_writes_outside_explicit_read_scope(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for kwargs in ({'readable': ('/',)}, {'readable': ()},
                           {'readable': (root / 'read',), 'writable': (root / 'outside',)},
                           {'readable': (root,), 'writable': (root / 'no',), 'denied': (root / 'no',)}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ScopeUnavailable): ModelScope(**kwargs)

    def test_read_and_edit_profiles_keep_read_denials_and_differ_only_on_authorized_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            scope = ModelScope((root,), (root / 'file',), (root / 'nested',))
            read, edit = scope.filesystem(), scope.filesystem(False)
            self.assertEqual(read[':root'], 'deny')
            self.assertEqual(read[str((root / 'nested').resolve())], 'deny')
            self.assertEqual(edit[str((root / 'nested').resolve())], 'deny')
            self.assertEqual({k for k in edit if edit[k] != read.get(k)}, set(scope.writable))

    def test_worktree_git_metadata_and_alternates_are_scoped_without_granting_parent(self):
        with GitFixture() as fx:
            worktree = fx.root / 'candidate'
            git(fx.repo, 'worktree', 'add', '--detach', str(worktree), fx.target)
            roots = git_read_roots([worktree])
            self.assertIn(fx.repo / '.git', roots)
            self.assertNotIn(fx.source_root, roots)
            clone = fx.root / 'shared'
            git(fx.root, 'clone', '--shared', str(fx.repo), str(clone))
            self.assertIn(fx.repo / '.git/objects', git_read_roots([clone]))

    def test_alternate_metadata_limit_blocks_scope_creation(self):
        with GitFixture() as fx:
            alternate = fx.repo / '.git/objects/info/alternates'
            alternate.write_bytes(b'x' * 65537)
            with self.assertRaisesRegex(ScopeUnavailable, 'metadata is too large'):
                git_read_roots([fx.repo])

    def test_runtime_profile_mismatch_fails_before_any_model_turn(self):
        async def scenario():
            calls = []
            async def request(method, params, response_model):
                calls.append((method, params))
                result = ({'config': {'mcp_servers': {'unsafe.server': {'command': '/bin/false', 'enabled': True}}}} if method == 'config/read'
                          else {'thread': {'id': 'fake'}, 'activePermissionProfile': {'id': ':read-only'}})
                return response_model(result)
            codex = SimpleNamespace(_client=SimpleNamespace(request=request))
            with self.assertRaisesRegex(ScopeUnavailable, 'did not activate'):
                await start_scoped_thread(codex, ModelScope((Path.cwd(),)), cwd=Path.cwd(), instructions='scope test')
            self.assertEqual(calls[-1][1]['config']['mcp_servers'], {'unsafe.server': {'command': '/bin/false', 'enabled': False}})
            self.assertNotIn('sandbox', calls[-1][1])
        asyncio.run(scenario())

    def test_routing_cannot_read_target_and_investigation_cannot_read_unselected_peer(self):
        with GitFixture() as fx:
            fixture = routing.ProjectFirstTest()
            class RecordingRuntime(QueueRuntime):
                def factory(self, **kwargs):
                    self.options.append(kwargs)
                    return self
            runtime = RecordingRuntime([(fixture.plan(), None), (fixture.assessment(), None)])
            runtime.options = []
            agent = ProjectFirstAgent(fixture.source(), fx.source_root, fx.run_root,
                catalog=fixture.catalog(fx, peer=True), runtime_factory=runtime.factory, auto_validation=False)
            self.assertEqual(agent.run(impact_only=True)['status'], 'AFFECTED')
            planning, investigation = [o['read_scope'] for o in runtime.options]
            self.assertEqual(planning.readable, (str(agent.run_dir),))
            self.assertNotIn(str(fx.repo), planning.readable)
            self.assertIn(str(fx.repo), investigation.readable)
            self.assertFalse(any((fx.source_root / 'peer').is_relative_to(p) for p in investigation.readable))
            self.assertFalse(investigation.writable)

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'native Codex sandbox is required')
    def test_real_sdk_commands_keep_scope_across_read_edit_read_and_remove_external_tools(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); visible = root / 'visible'; visible.mkdir()
            allowed = visible / 'allowed'; allowed.write_text('READ_OK\n')
            outside = root / 'outside'; outside.write_text('outside\n')
            alias = visible / 'alias'; alias.symlink_to(outside)
            edit = visible / 'edit'; edit.write_text('original')
            peer = visible / 'peer'; peer.write_text('peer')
            launched = root / 'external-server-started'
            cmd = 'cat ' + shlex.quote(str(allowed))
            for name, path in (('OUTSIDE', outside), ('ALIAS', alias)):
                cmd += '; if cat ' + shlex.quote(str(path)) + ' >/dev/null 2>&1; then echo ' + name + '_BAD; else echo ' + name + '_DENIED; fi'
            cmd += '; if (printf changed > ' + shlex.quote(str(edit)) + ') 2>/dev/null; then echo EDIT_OK; else echo EDIT_DENIED; fi'
            cmd += '; if (printf bad > ' + shlex.quote(str(peer)) + ') 2>/dev/null; then echo PEER_BAD; else echo PEER_DENIED; fi'
            cmd += '; if [ -n "$AOSP_SCOPE_SENTINEL" ]; then echo ENV_BAD; else echo ENV_EMPTY; fi'
            with ScriptedProvider(cmd) as provider:
                class Scope(NativeDiagnosticScope):
                    def config_overrides(self):
                        from aosp_agent.sandbox_scope import _toml
                        # A configured server is deliberately present. An empty
                        # mcp_servers table alone must not pass this test.
                        server = {'command': sys.executable, 'args': ['-c',
                            'from pathlib import Path; Path(' + repr(str(launched)) + ').touch()'], 'enabled': True}
                        return super().config_overrides() + provider.overrides() + (
                            'mcp_servers.aosp_scope_canary=' + _toml(server),
                            'shell_environment_policy.set.AOSP_SCOPE_SENTINEL="not-for-model-tools"')
                with NativeDiagnosticRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                        turn_timeout=25, read_scope=Scope((visible,), (edit,))) as runtime:
                    runtime.start(visible, 'Harmless filesystem canary only.')
                    for read_only in (True, False, True):
                        edit.write_text('original')
                        result = runtime.run('Execute the canary.', read_only=read_only)
                        output = command_output(result)
                        self.assertIn('READ_OK', output)
                        self.assertIn('OUTSIDE_DENIED', output)
                        self.assertIn('ALIAS_DENIED', output)
                        self.assertIn('PEER_DENIED', output)
                        self.assertIn('ENV_EMPTY', output)
                        self.assertIn('EDIT_DENIED' if read_only else 'EDIT_OK', output)
                        self.assertEqual(edit.read_text(), 'original' if read_only else 'changed')
                        self.assertEqual(peer.read_text(), 'peer')
                self.assertFalse(launched.exists())
                for names in provider.tool_names:
                    self.assertFalse(any(name.startswith('mcp') or name in ('web_search', 'spawn_agent', 'view_image') for name in names))

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'native Codex sandbox is required')
    def test_background_cleanup_failure_closes_runtime_before_result_is_accepted(self):
        with tempfile.TemporaryDirectory() as raw, ScriptedProvider('true') as provider:
            root = Path(raw).resolve()
            class Scope(NativeDiagnosticScope):
                def config_overrides(self): return super().config_overrides() + provider.overrides()
            async def failed_cleanup(*args):
                raise RuntimeError('injected cleanup transport failure')
            with NativeDiagnosticRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                    turn_timeout=20, read_scope=Scope((root,))) as runtime:
                runtime.start(root, 'Harmless cleanup failure regression.')
                with patch('aosp_agent.sandbox_scope.clean_background_terminals', failed_cleanup):
                    with self.assertRaises(CodexRuntimeError) as caught:
                        runtime.run('Execute the ordinary no-op.')
                self.assertEqual(caught.exception.kind, 'BACKGROUND_CLEANUP_FAILED')
                self.assertTrue(runtime._closed)
                with self.assertRaises(RuntimeError): runtime.run('Must not continue.')

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'native Codex sandbox is required')
    def test_edit_terminal_cannot_write_after_control_returns_or_during_readonly_turn(self):
        for background in (False, True):
            with self.subTest(background=background), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); visible = root / 'visible'; visible.mkdir()
                marker = visible / 'marker'; marker.write_text('original')
                trigger = visible / 'trigger'
                command = ('i=0; while [ ! -f ' + shlex.quote(str(trigger)) + ' ] && [ "$i" -lt 100 ]; '
                    'do sleep 0.1; i=$((i+1)); done; if [ -f ' + shlex.quote(str(trigger)) +
                    ' ]; then printf changed > ' + shlex.quote(str(marker)) + '; fi')
                if background:
                    command = 'sh -c ' + shlex.quote(command) + ' </dev/null >/dev/null 2>&1 &'
                with ScriptedProvider(command, {'yield_time_ms': 1000}) as provider:
                    class Scope(NativeDiagnosticScope):
                        def config_overrides(self): return super().config_overrides() + provider.overrides()
                    with NativeDiagnosticRuntime(root / 'events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                            turn_timeout=20, read_scope=Scope((visible,), (marker,))) as runtime:
                        runtime.start(visible, 'Harmless phase transition regression.')
                        runtime.run('Start a bounded ordinary marker process.', read_only=False)
                        before_calls = provider.calls
                        provider.command = 'sleep 0.5; cat ' + shlex.quote(str(marker))
                        def signal():
                            deadline = time.monotonic() + 5
                            while provider.calls <= before_calls and time.monotonic() < deadline:
                                time.sleep(0.02)
                            if provider.calls > before_calls: trigger.write_text('go')
                        worker = threading.Thread(target=signal); worker.start()
                        try:
                            runtime.run('Read the marker.', read_only=True)
                        finally:
                            worker.join()
                        self.assertEqual(marker.read_text(), 'original')
                    events = [json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()]
                    self.assertEqual(sum(e['event'] == 'background_terminals_cleaned' for e in events), 2)

    @unittest.skipUnless(sys.platform in ('darwin', 'linux'), 'native Codex sandbox is required')
    def test_real_controlled_source_tool_reads_pinned_git_with_scoped_python_support(self):
        with GitFixture() as fx:
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case())
            agent.prepare(); agent.inspect(); _write_wrappers(agent.run_dir)
            cmd = ' '.join(shlex.quote(str(x)) for x in [agent.run_dir / 'bin/view-code', '--repo', 'target',
                '--ref', fx.target, '--path', 'counter.py', '--start', '1', '--end', '2'])
            with ScriptedProvider(cmd) as provider:
                class Scope(NativeDiagnosticScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                base = agent.model_scope(read_only=True)
                scope = Scope(base.readable, (), base.denied)
                with NativeDiagnosticRuntime(fx.root / 'scoped-events.jsonl', model='gpt-5.1-codex', model_provider='scope_probe',
                                  turn_timeout=25, read_scope=scope) as runtime:
                    runtime.start(agent.worktree, 'Read the ordinary counter source using the controlled wrapper.')
                    output = command_output(runtime.run('Read the counter.'))
                self.assertIn('def normalize_count(value):', output)
                self.assertIn('return value', output)
                self.assertNotIn('Operation not permitted', output)
