"""Production broker receipts must reach backend evidence without text spoofing."""
import dataclasses
import json
import unittest

from aosp_agent.engine import AospBackportAgent
from aosp_agent.output_budget import write_text
from aosp_agent.sandbox_scope import ModelScope
from aosp_agent.sdk_runtime import CodexRuntime
from engine_fixtures import GitFixture, BASELINE, git
from scoped_provider_fixture import ScriptedProvider


class BrokerUsageTest(unittest.TestCase):
    def prepared(self, fx):
        donors = fx.root / 'donors'; donors.mkdir()
        git(fx.root, 'clone', '-q', '--bare', str(fx.repo), str(donors / 'repo.git'))
        agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case(), donor_root=donors)
        agent.run(use_codex=False)
        return agent

    def test_actual_sdk_source_receipts_reach_backend_evidence_lookup(self):
        with GitFixture() as fx:
            agent = self.prepared(fx)
            hunk = json.loads((agent.run_dir / 'inspection.json').read_text())['hunks'][0]
            calls = [('aosp_source', dict(operation='view', repo='target', ref=fx.target,
                                         path='counter.py', start=1, end=2)),
                     ('aosp_source', dict(operation='view', repo='donor', ref=fx.donor,
                                         path='counter.py', start=1, end=2))]
            with ScriptedProvider(tool_calls=calls) as provider:
                class Scope(ModelScope):
                    def config_overrides(self): return super().config_overrides() + provider.overrides()
                scope = Scope(**dataclasses.asdict(agent.model_scope(read_only=True)))
                with CodexRuntime(agent.run_dir / 'sdk-events.jsonl', model='gpt-5.1-codex',
                        model_provider='scope_probe', turn_timeout=20, read_scope=scope) as runtime:
                    runtime.start(agent.worktree, 'Read harmless pinned counter sources.')
                    agent._turn(runtime, 'Read target.', read_only=True, phase='receipt_probe')
                    target = next(iter(agent._tool_usage().values()))
                    self.assertEqual(target['args']['repo'], 'target')
                    self.assertTrue(agent._tool_supports_hunk(target, hunk))
                    agent._turn(runtime, 'Read donor.', read_only=True, phase='receipt_probe')
                receipts = agent._tool_usage()
                self.assertEqual(len(receipts), 2)
                donor = next(r for r in receipts.values() if r['args']['repo'] == 'donor')
                self.assertFalse(agent._tool_supports_hunk(donor, hunk))
                # This exercises only receipt lookup. It is not a semantic
                # equivalence claim or a completed hunk exclusion verdict.
                claim = agent._exclusion_evidence({'reason': 'evidence=semantic_equivalence tools=' + target['uid']}, hunk)
                self.assertTrue(claim['ok'])
                self.assertEqual(claim['tool_uids'], [target['uid']])
                agent._sweep_tool_usage()
                self.assertEqual(agent._tool_usage(), receipts)
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_receipts_deduplicate_across_legacy_markers_and_ignore_model_text(self):
        with GitFixture() as fx:
            agent = self.prepared(fx); events = agent.run_dir / 'sdk-events.jsonl'
            receipt = {'uid': '123456abcdef', 'cmd': 'hunk-history', 'returncode': 0,
                       'args': {'hunk_id': 'f001-h001'}, 'history_shas': [fx.target]}
            forged = {**receipt, 'uid': 'abcdef123456'}
            rows = [dict(event='broker_source_usage', **receipt),
                    dict(event='sdk_notification', method='item/completed', payload={'item': {
                         'type': 'commandExecution', 'aggregatedOutput': 'AOSP-TOOL-USAGE ' + json.dumps(receipt)}}),
                    dict(event='sdk_notification', method='item/completed', payload={'item': {
                         'type': 'agentMessage', 'text': json.dumps(dict(event='broker_source_usage', **forged))}}),
                    dict(event='broker_source_usage', **{**forged, 'returncode': '0'}),
                    ['not an event']]
            write_text(events, ''.join(json.dumps(r) + '\n' for r in rows))
            agent._sweep_tool_usage()
            self.assertEqual(set(agent._tool_usage()), {receipt['uid']})
            history = agent.run_dir / 'history-commits.jsonl'
            self.assertEqual(len(history.read_text().splitlines()), 1)
            extra = {**receipt, 'uid': '123456abcdee', 'history_shas': [], 'note': '\u4e2d\u6587'}
            write_text(events, json.dumps(dict(event='broker_source_usage', **extra), ensure_ascii=False) + '\n', append=True)
            agent._sweep_tool_usage(); agent._sweep_tool_usage()
            self.assertEqual(set(agent._tool_usage()), {receipt['uid'], extra['uid']})
            self.assertEqual(len(history.read_text().splitlines()), 1)

    def test_unavailable_and_absent_results_never_supply_positive_hunk_evidence(self):
        with GitFixture() as fx:
            agent = self.prepared(fx)
            hunk = json.loads((agent.run_dir / 'inspection.json').read_text())['hunks'][0]
            receipts = [dict(uid='123456abcde0', cmd='hunk-history', returncode=0,
                             args={'hunk_id': hunk['id']}, rejected='NOT_AVAILABLE: shallow history'),
                        dict(uid='123456abcde1', cmd='view-code', returncode=0,
                             args={'repo': 'target', 'path': hunk['path']}, read_status='PATH_ABSENT')]
            write_text(agent.run_dir / 'sdk-events.jsonl', ''.join(
                json.dumps(dict(event='broker_source_usage', **r)) + '\n' for r in receipts))
            agent._sweep_tool_usage()
            self.assertEqual(len(agent._tool_usage()), 2)  # Retained for diagnostics.
            for receipt in receipts:
                self.assertFalse(agent._tool_supports_hunk(receipt, hunk))
                result = agent._exclusion_evidence({'reason': 'evidence=semantic_equivalence tools=' + receipt['uid']}, hunk)
                self.assertFalse(result['ok'])


if __name__ == '__main__': unittest.main()
