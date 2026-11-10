"""Preparation consumption survives interruption before a frozen vector exists."""
import json
from pathlib import Path
import subprocess
from unittest import TestCase, mock

from aosp_agent.preparation import PreparationManager, PreparationError
from aosp_agent.resume import resume_batch
from aosp_agent.runtime_batch import RuntimeBatch
from engine_fixtures import GitFixture, git
from test_preparation import MemoryMounts, setup


class PreparationAccountingTest(TestCase):
    def interrupted_freeze(self, fixture):
        raw, row = setup(fixture)
        raw['preparation']['allow_fetch'] = True
        raw['batch_limits'] = {'min_free_bytes': 1}
        manifest = fixture.source_root / '.repo/manifests'
        xml = manifest / 'default.xml'
        xml.write_text(xml.read_text().replace(fixture.target, 'target'))
        git(manifest, 'commit', '-qam', 'mutable fixture target')
        git(manifest, 'tag', '-f', 'release')
        source = fixture.root / 'input.jsonl'
        source.write_text(json.dumps(row) + '\n')
        manager = PreparationManager(raw, overlays=MemoryMounts())
        runner = RuntimeBatch(source, fixture.source_root, fixture.run_root, raw['donor_root'],
                              preparer=manager, runtime_factory=lambda **kw: self.fail('model started'))
        original_git, original_advertise = manager._git, manager._advertise

        def offline_transport(root, *args, **kwargs):
            if args[0] == 'fetch':
                # Exercise real fetch admission/accounting without a transport.
                return subprocess.CompletedProcess(args, 128, '', 'fixture transport unavailable')
            self.assertFalse(kwargs.get('online', False))
            return original_git(root, *args, **kwargs)

        def stop_after_consumption(origin, revision, memo, original=None):
            original_advertise(origin, revision, memo, original=original)
            store = manager._store(origin, role='donor')
            with self.assertRaises(PreparationError) as caught:
                manager._fetch(store, origin, fixture.donor)
            self.assertEqual(caught.exception.kind, 'OBJECT_FETCH_FAILED')
            # A process lost during a reserved command must not reclaim its
            # unconfirmed time on the next invocation.
            manager._save_accounting(reserved_seconds=2)
            raise KeyboardInterrupt('fixture stops before writing the frozen vector')

        with mock.patch.object(manager, '_git', side_effect=offline_transport), \
                mock.patch.object(manager, '_advertise', side_effect=stop_after_consumption):
            result = runner.run(inspect_only=True)
        self.assertEqual(result['status'], 'CANCELLED', result)
        self.assertEqual(result['rows'], [])
        self.assertNotIn('preparation_frozen_receipt', result)
        self.assertFalse((runner.run_dir / 'preparation-frozen.json').exists())
        accounting = Path(result['batch_budget_root']) / 'preparation-budget.json'
        state = json.loads(accounting.read_text())
        self.assertEqual(state['fetches'], 1)
        self.assertEqual(state['ref_queries'], 1)
        self.assertEqual(state['local_ref_queries'], 1)
        self.assertEqual(state['remote_ref_queries'], 0)
        self.assertGreater(state['seconds_used'], 0)
        self.assertEqual(state['reserved_seconds'], 2)
        self.assertEqual(result['preparation_accounting'], str(accounting))
        return raw, runner, accounting, state

    def test_empty_batch_resume_preserves_preparation_consumption_before_refreeze(self):
        with GitFixture() as fixture:
            raw, runner, accounting, before = self.interrupted_freeze(fixture)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            first = []
            original_git = manager._git

            def observed(root, *args, **kwargs):
                self.assertFalse(kwargs.get('online', False))
                if not first:
                    self.assertEqual(manager.accounting_path, accounting)
                    self.assertEqual(manager.fetches, before['fetches'])
                    self.assertEqual(manager.ref_queries, before['ref_queries'])
                    self.assertEqual(manager.local_ref_queries, before['local_ref_queries'])
                    self.assertEqual(manager.remote_ref_queries, before['remote_ref_queries'])
                    self.assertGreaterEqual(manager.seconds_used,
                                            before['seconds_used'] + before['reserved_seconds'])
                    first.append(True)
                return original_git(root, *args, **kwargs)

            with mock.patch.object(manager, '_git', side_effect=observed):
                result = resume_batch(runner.run_dir / 'batch-status.json', preparer=manager,
                                      runtime_factory=lambda **kw: self.fail('resumed model started'))
            self.assertTrue(first)
            self.assertEqual(result['status'], 'COMPLETED', result)
            self.assertEqual([row['status'] for row in result['rows']], ['DISCOVERED'])
            self.assertEqual(result['batch_budget']['model_calls'], 0)
            self.assertEqual(result['batch_budget_root'], str(accounting.parent))
            self.assertEqual(result['preparation_accounting'], str(accounting))
            resumed_root = Path(result['record']).parent
            self.assertNotEqual(resumed_root, runner.run_dir)
            self.assertFalse((resumed_root / 'preparation-budget.json').exists())
            self.assertEqual(list(fixture.run_root.rglob('preparation-budget.json')), [accounting])
            after = json.loads(accounting.read_text())
            self.assertEqual(after['fetches'], 1)
            self.assertEqual(after['ref_queries'], 2)
            self.assertEqual(after['local_ref_queries'], 2)
            self.assertEqual(after['remote_ref_queries'], 0)
            self.assertGreaterEqual(after['seconds_used'], before['seconds_used'] + 2)

    def test_missing_original_preparation_accounting_blocks_empty_batch_resume(self):
        with GitFixture() as fixture:
            raw, runner, accounting, _ = self.interrupted_freeze(fixture)
            accounting.unlink()
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=AssertionError('missing accounting ran Git')):
                result = resume_batch(runner.run_dir / 'batch-status.json', preparer=manager,
                                      runtime_factory=lambda **kw: self.fail('blocked resume started a model'))
            self.assertEqual(result['status'], 'BLOCKED', result)
            self.assertEqual(result['completion_blocked_by'], 'PREPARATION_ACCOUNTING_UNAVAILABLE')
            self.assertEqual(result['rows'], [])
            self.assertEqual(result['preparation_accounting'], str(accounting))
            self.assertEqual(list(fixture.run_root.rglob('preparation-budget.json')), [])
