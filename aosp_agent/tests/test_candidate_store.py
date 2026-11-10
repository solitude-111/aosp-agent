import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from aosp_agent.candidate_store import CandidateStore, agent_identity, recover_stopped_candidates
from aosp_agent.engine import AospBackportAgent
from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.lifecycle import RecoveryBlocked, run_lease, source_lease
from aosp_agent.output_budget import create_budget, METADATA_RESERVE
from aosp_agent.sdk_runtime import CodexRuntimeError
from engine_fixtures import BASELINE, FIXED, PARTIAL, GitFixture, ScriptedRuntime, write_counter, git


class CandidateStoreTest(unittest.TestCase):
    def identity(self, repository='repo', targets=None):
        return {'source': {'input_sha256': 'a' * 64}, 'repository': repository,
                'targets': targets or {'repo': 'b' * 40}}

    def save(self, store, data, *, identity=None, kind='model', parent=None):
        attempt = store.begin(identity or self.identity(), source_record='/run/round/run.json', source_kind=kind,
                              parent=parent)
        candidate = store.observe(attempt, data)
        store.finish(attempt, status='PATCH_UNVERIFIED')
        return attempt, candidate

    def test_no_change_repeated_bytes_and_later_failure_keep_distinct_views(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CandidateStore(Path(directory) / 'candidates')
            first, good = self.save(store, 'first patch')
            store.evidence(good, 'replay', {'status': 'pass', 'target_commit': 'b' * 40,
                'patch_sha256': hashlib.sha256(b'first patch').hexdigest()})
            duplicate, same = self.save(store, 'first patch')
            last, bad = self.save(store, 'later unreviewed patch', parent=good)
            empty, nothing = self.save(store, '')
            snapshot = CandidateStore(store.root).snapshot()
            summary = store.summary()
            self.assertEqual(same, good)
            self.assertIsNone(nothing)
            self.assertEqual(snapshot['attempts'][duplicate]['change'], 'NO_NEW_CANDIDATE')
            self.assertEqual(snapshot['attempts'][last]['parent_candidate_id'], good)
            self.assertEqual(summary['last_attempt'], empty)
            self.assertEqual(summary['latest_candidate'], bad)
            self.assertEqual(summary['latest_replayable_candidate'], good)
            self.assertIsNone(summary['latest_delivery_eligible_candidate'])
            self.assertEqual(summary['candidate_count'], 2)
            self.assertEqual(len(list((store.root / 'patches').glob('*.patch'))), 2)

    def test_identity_and_artifact_tampering_cannot_restore_or_inherit_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CandidateStore(directory)
            _, ident = self.save(store, 'patch')
            changed = self.identity(targets={'repo': 'c' * 40})
            with self.assertRaises(RecoveryBlocked):
                store.load(ident, changed)
            with self.assertRaises(RecoveryBlocked):
                store.evidence(ident, 'replay', {'patch_sha256': 'wrong', 'status': 'pass'})
            with self.assertRaises(RecoveryBlocked):
                store.evidence(ident, 'delivery', {'patch_sha256': hashlib.sha256(b'patch').hexdigest(),
                                                  'status': 'VALIDATED'})
            artifact = store.root / store.snapshot()['candidates'][ident]['artifact']
            artifact.write_text('changed')
            with self.assertRaises(RecoveryBlocked):
                store.load(ident, self.identity())
            with self.assertRaises(RecoveryBlocked):
                self.save(store, 'patch')

    def test_bundle_rejects_mixed_pins_and_does_not_grant_joint_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CandidateStore(directory)
            targets = {'repo': 'b' * 40, 'other': 'c' * 40}
            _, one = self.save(store, 'one', identity=self.identity(targets=targets))
            _, two = self.save(store, 'two', identity=self.identity('other', targets))
            bundle = store.bundle([two, one], source_record='/run/round/run.json')
            self.assertEqual(bundle, store.bundle([one, two], source_record='/run/round/run.json'))
            self.assertEqual(store.snapshot()['bundles'][bundle]['status'], 'UNVERIFIED')
            _, wrong = self.save(store, 'wrong', identity=self.identity('other', {**targets, 'other': 'd' * 40}))
            with self.assertRaises(RecoveryBlocked):
                store.bundle([one, wrong], source_record='/run/round/run.json')

    def test_crash_after_candidate_bytes_before_index_never_publishes_missing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CandidateStore(directory)
            attempt = store.begin(self.identity(), source_record='/run/run.json')
            with patch.object(store, '_save', side_effect=OSError('crash before index commit')):
                with self.assertRaises(OSError):
                    store.observe(attempt, 'preserved bytes')
            self.assertEqual(store.snapshot()['candidates'], {})
            self.assertEqual(len(list((store.root / 'patches').glob('*.patch'))), 1)
            ident = store.observe(attempt, 'preserved bytes')
            self.assertEqual(store.load(ident, self.identity()), 'preserved bytes')
            self.assertEqual(len(list((store.root / 'patches').glob('*.patch'))), 1)

    def test_control_quota_exhaustion_cannot_admit_an_unrecorded_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = create_budget(root, 128 * 1024)
            store = CandidateStore(root / 'candidates')
            before = store.path.read_bytes()
            state = budget.data()
            remaining = state['limit'] - METADATA_RESERVE - state['normal_reserved'] - state['control_reserved']
            self.assertTrue(budget.write(root / 'fill', b'x' * remaining, control=True))
            with self.assertRaisesRegex(RecoveryBlocked, 'not durably saved'):
                store.begin(self.identity(), source_record=root / 'run.json')
            self.assertTrue(budget.data()['exhausted'])
            self.assertEqual(store.path.read_bytes(), before)
            self.assertEqual(store.snapshot()['attempts'], {})

    def test_restore_requires_clean_baseline_and_repeats_gates_without_copying_pass(self):
        with GitFixture() as fixture:
            first = AospBackportAgent(fixture.source_root, fixture.run_root / 'old', fixture.case())
            first.prepare()
            (first.worktree / 'counter.py').write_text(FIXED)
            first.export_patch(1)
            store = first._candidate_store
            ident = first.record['candidate_id']
            second = AospBackportAgent(fixture.source_root, fixture.run_root / 'new', fixture.case())
            second.prepare()
            store.restore(second, ident)
            self.assertEqual((second.worktree / 'counter.py').read_text(), FIXED)
            self.assertEqual(second.record['restored_candidate']['status'], 'DRAFT')
            self.assertFalse(second.record['restored_candidate']['prior_validation_reused'])
            self.assertEqual(second.record['patch_replay'], 'not_run')
            self.assertNotIn('final_verification', second.record)
            with self.assertRaises(RuntimeError):
                store.restore(second, ident)
            self.assertEqual(git(fixture.repo, 'status', '--porcelain'), '')

    def test_narrowed_restore_scope_is_incompatible_and_gate_failure_rolls_back_exactly(self):
        with GitFixture() as fixture:
            first = AospBackportAgent(fixture.source_root, fixture.run_root / 'old', fixture.case())
            first.prepare()
            (first.worktree / 'counter.py').write_text(FIXED)
            first.export_patch(1)
            store, ident = first._candidate_store, first.record['candidate_id']
            narrow = AospBackportAgent(fixture.source_root, fixture.run_root / 'narrow',
                                      replace(fixture.case(), files=('check_lower.py',)))
            narrow.prepare()
            self.assertIsNone(store.restore(narrow, ident))
            self.assertEqual(narrow.record['restored_candidate']['reason'], 'EDIT_SCOPE_CHANGED')
            self.assertEqual((narrow.worktree / 'counter.py').read_text(), BASELINE)
            narrow.audit_diff(require_clean=True)
            current = AospBackportAgent(fixture.source_root, fixture.run_root / 'current', fixture.case())
            current.prepare()
            with patch.object(current, '_new_file_integration_audit', return_value={'status': 'REJECTED'}):
                self.assertIsNone(store.restore(current, ident))
            self.assertEqual(current.record['restored_candidate']['reason'], 'SOURCE_INTEGRATION_CHANGED')
            self.assertEqual((current.worktree / 'counter.py').read_text(), BASELINE)
            current.audit_diff(require_clean=True)
            artifact = store.root / store.snapshot()['candidates'][ident]['artifact']
            artifact.write_text('corrupted bytes')
            with self.assertRaisesRegex(RecoveryBlocked, 'checksum'):
                store.restore(narrow, ident)

    def stopped_writer(self, fixture, content=PARTIAL):
        # The process exits without Python finally handlers, run finalization or
        # a candidate export. Its registered attempt is the only recovery key.
        script = '''
import json, os, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
from aosp_agent.case import Case
from aosp_agent.engine import AospBackportAgent
from aosp_agent.lifecycle import run_lease, source_lease
from aosp_agent.runtime_children import RuntimeChild
agent = AospBackportAgent(Path(sys.argv[1]), Path(sys.argv[2]), Case(**json.loads(sys.argv[3])))
agent.prepare()
with run_lease(agent.run_dir), source_lease(agent.source_root):
    child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.buffer.read()'],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tracker = RuntimeChild(agent.run_dir / 'events.jsonl', child)
    agent._begin_candidate_attempt('model', runtime=SimpleNamespace(_broker=object(), recovery_child=tracker.reference))
    child.stdin.close()
    child.wait(timeout=10)
    (agent.worktree / 'counter.py').write_text(sys.argv[4])
    os._exit(23)
'''
        result = subprocess.run([sys.executable, '-c', script, str(fixture.source_root),
            str(fixture.run_root), json.dumps(asdict(fixture.case())), content], capture_output=True, text=True,
            cwd=Path(__file__).resolve().parents[2])
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        return fixture.run_root / fixture.case().cve / 'run.json'

    def test_actual_process_exit_recovers_registered_draft_only_after_source_lease(self):
        with GitFixture() as fixture:
            record = self.stopped_writer(fixture)
            store = CandidateStore(record.parent / 'candidate-store')
            self.assertEqual(store.summary()['candidate_count'], 0)
            with self.assertRaisesRegex(RecoveryBlocked, 'source lease'):
                recover_stopped_candidates(record)
            with run_lease(record.parent), source_lease(fixture.source_root):
                recovered = recover_stopped_candidates(record)
                self.assertEqual(recover_stopped_candidates(record)['status'], 'NOTHING_TO_RECOVER')
            self.assertEqual(recovered['status'], 'RECOVERED')
            ident = recovered['attempts'][0]['candidate_id']
            value = store.snapshot()
            candidate = value['candidates'][ident]
            self.assertEqual(candidate['source_kind'], 'recovered_workspace')
            self.assertEqual(candidate['evidence'], [])
            self.assertIn('+    return max(0, value)', store.load(ident, candidate['identity']))
            self.assertIsNone(store.summary()['latest_replayable_candidate'])
            self.assertIsNone(store.summary()['latest_delivery_eligible_candidate'])
            self.assertEqual(git(fixture.repo, 'status', '--porcelain'), '')

    def test_stopped_write_without_changes_records_attempt_without_candidate(self):
        with GitFixture() as fixture:
            record = self.stopped_writer(fixture, BASELINE)
            with run_lease(record.parent), source_lease(fixture.source_root):
                result = recover_stopped_candidates(record)
            self.assertEqual(result['attempts'][0]['status'], 'NO_NEW_CANDIDATE')
            store = CandidateStore(record.parent / 'candidate-store')
            self.assertEqual(store.summary()['attempt_count'], 1)
            self.assertEqual(store.summary()['candidate_count'], 0)

    def test_two_identical_empty_attempts_stop_without_spending_remaining_candidate_turns(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), edits=[None] * 6)
            ledger = ExecutionBudget(fixture.root / 'accounting', 'input')
            with ledger.active():
                agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case(),
                                          runtime_factory=runtime.factory)
                result = agent.run(mechanical=False)
            self.assertEqual(runtime._write_index, 2)
            self.assertEqual(result['completion_blocked_by'], 'REPEATED_ERROR_NO_PROGRESS')
            self.assertEqual(result['repeated_error']['kind'], 'EMPTY_PATCH')
            self.assertEqual(agent._candidate_store.summary()['candidate_count'], 0)

    def test_different_replayable_bytes_do_not_reset_repeated_error_without_new_facts(self):
        with GitFixture() as fixture:
            ledger = ExecutionBudget(fixture.root / 'accounting', 'input')
            with ledger.active():
                agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case())
                agent.prepare()
                (agent.worktree / 'counter.py').write_text(PARTIAL)
                agent.export_patch(1)
                agent._migration_progress()
                revision = ledger.snapshot()['progress']['revision']
                self.assertFalse(agent._migration_repeated_error('HUNK_LEDGER', {'obligations': ['first']}))
                (agent.worktree / 'counter.py').write_text(FIXED)
                agent.export_patch(2)
                agent._migration_progress()
                self.assertEqual(ledger.snapshot()['progress']['revision'], revision)
                self.assertFalse(agent._migration_repeated_error('HUNK_LEDGER', {'obligations': ['second']}))
                self.assertFalse(agent._migration_repeated_error('HUNK_LEDGER', {'obligations': ['first']}))
                self.assertTrue(agent._migration_repeated_error('HUNK_LEDGER', {'obligations': ['first']}))

    def test_stopped_workspace_audit_failure_preserves_dirty_files_and_blocks(self):
        with GitFixture() as fixture:
            record = self.stopped_writer(fixture)
            store = CandidateStore(record.parent / 'candidate-store')
            attempt = next(iter(store.snapshot()['attempts'].values()))
            worktree = Path(attempt['recovery']['worktree'])
            unexpected = worktree / 'outside-scope.txt'
            unexpected.write_text('must remain for diagnosis')
            with run_lease(record.parent), source_lease(fixture.source_root):
                with self.assertRaisesRegex(RecoveryBlocked, 'outside its allowlist'):
                    recover_stopped_candidates(record)
            self.assertEqual(unexpected.read_text(), 'must remain for diagnosis')
            self.assertEqual((worktree / 'counter.py').read_text(), PARTIAL)
            self.assertEqual(store.summary()['candidate_count'], 0)
            self.assertEqual(store.snapshot()['attempts'][attempt['id']]['status'], 'STARTED')

    def test_timeout_after_mutation_archives_unreviewed_draft_after_runtime_cleanup(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment())
            original_run = runtime.run
            def run(prompt, read_only, output_schema=None):
                if read_only:
                    return original_run(prompt, read_only, output_schema)
                (runtime.worktree / 'counter.py').write_text(PARTIAL)
                raise CodexRuntimeError('timed out', kind='TIMEOUT')
            runtime.run = run
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case(),
                                      runtime_factory=runtime.factory)
            with self.assertRaises(CodexRuntimeError):
                agent.run(mechanical=False)
            self.assertTrue(runtime.closed)
            self.assertEqual(agent.record['candidate_preservation']['status'], 'SAVED')
            self.assertEqual(agent.record['status'], 'FAILED')
            self.assertIsNone(agent.record.get('patch_file'))
            self.assertEqual(agent.record['patch_replay'], 'not_run')
            store = agent._candidate_store
            ident = agent.record['candidate_id']
            self.assertIn('+    return max(0, value)', store.load(ident, agent_identity(agent)))
            self.assertEqual(store.snapshot()['candidates'][ident]['source_kind'], 'recovered_workspace')
            self.assertIsNone(store.summary()['latest_replayable_candidate'])

    def test_unverified_writer_cleanup_blocks_diagnostic_export(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment())
            original_run = runtime.run
            def run(prompt, read_only, output_schema=None):
                if read_only:
                    return original_run(prompt, read_only, output_schema)
                (runtime.worktree / 'counter.py').write_text(PARTIAL)
                raise CodexRuntimeError('writer remains', kind='BACKGROUND_CLEANUP_FAILED')
            runtime.run = run
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case(),
                                      runtime_factory=runtime.factory)
            with self.assertRaises(CodexRuntimeError):
                agent.run(mechanical=False)
            self.assertEqual(agent.record['candidate_preservation']['status'], 'BLOCKED')
            self.assertEqual(agent._candidate_store.summary()['candidate_count'], 0)


if __name__ == '__main__':
    unittest.main()
