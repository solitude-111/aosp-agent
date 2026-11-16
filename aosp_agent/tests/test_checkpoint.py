from pathlib import Path
from hashlib import sha256
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import json
import unittest
from unittest.mock import patch

from aosp_agent.checkpoint import checkpoint_metadata, validate_checkpoint
from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.resume import _accepted_assessment, _accepted_location
from aosp_agent.resume import resume_project


class CheckpointTest(unittest.TestCase):
    def test_current_code_is_accepted_and_old_or_unknown_protocols_are_rejected(self):
        current = checkpoint_metadata()
        validate_checkpoint(current)
        for version in (None, 0, 2, True, '1'):
            with self.subTest(version=version), self.assertRaisesRegex(RecoveryBlocked, 'protocol'):
                validate_checkpoint({**current, 'checkpoint_protocol': version})

    def test_code_change_blocks_without_relabeling_old_record(self):
        record = checkpoint_metadata()
        original = dict(record)
        with patch('aosp_agent.checkpoint.code_identity', return_value='changed-deployment'):
            with self.assertRaisesRegex(RecoveryBlocked, 'code version changed'):
                validate_checkpoint(record)
        self.assertEqual(record, original)
        with self.assertRaisesRegex(RecoveryBlocked, 'code version'):
            validate_checkpoint({'checkpoint_protocol': 1})

    def test_assessment_and_location_reuse_cannot_bypass_compatibility_guard(self):
        for reader in (_accepted_assessment, _accepted_location):
            with self.subTest(reader=reader.__name__), self.assertRaisesRegex(RecoveryBlocked, 'protocol'):
                reader(Path('/nonexistent-prior-run'), {'checkpoint_protocol': 0})

    def test_interrupted_location_retains_last_checked_location_bound_to_pins(self):
        from aosp_agent.project_first import ProjectFirstAgent

        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            first = root / 'rounds/r01/run.json'
            second = root / 'rounds/r02/run.json'
            first.parent.mkdir(parents=True)
            raw = {'primary_repository': 'repo', 'units': []}
            data = json.dumps(raw).encode()
            saved = first.with_name('grounded-location.json')
            saved.write_bytes(data)
            pins = {'repo': 'target-pin'}
            checked = {'status': 'READY', 'targets': pins, 'sha256': sha256(data).hexdigest()}
            record = {**checkpoint_metadata(), 'stage': 'LOCATION', 'impact_analysis': {'status': 'NOT_STARTED'},
                      'input_patch_sha256': 'unchanged patch', 'selected_projects': ['repo'],
                      'pinned_targets': {'repo': {'head': pins['repo']}}}
            row = {'input_patch_sha256': record['input_patch_sha256'], 'location_handoff': checked}
            first.write_text(json.dumps(row))
            agent = SimpleNamespace(record=record)
            ProjectFirstAgent._merge_round_impact(agent, row, first)
            ProjectFirstAgent._merge_round_impact(
                agent, {'location_handoff': {'status': 'INTERRUPTED', 'reason': 'MODEL_TIMEOUT'}}, second)
            self.assertEqual(record['location_handoff']['status'], 'INTERRUPTED')
            self.assertEqual(record['last_grounded_location']['round_record'], str(first))
            self.assertEqual(_accepted_location(root, record)['location'], raw)
            drifted = {**record, 'pinned_targets': {'repo': {'head': 'different-pin'}}}
            self.assertIsNone(_accepted_location(root, drifted))
            saved.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                _accepted_location(root, record)

    def test_resume_version_mismatch_preserves_accounting_and_creates_no_successor(self):
        import test_lifecycle as fixtures
        from engine_fixtures import GitFixture
        for change in ({'checkpoint_protocol': 0}, {'checkpoint_code_sha256': '0' * 64}):
            with self.subTest(change=change), GitFixture() as fixture:
                agent = fixtures.LifecycleTest().cancelled(fixture)
                record_path = agent.run_dir / 'run.json'
                record = json.loads(record_path.read_text())
                accounting = Path(record['execution_budget']['path'])
                original_accounting = accounting.read_bytes()
                record.update(change)
                record_path.write_text(json.dumps(record))
                with self.assertRaisesRegex(RecoveryBlocked, 'checkpoint'):
                    resume_project(record_path)
                self.assertEqual(accounting.read_bytes(), original_accounting)
                self.assertFalse((agent.run_dir / 'resumptions').exists())
                self.assertNotIn('resumed_to', json.loads(record_path.read_text()))


if __name__ == '__main__':
    unittest.main()
