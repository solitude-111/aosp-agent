from pathlib import Path
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
