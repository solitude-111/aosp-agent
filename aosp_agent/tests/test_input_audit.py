import json
import unittest

from aosp_agent.input_audit import audit_row, audit_dataset
from engine_fixtures import GitFixture, git


class InputAuditTest(unittest.TestCase):
    def setup_donor(self, fx):
        root = fx.root / 'donors'
        root.mkdir()
        repo = root / 'repo.git'
        git(fx.root, 'clone', '--bare', '--no-hardlinks', '-q', str(fx.repo), str(repo))
        row = {'cve': 'CVE-0000-123456', 'repository': 'repo',
               'source_commit': fx.donor, 'source_parent': fx.target}
        return root, repo, row

    def test_ready_resolves_only_identity_fields_and_keeps_cve_unverified(self):
        with GitFixture() as fx:
            root, repo, row = self.setup_donor(fx)
            row.update(files=['manual-answer'], validation=['invalid legacy answer'])
            row['source_commit'] = fx.donor[:12]
            result = audit_row(row, root)
            self.assertEqual(result['status'], 'READY')
            self.assertEqual(result['source_commit'], fx.donor)
            self.assertIn('TEMPORARY', result['identity_status'])
            self.assertNotIn('files', result)
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_missing_repo_commit_and_parent_mismatch_are_distinct(self):
        with GitFixture() as fx:
            root, repo, row = self.setup_donor(fx)
            self.assertEqual(audit_row({**row, 'donor_repository': 'absent'}, root)['status'], 'MISSING_DONOR_REPOSITORY')
            missing = audit_row({**row, 'source_parent': 'f' * 40}, root)
            self.assertEqual(missing['status'], 'MISSING_COMMIT_OBJECT')
            self.assertEqual(missing['missing'], ['source_parent'])
            self.assertEqual(audit_row({**row, 'source_parent': fx.donor}, root)['status'], 'PARENT_MISMATCH')

    def test_missing_promisor_blob_is_reported_without_fetch(self):
        with GitFixture() as fx:
            root, repo, row = self.setup_donor(fx)
            blob = git(repo, 'rev-parse', fx.donor + ':counter.py')
            path = repo / 'objects' / blob[:2] / blob[2:]
            path.unlink()
            git(repo, 'config', 'remote.origin.promisor', 'true')
            git(repo, 'config', 'extensions.partialClone', 'origin')
            git(repo, 'config', 'remote.origin.url', fx.repo.as_uri())
            self.assertEqual(audit_row(row, root)['status'], 'DIFF_UNAVAILABLE')
            self.assertFalse(path.exists())

    def test_bad_row_does_not_hide_other_rows_and_duplicates_fail(self):
        with GitFixture() as fx:
            root, repo, row = self.setup_donor(fx)
            data = fx.root / 'rows.json'
            data.write_text(json.dumps([row, {'cve': 'broken'}, row, {'cve': []}]))
            report = audit_dataset(data, root)
            self.assertEqual(report['total_rows'], 4)
            self.assertFalse(report['ready'])
            self.assertEqual(report['status_counts'], {'DUPLICATE_ID': 2, 'INVALID_INPUT': 2})
            self.assertEqual(report['rows'][0]['donor_status'], 'READY')

    def test_symlink_escape_and_non_repository_directory_are_rejected(self):
        with GitFixture() as fx:
            root, repo, row = self.setup_donor(fx)
            (root / 'escape.git').symlink_to(fx.repo, target_is_directory=True)
            self.assertEqual(audit_row({**row, 'donor_repository': 'escape'}, root)['status'], 'INVALID_INPUT')
            (fx.repo / 'nested.git').mkdir()
            self.assertEqual(audit_row({**row, 'donor_repository': 'nested'}, fx.repo)['status'], 'INVALID_DONOR_REPOSITORY')

    def test_empty_or_malformed_dataset_is_not_ready(self):
        with GitFixture() as fx:
            root, repo, row = self.setup_donor(fx)
            data = fx.root / 'rows.json'
            for content in ('[]', '{invalid', '{"cases": null}'):
                data.write_text(content)
                self.assertFalse(audit_dataset(data, root)['ready'])
