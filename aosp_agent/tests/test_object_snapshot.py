import hashlib
from pathlib import Path
import shutil
import subprocess
import unittest

from aosp_agent.object_snapshot import import_snapshot, SnapshotImportError
from engine_fixtures import GitFixture, git


class ObjectSnapshotTest(unittest.TestCase):
    def bare(self, path):
        path.mkdir()
        git(path, 'init', '--bare', '-q')
        return path

    def fingerprint(self, path):
        return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in path.rglob('*') if p.is_file()}

    def test_independent_snapshot_import_omits_parent_history_and_never_writes_source(self):
        with GitFixture() as fixture:
            destination = self.bare(fixture.root / 'cache.git')
            borrowed = destination / 'objects/info/alternates'
            borrowed.write_text(str(fixture.repo / '.git/objects') + '\n')
            before = self.fingerprint(fixture.repo / '.git')
            receipt = import_snapshot(fixture.repo, destination, [fixture.donor],
                max_bytes=1024 * 1024, timeout=10, min_free_bytes=0)
            self.assertTrue(receipt['independent'])
            self.assertGreater(receipt['packed_bytes'], 0)
            self.assertFalse(borrowed.exists())
            self.assertEqual(self.fingerprint(fixture.repo / '.git'), before)
            expected = git(fixture.repo, 'show', fixture.donor + ':counter.py')
            hidden = fixture.source_root.with_name('hidden-source')
            fixture.source_root.rename(hidden)
            self.assertEqual(git(destination, 'show', fixture.donor + ':counter.py'), expected)
            result = subprocess.run(['git', '-C', str(destination), 'cat-file', '-e', fixture.target],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(result.returncode, 0)  # No full-history clone.

    def test_source_union_is_materialized_and_destination_has_no_borrowed_dependency(self):
        with GitFixture() as fixture:
            source = self.bare(fixture.root / 'metadata.git')
            blobs = self.bare(fixture.root / 'blobs.git')
            destination = self.bare(fixture.root / 'cache.git')
            objects = git(fixture.repo, 'rev-list', '--objects', '--no-object-names', '--no-walk', fixture.donor).splitlines()
            for oid in objects:
                kind = git(fixture.repo, 'cat-file', '-t', oid)
                target = (blobs if kind == 'blob' else source) / 'objects' / oid[:2] / oid[2:]
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(fixture.repo / '.git/objects' / oid[:2] / oid[2:], target)
            original = self.fingerprint(source)
            receipt = import_snapshot(source, destination, [fixture.donor], alternate_objects=[blobs / 'objects'],
                max_bytes=1024 * 1024, timeout=10, min_free_bytes=0)
            self.assertEqual(receipt['object_count'], len(objects))
            self.assertEqual(self.fingerprint(source), original)
            source.rename(source.with_name('hidden-metadata'))
            blobs.rename(blobs.with_name('hidden-blobs'))
            self.assertEqual(git(destination, 'cat-file', '-t', fixture.donor), 'commit')
            self.assertNotIn('?', git(destination, 'rev-list', '--objects', '--no-object-names', '--missing=print', '--no-walk', fixture.donor))

    def test_byte_time_and_disk_limits_fail_without_removing_previous_alternates(self):
        with GitFixture() as fixture:
            for number, overrides in enumerate(({'max_bytes': 100}, {'timeout': 1e-9}, {'min_free_bytes': 2**63})):
                with self.subTest(overrides=overrides):
                    destination = self.bare(fixture.root / ('cache-' + str(number) + '.git'))
                    alternate = destination / 'objects/info/alternates'
                    before = str(fixture.repo / '.git/objects') + '\n'
                    alternate.write_text(before)
                    with self.assertRaises(SnapshotImportError):
                        import_snapshot(fixture.repo, destination, [fixture.donor],
                            **({'max_bytes': 1024 * 1024, 'timeout': 10, 'min_free_bytes': 0} | overrides))
                    self.assertEqual(alternate.read_text(), before)
                    self.assertEqual(list(destination.glob('.snapshot-*')), [])


if __name__ == '__main__':
    unittest.main()
