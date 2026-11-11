"""Controller fixtures with real Git and an explicit simulated mount boundary.

These tests do not claim Linux kernel isolation. The provider and LinuxOverlays
tests independently cover their kernel-proof parsers and mount identity checks.
"""
from copy import deepcopy
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from aosp_agent.prepared_source_base import SourceBaseView, verify_active_source_view, _ACTIVE_VIEW, _digest
from aosp_agent.source_base import SourceBaseBlocked


def git(path, *args, input=None):
    result = subprocess.run(['git', '-C', str(path), *args], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


class CopyMountDouble:
    """Copy-based scope simulation; never a replacement for kernel proof."""
    def __init__(self, scratch):
        self.scratch, self.records, self.counter = scratch, {}, 0
        self.extra, self.fail_unmount = set(), False

    def check_namespace(self):
        pass

    def _copy(self, source, target):
        if source.is_dir():
            shutil.copytree(source, target, symlinks=True)
        else:
            shutil.copy2(source, target)

    def _remove(self, target):
        if target.is_dir() and not target.is_symlink():
            shutil.rmtree(target)
        else:
            target.unlink()

    def _mount(self, source, target, *, sync=None, mode='rw'):
        target, source = Path(target), Path(source)
        self.counter += 1
        saved = self.scratch / str(self.counter)
        target.rename(saved)
        if source == target:
            source = saved
        self._copy(source, target)
        record = {'saved': saved, 'sync': sync, 'mount_id': str(self.counter),
                  'target': str(target), 'options': [mode]}
        self.records.setdefault(str(target), []).append(record)

    def bind(self, source, target, *, readonly):
        self._mount(source, target, sync=None if readonly else Path(source), mode='ro' if readonly else 'rw')

    def mount(self, root, layer, *, lower=None):
        root, layer = Path(root), Path(layer)
        upper, work = layer / 'upper', layer / 'work'
        fresh = not upper.exists()
        upper.mkdir(parents=True, exist_ok=True); work.mkdir(exist_ok=True)
        self._mount(Path(lower) if lower is not None else root, root, sync=upper)
        if not fresh:
            self._remove(root)
            self._copy(upper, root)

    def verify(self, target):
        result = self.records[str(target)][-1]
        return {key: result[key] for key in ('mount_id', 'target', 'options')}

    def source_mounts(self, root):
        return {path for path in self.records if Path(path).is_relative_to(root)} | self.extra

    def unmount(self, target):
        if self.fail_unmount:
            raise RuntimeError('simulated busy mount')
        target = Path(target)
        row = self.records[str(target)][-1]
        if row['sync'] is not None:
            self._remove(row['sync'])
            self._copy(target, row['sync'])
        self._remove(target)
        row['saved'].rename(target)
        self.records[str(target)].pop()
        if not self.records[str(target)]:
            del self.records[str(target)]


class Fixture:
    def __init__(self, root):
        self.root, self.base_root, self.source = root, root / 'sealed', root / 'source'
        self.base_root.mkdir(); self.source.mkdir()
        (self.source / 'host-marker').write_text('host untouched')
        self.projects, self.pins, self.rows = {}, {}, {}
        for key in ('alpha', 'beta', 'gamma'):
            repo = self.base_root / key
            repo.mkdir(); git(repo, 'init', '-q')
            git(repo, 'config', 'user.name', 'fixture'); git(repo, 'config', 'user.email', 'fixture@example.invalid')
            (repo / 'file.txt').write_text(key + '\n')
            git(repo, 'add', '.'); git(repo, 'commit', '-qm', 'base')
            pin, tree = git(repo, 'rev-parse', 'HEAD'), git(repo, 'rev-parse', 'HEAD^{tree}')
            row = {'head': pin, 'tree': tree, 'status': '', 'index_check_returncode': 0,
                   'worktree_check_returncode': 0, 'index_flags_verified': True, 'ignored_files': [],
                   'undeclared_ignored_files': [], 'declared_ignored_inputs': {}}
            self.rows[key], self.pins[key] = row, pin
            self.projects[key] = {'commit': pin, 'tree': tree, 'git_dir': key + '/.git',
                                  'common_dir': key + '/.git', 'objects_dir': key + '/.git/objects', 'audit': row}
        self.base = SimpleNamespace(mount_root=self.base_root, projects=self.projects,
            project_pins=self.pins, catalog={'manifest_files': []}, audit={'repositories': self.rows},
            descriptor={'base_id': 'a' * 64, 'receipt_sha256': 'b' * 64, 'project_vector_sha256': _digest(self.pins)},
            revalidate=lambda: {'verified': 'simulated-provider-boundary'})
        scratch = root / 'mount-scratch'; scratch.mkdir()
        self.mounts = CopyMountDouble(scratch)
        self.commands = []
        def command(path, *args):
            self.commands.append((str(path), args))
            return subprocess.run(['git', '-C', str(path), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.manager = SimpleNamespace(config={'source_root': str(self.source), 'build': {
            'enabled': True, 'output_root': str(root / 'out'), 'tmp_root': str(root / 'tmp')}},
            overlays=self.mounts, _git=command, _resources=lambda: None, _save_accounting=lambda *args: None,
            policy={'max_seconds': 600}, seconds_used=0.)
        self.record = {'layer_root': str(root / 'layers'), 'frozen': {'manifest_files': []}}
        self.prepared = SimpleNamespace(manager=self.manager, environment={'project_pins': self.pins}, record=self.record,
            catalog=SimpleNamespace(projects=self.projects), save=lambda: None)


class PreparedSourceBaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name).resolve())

    def tearDown(self):
        _ACTIVE_VIEW.set(None)
        self.temporary.cleanup()

    def test_readonly_credit_and_private_metadata_do_not_modify_base(self):
        f = self.fixture
        view = SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual(f.commands, [])
        self.assertEqual(set(view.verify(f.pins, view.descriptor)['repositories']), set(f.pins))
        view.ensure_writable(['alpha'])
        self.assertEqual(len(f.commands), 3)
        repo = f.source / 'alpha'
        git(repo, 'update-ref', 'refs/heads/private', f.pins['alpha'])
        oid = git(repo, 'hash-object', '-w', '--stdin', input='private-only-new-object\n')
        self.assertFalse((f.base_root / 'alpha/.git/refs/heads/private').exists())
        self.assertFalse((f.base_root / 'alpha/.git/objects' / oid[:2] / oid[2:]).exists())
        self.assertEqual(git(repo, 'show', 'HEAD:file.txt'), 'alpha')
        proof = verify_active_source_view(f.source, f.pins, view.descriptor)
        self.assertEqual(set(proof['repositories']), {'beta', 'gamma'})
        self.assertEqual(proof['writable_repositories'], ['alpha'])
        private = Path(view.metadata['alpha'])
        view.close()
        self.assertTrue((private / 'refs/heads/private').is_file())
        self.assertTrue((private / 'objects' / oid[:2] / oid[2:]).is_file())
        self.assertEqual((f.source / 'host-marker').read_text(), 'host untouched')
        self.assertEqual(f.mounts.records, {})

    def test_resume_reuses_upper_and_private_git_with_only_effective_path_check(self):
        f = self.fixture
        first = SourceBaseView(f.prepared, f.base).activate()
        first.ensure_writable(['alpha'])
        (f.source / 'alpha/file.txt').write_text('pending transaction\n')
        git(f.source / 'alpha', 'update-ref', 'refs/heads/preserved', f.pins['alpha'])
        layer, metadata = first.layer, dict(first.metadata)
        first.close(); f.commands.clear()
        resumed = SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual(resumed.layer, layer)
        self.assertEqual(resumed.metadata, metadata)
        self.assertEqual(len(f.commands), 1)
        self.assertIn('rev-parse', f.commands[0][1])
        self.assertEqual((f.source / 'alpha/file.txt').read_text(), 'pending transaction\n')
        self.assertEqual(git(f.source / 'alpha', 'rev-parse', 'refs/heads/preserved'), f.pins['alpha'])
        self.assertNotIn('alpha', resumed.verify(f.pins, resumed.descriptor)['repositories'])
        resumed.close()

    def test_child_reisolates_parent_writes_and_uses_empty_outputs(self):
        f = self.fixture
        parent = SourceBaseView(f.prepared, f.base).activate()
        parent.ensure_writable(['alpha'])
        (f.source / 'alpha/file.txt').write_text('parent\n')
        (Path(f.manager.config['build']['output_root']) / 'parent-output').write_text('parent')
        child = SourceBaseView(f.prepared, f.base, layer=parent.layer.parent / 'validation-child', parent=parent).activate()
        self.assertEqual(child.writable, {'alpha'})
        self.assertNotEqual(child.metadata['alpha'], parent.metadata['alpha'])
        self.assertFalse((Path(f.manager.config['build']['output_root']) / 'parent-output').exists())
        (f.source / 'alpha/file.txt').write_text('child\n')
        self.assertEqual(child.verify(f.pins, child.descriptor)['writable_repositories'], ['alpha'])
        child.close()
        self.assertEqual((f.source / 'alpha/file.txt').read_text(), 'parent\n')
        self.assertTrue((Path(f.manager.config['build']['output_root']) / 'parent-output').exists())
        parent.verify(f.pins, parent.descriptor)
        parent.close()

    def test_nested_worktree_and_layout_changes_block(self):
        f = self.fixture
        f.projects['alpha']['common_dir'] = 'beta/.git'
        view = SourceBaseView(f.prepared, f.base).activate()
        with self.assertRaisesRegex(SourceBaseBlocked, 'linked-worktree'):
            view.ensure_writable(['alpha'])
        f.projects['alpha']['common_dir'] = 'alpha/.git'
        f.projects['alpha/nested'] = deepcopy(f.projects['alpha'])
        with self.assertRaisesRegex(SourceBaseBlocked, 'nested writable'):
            view.ensure_writable(['alpha'])
        del f.projects['alpha/nested']
        with self.assertRaisesRegex(SourceBaseBlocked, 'layout changed'):
            view.refresh_manifest_files([{'kind': 'copyfile'}])
        view.close()

    def test_unexpected_mount_replaced_top_and_stale_seal_are_rejected(self):
        f = self.fixture
        view = SourceBaseView(f.prepared, f.base).activate()
        f.mounts.extra.add(str(f.source / 'unowned'))
        with self.assertRaisesRegex(SourceBaseBlocked, 'unexpected mount'):
            view.verify(f.pins, view.descriptor)
        f.mounts.extra.clear()
        record = f.mounts.records[str(f.source)][-1]
        original = record['mount_id']; record['mount_id'] = '99999'
        with self.assertRaisesRegex(SourceBaseBlocked, 'top mount'):
            view.verify(f.pins, view.descriptor)
        record['mount_id'] = original
        def stale():
            raise SourceBaseBlocked('seal lost')
        f.base.revalidate = stale
        with self.assertRaisesRegex(SourceBaseBlocked, 'seal lost'):
            view.verify(f.pins, view.descriptor)
        view.close()

    def test_close_failure_preserves_layers_and_marks_restore_blocked(self):
        f = self.fixture
        view = SourceBaseView(f.prepared, f.base).activate()
        view.ensure_writable(['alpha'])
        f.mounts.fail_unmount = True
        with self.assertRaises(SourceBaseBlocked) as caught:
            view.close()
        self.assertEqual(caught.exception.kind, 'ISOLATION_RESTORE_UNVERIFIED')
        self.assertEqual(f.record['source_view_state']['state'], 'RESTORE_BLOCKED')
        self.assertTrue(Path(view.metadata['alpha']).is_dir())
        with self.assertRaises(SourceBaseBlocked):
            view.verify(f.pins, view.descriptor)
        f.mounts.fail_unmount = False
        view.close()

    def test_missing_saved_upper_and_incomplete_metadata_never_start_new_view(self):
        f = self.fixture
        view = SourceBaseView(f.prepared, f.base).activate()
        view.ensure_writable(['alpha']); view.close()
        state = f.record['source_view_state']
        state['metadata']['alpha']['state'] = 'COPYING'
        with self.assertRaisesRegex(SourceBaseBlocked, 'binding changed'):
            SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual(f.mounts.records, {})
        state = f.record['source_view_state']
        state['metadata']['alpha']['state'] = 'READY'
        shutil.rmtree(Path(state['repository_layers']['alpha']) / 'upper')
        with self.assertRaisesRegex(SourceBaseBlocked, 'incomplete'):
            SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual(f.mounts.records, {})

    def test_prechecks_reject_stale_view_before_new_scope_or_manifest_write(self):
        f = self.fixture
        view = SourceBaseView(f.prepared, f.base).activate()
        f.mounts.extra.add(str(f.source / 'foreign'))
        with self.assertRaisesRegex(SourceBaseBlocked, 'unexpected mount'):
            view.ensure_writable(['alpha'])
        with self.assertRaisesRegex(SourceBaseBlocked, 'unexpected mount'):
            view.refresh_manifest_files([])
        self.assertEqual(f.commands, [])
        self.assertEqual(view.state['writable'], [])
        f.mounts.extra.clear(); view.close()

    def test_resume_does_not_replace_changed_git_marker(self):
        f = self.fixture
        view = SourceBaseView(f.prepared, f.base).activate()
        view.ensure_writable(['alpha']); view.close()
        marker = Path(view.state['repository_layers']['alpha']) / 'upper/.git'
        shutil.rmtree(marker); marker.write_text('unexpected retained marker')
        with self.assertRaisesRegex(SourceBaseBlocked, 'mount point changed'):
            SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual(marker.read_text(), 'unexpected retained marker')
        self.assertEqual(f.mounts.records, {})

    def test_worktree_config_override_and_saved_object_symlink_are_rejected(self):
        f = self.fixture
        git(f.base_root / 'alpha', 'config', 'extensions.worktreeConfig', 'true')
        git(f.base_root / 'alpha', 'config', '--worktree', 'core.worktree', str(f.source))
        view = SourceBaseView(f.prepared, f.base).activate()
        with self.assertRaisesRegex(SourceBaseBlocked, 'effective private Git'):
            view.ensure_writable(['alpha'])
        view.close()
        # A separate case with ordinary metadata reaches READY, then an object
        # directory replacement must be refused without touching the link target.
        f.record.pop('source_view_state')
        (f.base_root / 'alpha/.git/config.worktree').unlink()
        git(f.base_root / 'alpha', 'config', '--unset', 'extensions.worktreeConfig')
        view = SourceBaseView(f.prepared, f.base).activate()
        view.ensure_writable(['alpha']); view.close()
        objects = Path(view.metadata['alpha']) / 'objects'
        shutil.rmtree(objects); objects.symlink_to(f.base_root / 'alpha/.git/objects', target_is_directory=True)
        with self.assertRaisesRegex(SourceBaseBlocked, 'symbolic link'):
            SourceBaseView(f.prepared, f.base).activate()
        self.assertTrue(objects.is_symlink())
        self.assertEqual(f.mounts.records, {})

    def test_changed_pin_survives_resume_and_child_inherits_writable_scope(self):
        f = self.fixture
        repo = f.base_root / 'alpha'
        (repo / 'file.txt').write_text('target revision\n')
        git(repo, 'add', '.'); git(repo, 'commit', '-qm', 'another available revision')
        target = git(repo, 'rev-parse', 'HEAD')
        git(repo, 'switch', '--detach', f.pins['alpha'])
        pins = {**f.pins, 'alpha': target}
        f.prepared.environment['project_pins'] = pins
        first = SourceBaseView(f.prepared, f.base).activate()
        with self.assertRaisesRegex(SourceBaseBlocked, 'changed project'):
            first.verify(pins, first.descriptor)
        first.ensure_writable(['alpha'])
        git(f.source / 'alpha', 'switch', '--detach', target)
        first.close(); f.commands.clear()
        resumed = SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual(git(f.source / 'alpha', 'rev-parse', 'HEAD'), target)
        self.assertEqual((f.source / 'alpha/file.txt').read_text(), 'target revision\n')
        self.assertEqual(set(resumed.verify(pins, resumed.descriptor)['repositories']), {'beta', 'gamma'})
        child = SourceBaseView(f.prepared, f.base, pins=pins,
            layer=resumed.layer.parent / 'validation-changed', parent=resumed).activate()
        self.assertEqual(child.writable, {'alpha'})
        self.assertEqual(git(f.source / 'alpha', 'rev-parse', 'HEAD'), target)
        self.assertEqual(set(child.verify(pins, child.descriptor)['repositories']), {'beta', 'gamma'})
        child.close(); resumed.close()

    def test_changed_copyfile_is_separate_readonly_bind_and_survives_resume(self):
        f = self.fixture
        operation = {'kind': 'copyfile', 'project': 'alpha', 'src': 'file.txt', 'dest': 'copied.txt'}
        f.base.catalog['manifest_files'] = [operation]
        f.record['frozen']['manifest_files'] = [operation]
        (f.base_root / 'copied.txt').write_text('alpha\n')
        view = SourceBaseView(f.prepared, f.base).activate()
        view.ensure_writable(['alpha'])
        (f.source / 'alpha/file.txt').write_text('updated projection\n')
        view.refresh_manifest_files([operation])
        self.assertEqual((f.source / 'copied.txt').read_text(), 'updated projection\n')
        self.assertEqual(f.mounts.verify(f.source / 'copied.txt')['options'], ['ro'])
        self.assertEqual((f.base_root / 'copied.txt').read_text(), 'alpha\n')
        view.close()
        resumed = SourceBaseView(f.prepared, f.base).activate()
        self.assertEqual((f.source / 'copied.txt').read_text(), 'updated projection\n')
        resumed.verify(f.pins, resumed.descriptor)
        resumed.close()


if __name__ == '__main__':
    unittest.main()
