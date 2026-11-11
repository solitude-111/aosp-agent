"""Sealed-provider contract tests. Simulated kernel proof is explicitly labelled.

No mount, fs-verity provisioning, Git checkout, network or AOSP tree is touched.
The independent ioctl/mount tests exercise actual parsing and rejection logic;
temporary catalogue fixtures mock only the unavailable kernel boundary.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aosp_agent import source_base as base


def row(commit='a' * 40, tree='b' * 40):
    return {'head': commit, 'tree': tree, 'status': '', 'index_check_returncode': 0,
            'worktree_check_returncode': 0, 'index_flags_verified': True, 'ignored_files': [],
            'undeclared_ignored_files': [], 'declared_ignored_inputs': {}}


@contextmanager
def simulated_sealed_image():
    """Real files and registration lifecycle; mocked seal is NOT Linux proof."""
    with tempfile.TemporaryDirectory() as temporary, ExitStack() as patches:
        root = Path(temporary).resolve()
        image = root / 'image.squashfs'; image.write_bytes(b'fixture, not an actual filesystem')
        mount = root / 'base'; mount.mkdir()
        loop = root / 'loop'; loop.write_bytes(b'not an actual block device')
        project = {'commit': 'a' * 40, 'tree': 'b' * 40, 'git_dir': 'repo/.git',
                   'common_dir': 'repo/.git', 'objects_dir': 'repo/.git/objects', 'audit': row()}
        catalog = {'version': 1, 'projects': {'repo': project}, 'manifest_files': []}
        data = json.dumps(catalog).encode(); (mount / 'catalog.json').write_bytes(data)
        spec = {'provider': base.PROVIDER, 'image': str(image), 'mount_root': str(mount),
                'verity_digest': 'd' * 64, 'catalog_path': 'catalog.json',
                'catalog_sha256': hashlib.sha256(data).hexdigest()}
        original_open = base._open_path
        def open_path(path, **kwargs):
            return original_open(loop if str(path) == '/dev/loop7' else path, **kwargs)
        patches.enter_context(patch.object(base.sys, 'platform', 'linux'))
        patches.enter_context(patch.object(base, '_open_path', side_effect=open_path))
        patches.enter_context(patch.object(base, '_visible_mount', return_value={'source': '/dev/loop7', 'mount_id': 77}))
        kernel = patches.enter_context(patch.object(base, '_verify_kernel', return_value={'mock_kernel_boundary': True}))
        yield root, spec, catalog, kernel


class SourceBaseTest(unittest.TestCase):
    def test_ioctl_digest_uses_kernel_sha256_and_rejects_wrong_algorithm(self):
        def ioctl(fd, operation, data, mutate):
            self.assertEqual((fd, operation, mutate), (42, 0xC0046686, True))
            self.assertEqual(struct.unpack_from('=HH', data), (0, 32))
            data[:] = struct.pack('=HH', 1, 32) + bytes.fromhex('ab' * 32)
        with patch.object(base.fcntl, 'ioctl', side_effect=ioctl):
            self.assertEqual(base._measure_verity(42), 'ab' * 32)
        with patch.object(base.fcntl, 'ioctl', side_effect=lambda fd, op, data, mutate: data.__setitem__(slice(None), struct.pack('=HH', 2, 32) + bytes(32))):
            with self.assertRaises(base.SourceBaseBlocked): base._measure_verity(42)

    def test_loop_ioctl_layout_is_not_a_path_claim(self):
        values = (2049, 1234, 0, 0, 0, 7, 0, 0, 1, bytes(64), bytes(64), bytes(32), 0, 0)
        def ioctl(fd, operation, data, mutate):
            self.assertEqual(operation, 0x4C05)
            data[:] = struct.pack('=QQQQQIIII64s64s32sQQ', *values)
        with patch.object(base.fcntl, 'ioctl', side_effect=ioctl):
            self.assertEqual(base._loop_info(5)['inode'], 1234)
            self.assertEqual(base._loop_info(5)['flags'], 1)

    def test_visible_mount_uses_fd_id_and_decodes_once(self):
        lines = ('31 1 8:1 / / rw - ext4 /dev/sda rw\n'
                 '77 31 7:7 / /sealed\\040base ro - squashfs /dev/loop7 ro\n'
                 '78 31 7:8 / /other ro - squashfs /dev/loop8 ro\n')
        with patch.object(base, '_proc', side_effect=['pos: 0\nmnt_id:\t77\n', lines]):
            self.assertEqual(base._visible_mount(6)['target'], '/sealed base')
        with patch.object(base, '_proc', return_value='mnt_id:\t77\nmnt_id:\t78\n'):
            with self.assertRaises(base.SourceBaseBlocked): base._visible_mount(6)

    def test_kernel_proof_requires_image_mount_loop_chain_and_real_readonly(self):
        mount = {'mount_id': 77, 'device': '7:7', 'root': '/', 'target': '/sealed',
                 'options': ['ro'], 'super_options': ['ro'], 'filesystem': 'squashfs', 'source': '/dev/loop7'}
        image = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=2049, st_ino=1234, st_size=4096)
        mounted = SimpleNamespace(st_dev=os.makedev(7, 7))
        loop = SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(7, 7))
        info = {'device': 2049, 'inode': 1234, 'rdevice': 0, 'offset': 0, 'sizelimit': 0,
                'encryption': 0, 'key_size': 0, 'flags': 1}
        spec = {'verity_digest': 'd' * 64, 'mount_root': '/sealed'}
        with ExitStack() as stack:
            stack.enter_context(patch.object(base.os, 'fstat', side_effect=lambda fd: {1: image, 2: mounted, 3: loop}[fd]))
            stack.enter_context(patch.object(base.os, 'fstatvfs', return_value=SimpleNamespace(f_flag=os.ST_RDONLY)))
            stack.enter_context(patch.object(base, '_measure_verity', return_value='d' * 64))
            stack.enter_context(patch.object(base, '_visible_mount', side_effect=lambda _: mount))
            stack.enter_context(patch.object(base, '_loop_info', side_effect=lambda _: info))
            stack.enter_context(patch.object(base, '_reject_submounts'))
            self.assertEqual(base._verify_kernel(1, 2, 3, spec)['verity_digest'], 'd' * 64)
            for target, field, changed in ((mount, 'filesystem', 'ext4'), (mount, 'options', ['rw']),
                                           (mount, 'super_options', ['rw']), (mount, 'root', '/subdir'),
                                           (mount, 'target', '/other'), (mount, 'device', '7:8'),
                                           (info, 'inode', 999), (info, 'device', 999), (info, 'flags', 0),
                                           (info, 'offset', 4096), (info, 'sizelimit', 512)):
                with self.subTest(field=field, value=changed):
                    old = target[field]; target[field] = changed
                    try:
                        with self.assertRaises(base.SourceBaseBlocked): base._verify_kernel(1, 2, 3, spec)
                    finally: target[field] = old
            with patch.object(base, '_measure_verity', return_value='e' * 64):
                with self.assertRaises(base.SourceBaseBlocked): base._verify_kernel(1, 2, 3, spec)

    def test_nested_mount_over_sealed_repository_is_not_a_sealed_base(self):
        root = '77 31 7:7 / /sealed\\040base ro - squashfs /dev/loop7 ro\n'
        with patch.object(base, '_proc', return_value=root):
            base._reject_submounts('/sealed base')
        for filesystem, options in (('ext4', 'rw'), ('squashfs', 'ro')):
            with self.subTest(filesystem=filesystem):
                extra = f'78 77 8:1 / /sealed\\040base/repo {options} - {filesystem} /dev/source {options}\n'
                with patch.object(base, '_proc', return_value=root + extra):
                    with self.assertRaises(base.SourceBaseBlocked): base._reject_submounts('/sealed base')

    def test_simulated_registration_requires_first_audit_then_reopens_without_git(self):
        with simulated_sealed_image() as (root, spec, catalog, kernel):
            audit = Mock(return_value={'status': 'PASS', 'repositories': {'repo': row()}})
            binding = base.register_source_base(spec, root / 'registration.json', audit=audit)
            self.assertEqual(audit.call_count, 1)
            with patch('subprocess.Popen', side_effect=AssertionError('no Git or other child on reopen')):
                handle = base.open_source_base(binding)
                try:
                    self.assertEqual(handle.project_pins, {'repo': 'a' * 40})
                    self.assertEqual(handle.audit['repositories'], {'repo': row()})
                    self.assertNotIn('mount', handle.descriptor)
                    self.assertEqual(handle.descriptor['receipt_sha256'], binding['receipt_sha256'])
                    self.assertTrue(handle.revalidate()['mock_kernel_boundary'])
                finally: handle.close()
            self.assertEqual(audit.call_count, 1)
            self.assertGreater(kernel.call_count, 0)
            with self.assertRaises(base.SourceBaseBlocked): handle.revalidate()
            with self.assertRaises(base.SourceBaseBlocked):
                base.register_source_base(spec, root / 'registration.json', audit=audit)
            self.assertEqual(audit.call_count, 1)

    def test_simulated_no_self_declared_audit_or_partial_publication(self):
        with simulated_sealed_image() as (root, spec, catalog, _):
            for outcome in ({'status': 'PASS', 'repositories': {}},
                            {'status': 'PASS', 'repositories': {'repo': {**row(), 'status': ' M file'}}},
                            {'status': 'FAIL', 'repositories': {'repo': row()}}):
                with self.subTest(outcome=outcome):
                    with self.assertRaises(base.SourceBaseBlocked):
                        base.register_source_base(spec, root / 'registration.json', audit=lambda h: outcome)
                    self.assertFalse((root / 'registration.json').exists())
            with self.assertRaises(RuntimeError):
                base.register_source_base(spec, root / 'registration.json', audit=Mock(side_effect=RuntimeError('interrupted audit')))
            self.assertFalse((root / 'registration.json').exists())

    def test_simulated_tamper_capability_loss_and_fd_cleanup_fail_closed(self):
        with simulated_sealed_image() as (root, spec, catalog, kernel):
            binding = base.register_source_base(spec, root / 'registration.json', audit=lambda h: {'status': 'PASS', 'repositories': {'repo': row()}})
            original = (root / 'registration.json').read_bytes()
            (root / 'registration.json').write_bytes(original + b' ')
            with self.assertRaises(base.SourceBaseBlocked): base.open_source_base(binding)
            (root / 'registration.json').write_bytes(original)
            with patch.object(base, '_verify_kernel', side_effect=OSError('fs-verity unsupported')):
                with self.assertRaises(base.SourceBaseBlocked) as caught: base.open_source_base(binding)
                self.assertEqual(caught.exception.kind, 'SOURCE_BASE_UNAVAILABLE')
            handle = base.open_source_base(binding)
            descriptors = list(handle._fds)
            image = Path(spec['image']); image.rename(root / 'old-image'); image.write_bytes(b'replacement')
            with self.assertRaises(base.SourceBaseBlocked): handle.revalidate()
            handle.close()
            for fd in descriptors:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_paths_and_frozen_reference_audit_are_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); (root / 'real').mkdir(); (root / 'real/file').write_text('{}')
            (root / 'alias').symlink_to(root / 'real', target_is_directory=True)
            with self.assertRaises(OSError): base._read_path(root / 'alias/file')
        catalog = {'version': 1, 'projects': {'repo': {'commit': 'a' * 40, 'tree': 'b' * 40,
            'git_dir': 'repo/.git', 'common_dir': 'repo/.git', 'objects_dir': 'repo/.git/objects',
            'audit': row(), 'origin': 'https://android.googlesource.com/platform/repo',
            'references': {'refs/tags/example': 'a' * 40}}}, 'manifest_files': [],
            'manifest_provenance': {'manifest_commit': 'c' * 40}}
        projects = base._validate_catalog(catalog)
        audit = {'status': 'PASS', 'repositories': {'repo': row()}}
        with self.assertRaises(base.SourceBaseBlocked): base._validate_audit(audit, projects, catalog)
        audit.update(project_references={'repo': {key: projects['repo'][key] for key in ('references', 'origin')}},
                     manifest_provenance=catalog['manifest_provenance'])
        base._validate_audit(audit, projects, catalog)
        for value in (None, False, 1):
            unverified = deepcopy(catalog)
            if value is None:
                unverified['projects']['repo']['audit'].pop('index_flags_verified')
            else:
                unverified['projects']['repo']['audit']['index_flags_verified'] = value
            old_audit = {**audit, 'repositories': {'repo': unverified['projects']['repo']['audit']}}
            with self.subTest(index_flags_verified=value), self.assertRaises(base.SourceBaseBlocked):
                base._validate_audit(old_audit, unverified['projects'], unverified)
        bad = deepcopy(catalog); bad['projects']['repo']['git_dir'] = '../shared'
        with self.assertRaises(base.SourceBaseBlocked): base._validate_catalog(bad)


if __name__ == '__main__':
    unittest.main()
