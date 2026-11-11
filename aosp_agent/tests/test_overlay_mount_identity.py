"""Mount verification must select the visible kernel mount, never a table row order."""
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from aosp_agent.preparation import LinuxOverlays, PreparationBlocked


class OverlayMountIdentityTest(unittest.TestCase):
    root = Path('/fixture/source with space')
    upper = Path('/fixture/layer/upper')
    work = Path('/fixture/layer/work')

    def entry(self, mount_id='17', **overrides):
        values = {'root': str(self.root), 'upper': str(self.upper), 'work': str(self.work),
                  'lower': str(self.root), 'fstype': 'overlay', 'fsroot': '/', 'mode': 'rw', 'supermode': 'rw'}
        values.update(overrides)
        values = {key: str(value).replace('\\', '\\134').replace(' ', '\\040').replace('\t', '\\011')
                  for key, value in values.items()}
        return (f'{mount_id} 11 0:74 {values["fsroot"]} {values["root"]} {values["mode"]},relatime - '
                f'{values["fstype"]} overlay {values["supermode"]},lowerdir={values["lower"]},'
                f'upperdir={values["upper"]},workdir={values["work"]},userxattr\n')

    def verify(self, table, fdinfo='pos:\t0\nmnt_id:\t17\nflags:\t02300000\n'):
        def read(path, *_args, **_kwargs):
            return io.StringIO(fdinfo if str(path).startswith('/proc/self/fdinfo/') else table)
        with patch('aosp_agent.preparation.os.open', return_value=47), patch('aosp_agent.preparation.os.close') as close, patch.object(Path, 'open', read):
            try:
                LinuxOverlays._verify_mount(self.root, self.upper, self.work)
            finally:
                close.assert_called_once_with(47)

    def test_single_and_stacked_visible_mount_independent_of_row_order(self):
        old = self.entry('900', upper='/fixture/old/upper', work='/fixture/old/work')
        visible = self.entry()
        for table in (visible, old + visible, visible + old):
            with self.subTest(table=table):
                self.verify(table)

    def test_wrong_missing_or_ambiguous_identity_and_backing_layer_rejected(self):
        table = self.entry()
        invalid = [(table, ''), (table, 'mnt_id:\t0\n'), (table, 'mnt_id:\t-17\n'),
            (table, 'mnt_id:\t17\nmnt_id:\tbad\n'), (table, 'mnt_id:\t17\nmnt_id:\t17\n'),
            ('', 'mnt_id:\t17\n'), (table + table, 'mnt_id:\t17\n'),
            (self.entry('900'), 'mnt_id:\t17\n')]
        for field, value in [('upper', '/old/upper'), ('work', '/old/work'), ('lower', '/wrong/source'),
                             ('root', '/wrong/root'), ('fsroot', '/subdir'), ('fstype', 'ext4'),
                             ('mode', 'ro'), ('supermode', 'ro')]:
            invalid.append((self.entry(**{field: value}), 'mnt_id:\t17\n'))
        invalid.extend([(table.replace('upperdir=', 'missing='), 'mnt_id:\t17\n'),
                        (table.rstrip() + ',upperdir=/duplicate\n', 'mnt_id:\t17\n')])
        for content, info in invalid:
            with self.subTest(content=content, info=info):
                with self.assertRaises(PreparationBlocked) as caught:
                    self.verify(content, info)
                self.assertEqual(caught.exception.kind, 'ISOLATION_UNVERIFIED')

    def test_proc_reads_are_bounded_and_escape_decoding_is_single_pass(self):
        with self.assertRaises(PreparationBlocked):
            self.verify(self.entry(), 'mnt_id:\t17\n' + 'x' * 65536)
        with self.assertRaises(PreparationBlocked):
            self.verify(self.entry() + 'x' * (4 * 1024**2))
        # A literal backslash followed by "040" must not become a space after
        # decoding the mountinfo backslash escape once.
        with self.assertRaises(PreparationBlocked):
            self.verify(self.entry(root=str(self.root).replace(' ', '\\040')))

    def test_failed_verification_closes_directory_before_rollback_unmount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'source'; source.mkdir()
            overlays = LinuxOverlays('fixture'); closed = Mock(); calls = []
            def command(argv):
                calls.append(argv)
                if argv[0] == 'umount': closed.assert_called_once_with(47)
                return ''
            def read(_path, *_args, **_kwargs): return io.StringIO('mnt_id:\t17\n')
            with patch.object(overlays, 'check_namespace'), patch.object(overlays, 'command', command), \
                    patch('aosp_agent.preparation.os.open', return_value=47), \
                    patch('aosp_agent.preparation.os.close', closed), patch.object(Path, 'open', read):
                with self.assertRaises(PreparationBlocked): overlays.mount(source, root / 'layer')
            self.assertEqual([args[0] for args in calls], ['mount', 'umount'])
            self.assertEqual(overlays.mounted, [])


if __name__ == '__main__':
    unittest.main()
