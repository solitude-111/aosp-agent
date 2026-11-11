"""Real tiny Git closure audits; no AOSP, provider, mount or image operations."""
from contextlib import redirect_stdout
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aosp_agent.source_base_cli import (GitAudit, audit_registered_base,
                                      create_catalog, main)
from aosp_agent.source_base import SourceBaseBlocked
from engine_fixtures import GitFixture, git


class SourceBaseCliTest(unittest.TestCase):
    def declarations(self, fx):
        path = fx.root / 'projects.json'
        path.write_text(json.dumps({'projects': [{'key': 'repo', 'revision': 'HEAD',
            'origin': 'https://example.test/platform/repo'}], 'manifest_files': []}))
        return path

    def repo_checkout(self, fx):
        root = fx.source_root
        manifests = root / '.repo/manifests'; manifests.mkdir(parents=True)
        git(fx.repo, 'branch', 'manifest-revision', fx.donor)
        (manifests / 'default.xml').write_text('''<manifest>
<remote name="origin" fetch="https://example.test/" />
<default remote="origin" revision="refs/heads/manifest-revision" />
<project name="platform/repo" path="repo"><copyfile src="counter.py" dest="root-copy" /></project>
</manifest>''')
        git(manifests, 'init', '-q')
        git(manifests, 'add', 'default.xml')
        git(manifests, 'commit', '-qm', 'fixed effective manifest')
        (root / '.repo/manifest.xml').symlink_to('manifests/default.xml')
        (root / 'root-copy').write_bytes((fx.repo / 'counter.py').read_bytes())
        metadata = root / '.repo/projects/repo.git'; metadata.parent.mkdir(parents=True)
        (fx.repo / '.git').rename(metadata)
        (fx.repo / '.git').symlink_to('../.repo/projects/repo.git', target_is_directory=True)
        storage = root / '.repo/project-objects/platform/repo.git/objects'
        storage.parent.mkdir(parents=True)
        (metadata / 'objects').rename(storage)
        (metadata / 'objects').symlink_to(os.path.relpath(storage, metadata), target_is_directory=True)
        return metadata, storage

    def test_aosp_metadata_and_manifest_refs_survive_relocation_without_checkout(self):
        with GitFixture() as fx:
            _, storage = self.repo_checkout(fx)
            catalog = create_catalog(fx.source_root, manifest_origin='https://example.test/platform/manifest')
            row = catalog['projects']['repo']
            self.assertEqual(row['commit'], fx.target)
            self.assertEqual(row['references'], {'refs/heads/manifest-revision': fx.donor})
            self.assertEqual(row['objects_dir'], storage.relative_to(fx.source_root).as_posix())
            self.assertEqual(row['git_dir'], '.repo/projects/repo.git')
            self.assertEqual(row['origin'], 'https://example.test/platform/repo')
            self.assertEqual(git(fx.repo, 'rev-parse', 'HEAD'), fx.target)
            relocated = fx.root / 'relocated'
            shutil.copytree(fx.source_root, relocated, symlinks=True)
            result = audit_registered_base(SimpleNamespace(mount_root=relocated, catalog=catalog))
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['repositories']['repo'], row['audit'])
            self.assertEqual(result['project_references']['repo']['references'], row['references'])

    def test_relative_in_image_alternates_are_accepted_and_external_alternates_rejected(self):
        with GitFixture() as fx:
            declarations = self.declarations(fx)
            objects = fx.repo / '.git/objects'
            shared = fx.source_root / '.objects/shared'; shared.parent.mkdir()
            shutil.copytree(objects, shared)
            alternate = objects / 'info/alternates'
            alternate.write_text(os.path.relpath(shared, objects) + '\n')
            catalog = create_catalog(fx.source_root, project_catalog=declarations)
            self.assertEqual(catalog['projects']['repo']['commit'], fx.target)
            outside = fx.root / 'outside-objects'; shutil.copytree(shared, outside)
            alternate.write_text(os.path.relpath(outside, objects) + '\n')
            with self.assertRaisesRegex(SourceBaseBlocked, 'escapes'):
                create_catalog(fx.source_root, project_catalog=declarations)
            alternate.write_text(str(shared) + '\n')
            with self.assertRaisesRegex(SourceBaseBlocked, 'relocatable'):
                create_catalog(fx.source_root, project_catalog=declarations)

    def test_missing_snapshot_blob_dirty_and_ignored_files_block(self):
        for mutation in ('missing', 'staged', 'ignored'):
            with self.subTest(mutation=mutation), GitFixture() as fx:
                declarations = self.declarations(fx)
                if mutation == 'missing':
                    oid = git(fx.repo, 'rev-parse', 'HEAD:counter.py')
                    (fx.repo / '.git/objects' / oid[:2] / oid[2:]).unlink()
                elif mutation == 'staged':
                    (fx.repo / 'counter.py').write_text('unexpected')
                    git(fx.repo, 'add', 'counter.py')
                else:
                    (fx.repo / '.git/info/exclude').write_text('extra.bin\n')
                    (fx.repo / 'extra.bin').write_text('unexpected')
                with self.assertRaises(SourceBaseBlocked):
                    create_catalog(fx.source_root, project_catalog=declarations)

    def test_config_includes_and_external_config_sources_block_creation_and_registration(self):
        for mutation in ('include', 'includeIf', 'external_config'):
            with self.subTest(mutation=mutation), GitFixture() as fx:
                declarations = self.declarations(fx)
                catalog = create_catalog(fx.source_root, project_catalog=declarations)
                outside = fx.root / 'outside-config'
                outside.write_text('[fixture]\n marker = external\n')
                if mutation == 'external_config':
                    config = fx.repo / '.git/config'
                    outside.write_bytes(config.read_bytes())
                    config.unlink(); config.symlink_to(os.path.relpath(outside, config.parent))
                else:
                    key = 'include.path' if mutation == 'include' else 'includeIf.gitdir:/**.path'
                    git(fx.repo, 'config', key, str(outside))
                with self.assertRaises(SourceBaseBlocked):
                    create_catalog(fx.source_root, project_catalog=declarations)
                with self.assertRaises(SourceBaseBlocked):
                    audit_registered_base(SimpleNamespace(mount_root=fx.source_root, catalog=catalog))

    def test_index_flags_cannot_hide_dirty_source_during_cold_registration(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag), GitFixture() as fx:
                declarations = self.declarations(fx)
                catalog = create_catalog(fx.source_root, project_catalog=declarations)
                self.assertTrue(catalog['projects']['repo']['audit']['index_flags_verified'])
                git(fx.repo, 'update-index', flag, 'counter.py')
                (fx.repo / 'counter.py').write_text('unverified hidden source bytes\n')
                self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
                with self.assertRaisesRegex(SourceBaseBlocked, 'assume-unchanged/skip-worktree'):
                    create_catalog(fx.source_root, project_catalog=declarations)
                with self.assertRaisesRegex(SourceBaseBlocked, 'assume-unchanged/skip-worktree'):
                    audit_registered_base(SimpleNamespace(mount_root=fx.source_root, catalog=catalog))

    def test_registration_rechecks_manifest_reference_and_projection(self):
        for mutation in ('reference', 'projection', 'absolute_manifest_git'):
            with self.subTest(mutation=mutation), GitFixture() as fx:
                self.repo_checkout(fx)
                catalog = create_catalog(fx.source_root, manifest_origin='https://example.test/platform/manifest')
                if mutation == 'reference':
                    git(fx.repo, 'update-ref', 'refs/heads/manifest-revision', fx.target)
                elif mutation == 'projection':
                    (fx.source_root / 'root-copy').write_text('changed manifest copy')
                else:
                    directory = fx.source_root / '.repo/manifests'
                    moved = fx.source_root / '.repo/manifests.git'
                    (directory / '.git').rename(moved)
                    (directory / '.git').write_text('gitdir: ' + str(moved) + '\n')
                with self.assertRaisesRegex(SourceBaseBlocked,
                        'gitdir pointer must be relative' if mutation == 'absolute_manifest_git' else '.'):
                    audit_registered_base(SimpleNamespace(mount_root=fx.source_root, catalog=catalog))

    def test_project_inventory_is_exact_and_rechecked_during_registration(self):
        with GitFixture() as fx:
            self.repo_checkout(fx)
            inventory = fx.source_root / '.repo/project.list'
            inventory.write_bytes(b'repo\n')
            catalog = create_catalog(fx.source_root, manifest_origin='https://example.test/platform/manifest')
            self.assertEqual(catalog['manifest_provenance']['project_list_sha256'],
                             hashlib.sha256(b'repo\n').hexdigest())
            inventory.write_bytes(b'repo\nleftover-checkout\n')
            with self.assertRaisesRegex(SourceBaseBlocked, 'project inventory differs'):
                audit_registered_base(SimpleNamespace(mount_root=fx.source_root, catalog=catalog))
            with self.assertRaisesRegex(SourceBaseBlocked, 'project inventory differs'):
                create_catalog(fx.source_root, manifest_origin='https://example.test/platform/manifest')

    def test_output_exclusion_and_exclusive_creation_and_help_have_no_actions(self):
        with GitFixture() as fx:
            declarations = self.declarations(fx); output = fx.root / 'catalog.json'
            args = ['create-catalog', '--source-root', str(fx.source_root),
                    '--project-catalog', str(declarations), '--output', str(output)]
            with redirect_stdout(StringIO()): self.assertEqual(main(args), 0)
            original = output.read_bytes()
            with patch('aosp_agent.source_base_cli.create_catalog', side_effect=AssertionError('must refuse first')):
                with self.assertRaises(SourceBaseBlocked): main(args)
                with self.assertRaises(SourceBaseBlocked): main(args[:-1] + [str(fx.source_root / 'bad.json')])
            self.assertEqual(output.read_bytes(), original)
            for argv in (['--help'], ['create-catalog', '--help'], ['register', '--help']):
                with redirect_stdout(StringIO()), patch('aosp_agent.source_base_cli.GitAudit', side_effect=AssertionError('help is inert')):
                    with self.assertRaises(SystemExit) as ended: main(argv)
                    self.assertEqual(ended.exception.code, 0)

    def test_git_output_and_operation_budgets_are_enforced(self):
        with GitFixture() as fx:
            with self.assertRaisesRegex(SourceBaseBlocked, 'output limit'):
                GitAudit(max_output_bytes=1).run(fx.repo, 'rev-parse', 'HEAD')
            audit = GitAudit(max_operations=1)
            audit.run(fx.repo, 'rev-parse', 'HEAD')
            with self.assertRaisesRegex(SourceBaseBlocked, 'operation limit'):
                audit.run(fx.repo, 'rev-parse', 'HEAD')
            with self.assertRaises(SourceBaseBlocked): GitAudit(timeout=float('inf'))


if __name__ == '__main__':
    unittest.main()
