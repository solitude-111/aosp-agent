from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent import project_catalog as catalog
from engine_fixtures import GitFixture, git


class ProjectCatalogTest(unittest.TestCase):
    def test_current_checkout_applies_local_add_remove_and_extend_without_project_reads(self):
        from aosp_agent.project_first import checkout_catalog
        import test_runtime_entrypoints as entry
        with GitFixture() as fx:
            manifests = entry.manifest(fx)
            overlays = fx.source_root / '.repo/local_manifests'; overlays.mkdir()
            (overlays / '10-add.xml').write_text('<manifest><remove-project name="platform/unused"/>'
                '<project name="vendor/custom" path="vendor/custom" revision="vendor-branch"/></manifest>')
            (overlays / '20-extend.xml').write_text('<manifest><extend-project name="vendor/custom" '
                'dest-path="vendor/moved" revision="other-branch" base-rev="vendor-branch"/></manifest>')
            with patch.object(catalog, 'local_git', side_effect=AssertionError('metadata needs no project Git')):
                current = checkout_catalog(fx.source_root)
            self.assertEqual(set(current.projects), {'repo', 'vendor/moved'})
            self.assertEqual(current.projects['vendor/moved'].revision, 'HEAD')
            self.assertEqual(current.provenance['local_overrides'], 'APPLIED_IN_FILENAME_ORDER')
            self.assertEqual(len(current.provenance['metadata_sha256']), 3)
            # A release remains solely its pinned versioned manifest.
            versioned = catalog.catalog_at_revision(fx.source_root, 'release-target')
            self.assertEqual(set(versioned.projects), {'repo', 'unused'})

    def test_current_selected_xml_and_includes_are_snapshotted_not_replaced_with_git_head(self):
        from aosp_agent.project_first import checkout_catalog
        import test_runtime_entrypoints as entry
        with GitFixture() as fx:
            manifests = entry.manifest(fx)
            (fx.source_root / '.repo/manifest.xml').write_text('<manifest><include name="custom.xml"/></manifest>')
            (manifests / 'custom.xml').write_text('<manifest><project name="custom" path="repo" revision="custom-tag"/></manifest>')
            current = checkout_catalog(fx.source_root)
            self.assertEqual(set(current.projects), {'repo'})
            self.assertEqual(current.projects['repo'].name, 'custom')
            self.assertEqual(current.projects['repo'].revision, 'HEAD')
            self.assertEqual(set(current.provenance['metadata_sha256']), {'manifest.xml', 'manifests/custom.xml'})

    def test_current_unsupported_or_unreadable_manifest_never_falls_back_to_partial_scan(self):
        from aosp_agent.project_first import checkout_catalog
        import test_runtime_entrypoints as entry
        for xml in ('<manifest><submanifest name="nested"/></manifest>',
                    '<manifest><include name="absent.xml"/></manifest>'):
            with self.subTest(xml=xml), GitFixture() as fx:
                manifests = entry.manifest(fx)
                (manifests / 'default.xml').write_text(xml)
                with patch('aosp_agent.project_first.repository_roots', side_effect=AssertionError('must not silently fall back')):
                    with self.assertRaises((ValueError, OSError)):
                        checkout_catalog(fx.source_root)

    def test_versioned_catalog_reads_no_target_projects_until_selected(self):
        with GitFixture() as fx:
            manifests = fx.root / 'manifests'; manifests.mkdir(); git(manifests, 'init', '-q')
            xml = ('<manifest><remote name="aosp" fetch="https://android.googlesource.com"/>'
                   f'<default remote="aosp" revision="{fx.target}"/>'
                   '<project name="platform/repo" path="repo"/>'
                   + ''.join(f'<project name="platform/unused{i}" path="unused{i}"/>' for i in range(500)) + '</manifest>')
            (manifests / 'default.xml').write_text(xml); git(manifests, 'add', '.'); git(manifests, 'commit', '-qm', 'target manifest')
            git(manifests, 'tag', 'release-target')
            (manifests / 'default.xml').write_text('<manifest><project name="wrong" revision="HEAD"/></manifest>')
            git(manifests, 'commit', '-qam', 'different current manifest')
            original = catalog.local_git
            with patch.object(catalog, 'local_git', wraps=original) as read:
                result = catalog.catalog_at_revision(fx.source_root, 'release-target', manifest_repo=manifests)
                self.assertEqual(len(result.projects), 501)
                self.assertTrue(all(Path(call.args[0]) == manifests for call in read.call_args_list))
                self.assertEqual(result.candidates(['https://android.googlesource.com/platform/repo']), ['repo'])
                self.assertEqual(result.pin('repo')['head'], fx.target)
                count = read.call_count
                result.pin('repo')
                self.assertEqual(read.call_count, count)
            self.assertNotIn('wrong', result.projects)
            with self.assertRaises(subprocess.SubprocessError):
                catalog.catalog_at_revision(fx.source_root, 'nonexistent-release', manifest_repo=manifests)

    def test_include_revisions_nested_paths_and_remote_defaults(self):
        files = {'default.xml': '<manifest><remote name="r" fetch="." revision="remote-tag"/>'
                 '<default remote="r" revision="default-tag"/><project name="base" path="base"/>'
                 '<include name="parts.xml" revision="include-tag"/></manifest>',
                 'parts.xml': '<manifest><project name="parent" path="p"><project name="child" path="c"/>'
                 '</project><project name="explicit" revision="own-tag"/></manifest>'}
        projects = {p.key: p for p in catalog.parse_manifest(files.__getitem__)}
        self.assertEqual(projects['base'].revision, 'remote-tag')
        self.assertEqual(projects['p/c'].name, 'parent/child')
        self.assertEqual(projects['p/c'].revision, 'include-tag')
        self.assertEqual(projects['explicit'].revision, 'own-tag')

    def test_extend_remove_and_revision_guard(self):
        xml = '<manifest><default revision="base"/><project name="old" path="a"/>'
        xml += '<extend-project name="old" dest-path="b" revision="fixed" base-rev="base"/>'
        xml += '<project name="unused"/><remove-project name="unused"/></manifest>'
        projects = catalog.parse_manifest(lambda _: xml)
        self.assertEqual([(p.key, p.revision) for p in projects], [('b', 'fixed')])
        with self.assertRaisesRegex(ValueError, 'base-rev'):
            catalog.parse_manifest(lambda _: xml.replace('base-rev="base"', 'base-rev="wrong"'))

    def test_cycle_path_escape_and_submanifest_fail_explicitly(self):
        for xml in ('<manifest><include name="default.xml"/></manifest>',
                    '<manifest><include name="../outside.xml"/></manifest>',
                    '<manifest><submanifest name="child"/></manifest>',
                    '<manifest><project name="x" path="../outside" revision="HEAD"/></manifest>'):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                catalog.parse_manifest(lambda _: xml)

    def test_selected_project_missing_revision_does_not_fall_back_to_head(self):
        with GitFixture() as fx:
            result = catalog.ProjectCatalog(fx.source_root, [catalog.Project('repo', 'platform/repo', 'missing-tag')], {})
            with self.assertRaises(subprocess.SubprocessError):
                result.pin('repo')
            self.assertEqual(result.pins, {})
