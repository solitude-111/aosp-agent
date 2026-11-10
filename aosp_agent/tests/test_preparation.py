import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import TestCase, mock

from engine_fixtures import GitFixture, git
from aosp_agent.preparation import (PreparationManager, PreparationBlocked, PreparationError,
                                    LinuxOverlays, digest, project_origin)
from aosp_agent.project_catalog import Project
from aosp_agent.runtime_input import RuntimeInput
from aosp_agent.server_config import validate_config, load_config
from aosp_agent.build_environment import canonical_hash
from aosp_agent.batch_budget import BatchBudget, BatchBudgetExceeded
from aosp_agent.tool_io import ToolIO


class MemoryMounts:
    def __init__(self): self.mounted, self.calls = [], []
    def check_namespace(self): pass
    def mount(self, root, layer):
        Path(layer).mkdir(parents=True, exist_ok=True)
        self.mounted.append(str(root)); self.calls.append((str(root), str(layer)))
    def unmount(self, root): self.mounted.remove(str(root))


def setup(fixture):
    manifest = fixture.source_root / '.repo/manifests'
    manifest.mkdir(parents=True)
    git(manifest, 'init', '-q')
    git(fixture.repo, 'branch', 'target', fixture.target)
    git(fixture.repo, 'remote', 'add', 'aosp', 'https://android.googlesource.com/platform/repo.git')
    (manifest / 'default.xml').write_text('<manifest><remote name="aosp" fetch=".."/>'
        f'<default remote="aosp" revision="{fixture.target}"/><project name="platform/repo" path="repo"/></manifest>')
    git(manifest, 'add', '.'); git(manifest, 'commit', '-q', '-m', 'manifest')
    git(manifest, 'tag', 'release')
    fixture.run_root.mkdir()
    raw = {'source_root': str(fixture.source_root), 'donor_root': str(fixture.root / 'donors'),
        'cache_root': str(fixture.root / 'cache'), 'isolation_root': str(fixture.root / 'isolation'),
        'run_root': str(fixture.run_root), 'donor_map': {'platform/repo': str(fixture.repo)},
        'preparation': {'allow_fetch': False, 'min_free_bytes': 1}}
    row = dict(source_commit_sequence=[fixture.donor], source_parent_sequence=[fixture.target],
               donor_repositories=['platform/repo'], target_revision='release')
    return raw, row


class ConfigurationTest(TestCase):
    def test_only_environment_configuration_and_explicit_precedence(self):
        with GitFixture() as f:
            raw, row = setup(f)
            path = f.root / 'server.json'; path.write_text(json.dumps(raw))
            config = load_config(path, {'model': 'explicit-model', 'max_read_bytes': 1000})
            self.assertEqual(config['agent']['model'], 'explicit-model')
            self.assertEqual(config['agent']['model_provider'], 'deepseek')
            self.assertTrue(config['agent']['locate_first'])
            self.assertEqual(validate_config({**raw, 'agent': {'max_stage_extensions': 0}})['agent']['max_stage_extensions'], 0)
            for extra in ({'files': ['counter.py']}, {'repository_keys': ['repo']}, {'max_rounds': 1.5},
                          {'turn_timeout': float('inf')}, {'max_read_bytes': True}):
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    validate_config({**raw, 'agent': extra})
            with self.assertRaises(ValueError): validate_config({**raw, 'credential_reference': 'secret-value'})
            with self.assertRaises(ValueError): RuntimeInput.parse({**row, 'target_files': ['counter.py']})

    def test_upstream_boundary_and_vector_hash(self):
        with GitFixture() as f:
            raw, _ = setup(f)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            self.assertEqual(project_origin(raw.get('manifest_origin', 'https://android.googlesource.com/platform/manifest'),
                Project('repo', 'platform/repo', f.target, 'aosp', '..')), 'https://android.googlesource.com/platform/repo')
            for url in ('https://android.googlesource.com.evil/repo', 'https://user:secret@android.googlesource.com/repo',
                        'file:///tmp/repo', 'https://android.googlesource.com/a/../repo'):
                with self.subTest(url=url), self.assertRaises((ValueError, PreparationError)): manager._allowed(url)
            self.assertEqual(digest({'repo': f.target}), canonical_hash({'repo': f.target}))


class PreparationTest(TestCase):
    def test_missing_tree_refetch_works_without_new_git_option(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
            manager = PreparationManager(raw, overlays=MemoryMounts())
            origin = 'https://android.googlesource.com/platform/repo'
            store = manager._store(origin, role='target')
            target_object = store / 'objects' / f.donor[:2] / f.donor[2:]
            target_object.parent.mkdir()
            shutil.copyfile(f.repo / '.git/objects' / f.donor[:2] / f.donor[2:], target_object)
            self.assertFalse(manager._complete(store, f.donor))
            original = manager._git
            def fetch_from_fixture(root, *args, **kwargs):
                if args[0] == 'fetch':
                    self.assertNotIn('--refetch', args)
                    self.assertNotEqual(Path(root), store)
                    git(Path(root), 'fetch', '--no-tags', str(f.repo), args[-1])
                    return subprocess.CompletedProcess(args, 0, '', '')
                return original(root, *args, **kwargs)
            with mock.patch.object(manager, '_git', fetch_from_fixture):
                manager._fetch(store, origin, f.donor, refetch=True)
            self.assertTrue(manager._complete(store, f.donor))
            self.assertFalse(list(store.parent.glob('acquire-*')))
            self.assertFalse((store / 'objects/info/alternates').exists())
            self.assertEqual(manager.fetches, 1)

    def test_manifest_files_and_uncontrolled_extra_projects(self):
        from aosp_agent.build_environment import BuildEnvironmentBlocked
        with GitFixture() as f:
            raw, row = setup(f)
            manifest = f.source_root / '.repo/manifests'
            path = manifest / 'default.xml'
            path.write_text(path.read_text().replace('path="repo"/>', 'path="repo">'
                '<copyfile src="counter.py" dest="root-copy.py"/>'
                '<linkfile src="counter.py" dest="root-link.py"/></project>'))
            git(manifest, 'commit', '-qam', 'root files'); git(manifest, 'tag', '-f', 'release')
            manager = PreparationManager(raw, overlays=MemoryMounts())
            manager.freeze_inputs([(1, json.dumps(row))], f.run_root)
            prepared = manager.prepare(RuntimeInput.parse(row), f.run_root / 'row')
            prepared.materialize_all()
            self.assertEqual((f.source_root / 'root-copy.py').read_bytes(), (f.repo / 'counter.py').read_bytes())
            self.assertEqual((f.source_root / 'root-link.py').resolve(), f.repo / 'counter.py')
            (f.source_root / '.repo/project.list').write_text('repo\nextra-project\n')
            with self.assertRaises(BuildEnvironmentBlocked): prepared.materialize_all()
            self.assertEqual(prepared.environment['extra_projects'], ['extra-project'])
            manager.release(prepared)

    def test_donor_and_target_caches_do_not_form_alternate_cycle(self):
        with GitFixture() as f:
            raw, row = setup(f)
            old = f.root / 'old-donor.git'; old.mkdir(); git(old, 'init', '--bare', '-q')
            (old / 'objects/info/alternates').write_text(str(f.repo / '.git/objects') + '\n')
            raw['donor_map']['platform/repo'] = str(old)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            manager.freeze_inputs([(1, json.dumps(row))], f.run_root)
            prepared = manager.prepare(RuntimeInput.parse(row), f.run_root / 'row')
            donor_store = Path(prepared.donor_map['platform/repo'])
            target_store = manager._store('https://android.googlesource.com/platform/repo', role='target')
            self.assertNotEqual(donor_store, target_store)
            self.assertFalse((donor_store / 'objects/info/alternates').exists())
            self.assertFalse((target_store / 'objects/info/alternates').exists())
            (f.repo / '.git/objects/info/alternates').write_text(str(target_store / 'objects') + '\n')
            hidden = f.repo / '.git/objects-hidden'
            (f.repo / '.git/objects').rename(hidden)
            try:
                self.assertTrue(manager._complete(donor_store, f.target))
                self.assertTrue(manager._complete(donor_store, f.donor))
            finally: hidden.rename(f.repo / '.git/objects')
            manager.release(prepared)

    def test_deleted_preparation_budget_cannot_reset_on_resume(self):
        with GitFixture() as f:
            raw, row = setup(f)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            receipt = manager.freeze_inputs([(1, json.dumps(row))], f.run_root)
            (f.run_root / 'preparation-budget.json').unlink()
            with self.assertRaises(PreparationBlocked):
                manager.freeze_inputs([(1, json.dumps(row))], f.run_root, frozen_receipt=receipt)

    def test_freeze_pin_materialize_and_resume_same_layer(self):
        with GitFixture() as f:
            raw, row = setup(f); mounts = MemoryMounts()
            manager = PreparationManager(raw, overlays=mounts)
            lines = [(1, json.dumps(row))]
            frozen = manager.freeze_inputs(lines, f.run_root)
            second = PreparationManager(raw, overlays=mounts)
            second.freeze_inputs(lines, f.run_root, frozen_receipt=frozen)
            prepared = second.prepare(RuntimeInput.parse(row), f.run_root / 'row-0001')
            self.assertEqual(prepared.environment['project_pins'], {'repo': f.target})
            self.assertIn('manifest_commit', prepared.environment['manifest'])
            self.assertEqual(prepared.catalog.pin('repo')['head'], f.target)
            environment = prepared.materialize_all()
            self.assertEqual(environment['materialized_vector_sha256'], canonical_hash({'repo': f.target}))
            first_layer = mounts.calls[-1][1]
            second.release(prepared)
            self.assertFalse(mounts.mounted)
            with second.activate_receipt(prepared.receipt_path) as resumed:
                self.assertEqual(mounts.calls[-1][1], first_layer)
                self.assertEqual(resumed.catalog.pin('repo')['head'], f.target)
            self.assertEqual(json.loads(prepared.receipt_path.read_text())['restoration'], 'PASS')
            self.assertGreater(json.loads((f.run_root / 'preparation-budget.json').read_text())['seconds_used'], 0)

    def test_missing_blob_is_not_a_complete_commit(self):
        with GitFixture() as f:
            raw, _ = setup(f)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            blob = git(f.repo, 'rev-parse', f.target + ':counter.py')
            self.assertTrue(manager._complete(f.repo, f.target))
            (f.repo / '.git/objects' / blob[:2] / blob[2:]).unlink()
            self.assertFalse(manager._complete(f.repo, f.target))
            with self.assertRaises(PreparationError) as caught:
                manager._snapshot(f.repo, f.target, 'https://android.googlesource.com/platform/repo')
            self.assertEqual(caught.exception.kind, 'OBJECTS_UNAVAILABLE')

    def test_symlink_checkout_rejected_before_mutation(self):
        with GitFixture() as f:
            raw, row = setup(f)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            manager.freeze_inputs([(1, json.dumps(row))], f.run_root)
            prepared = manager.prepare(RuntimeInput.parse(row), f.run_root / 'row')
            outside = f.root / 'outside'; outside.mkdir()
            (f.source_root / 'escape').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(PreparationBlocked):
                manager._materialize(Project('escape', 'platform/repo', f.target, fetch='..'))
            self.assertFalse((outside / '.git').exists())
            manager.release(prepared)

    def test_failed_second_mount_unwinds_first(self):
        with GitFixture() as f:
            raw, row = setup(f)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            manager.freeze_inputs([(1, json.dumps(row))], f.run_root)
            first = manager.overlays.mount
            def mount(root, layer):
                if str(root).endswith('missing'): raise PreparationBlocked('TEST', 'failed')
                first(root, layer)
            manager.overlays.mount = mount
            manager._overlay_roots = lambda: [(raw['source_root'], 'source'), (str(f.root / 'missing'), 'missing')]
            with self.assertRaises(PreparationBlocked): manager.prepare(RuntimeInput.parse(row), f.run_root / 'row')
            self.assertFalse(manager.overlays.mounted)
            self.assertIsNone(manager.active)

    def test_mount_verification_failure_unmounts_successful_mount(self):
        with GitFixture() as f:
            overlays = LinuxOverlays('test')
            calls = []
            def command(args):
                calls.append(args)
                return 'ext4' if args[0] == 'findmnt' else ''
            with mock.patch.object(overlays, 'check_namespace'), mock.patch.object(overlays, 'command', command):
                with self.assertRaises(PreparationBlocked): overlays.mount(f.source_root, f.root / 'layer')
            self.assertEqual(calls[-1][0], 'umount')
            self.assertFalse(overlays.mounted)


class TargetAdvertisementTest(TestCase):
    origin = 'https://android.googlesource.com/platform/repo'

    def offline_local_refs(self, manager):
        original = manager._git
        def read(root, *args, **kwargs):
            self.assertFalse(kwargs.get('online', False))
            self.assertNotEqual(args[0], 'ls-remote')
            return original(root, *args, **kwargs)
        return read

    def local_advertisements(self, manager, repo):
        original = manager._git
        def transport(root, *args, **kwargs):
            if args[0] != 'ls-remote': return original(root, *args, **kwargs)
            self.assertTrue(kwargs['online'])
            self.assertEqual(kwargs['max_output'], 65536)
            self.assertLessEqual(kwargs['timeout'], 30)
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            env.update(GIT_ALLOW_PROTOCOL='file', GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1',
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
            return subprocess.run(['git', 'ls-remote', '--exit-code', '--', str(repo), *args[4:]],
                                  env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return transport

    def test_freeze_queries_once_across_manifests_and_resume_never_refreshes(self):
        with GitFixture() as f:
            raw, row = setup(f)
            manifest = f.source_root / '.repo/manifests'; xml = manifest / 'default.xml'
            xml.write_text(xml.read_text().replace(f.target, 'target'))
            git(manifest, 'commit', '-qam', 'mutable ref'); git(manifest, 'tag', '-f', 'release')
            git(manifest, 'tag', 'release-two')
            lines = [(1, json.dumps(row)), (2, json.dumps({**row, 'target_revision': 'release-two'}))]
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.offline_local_refs(manager)), \
                    mock.patch.object(manager, '_fetch', side_effect=AssertionError('freeze fetched target objects')):
                receipt = manager.freeze_inputs(lines, f.run_root)
            self.assertEqual(manager.ref_queries, 1)
            self.assertEqual(manager.local_ref_queries, 1)
            self.assertEqual(manager.remote_ref_queries, 0)
            self.assertEqual(manager.fetches, 0)
            self.assertFalse(list((f.root / 'cache/git').glob('target-*')))
            frozen = json.loads(Path(receipt).read_text())
            self.assertEqual(len(frozen['ref_advertisements']), 1)
            proof = next(iter(frozen['ref_advertisements'].values()))
            self.assertEqual(proof['resolved_oid'], f.target)
            self.assertEqual(proof['object_type'], 'UNVERIFIED')
            self.assertFalse(proof['snapshot_complete'])
            self.assertEqual(proof['advertised_ref'], 'refs/heads/target')
            self.assertEqual(proof['method'], 'git_local_ref_exact')
            self.assertEqual(proof['local_source'], str(f.repo.resolve()))
            self.assertEqual(frozen['revisions']['release']['projects'][0]['revision'], f.target)
            git(f.repo, 'branch', '-f', 'target', f.donor)
            resumed = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(resumed, '_git', side_effect=AssertionError('resume queried a mutable ref')):
                resumed.freeze_inputs(lines, f.run_root, frozen_receipt=receipt)
            self.assertEqual(resumed.ref_queries, 1)
            self.assertEqual(resumed.local_ref_queries, 1)
            self.assertEqual(resumed.remote_ref_queries, 0)
            self.assertEqual(resumed.frozen['release']['projects'][0]['revision'], f.target)
            # A new freeze has no cross-batch mutable-ref cache.
            fresh = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(fresh, '_git', side_effect=self.offline_local_refs(fresh)):
                fresh.freeze_inputs(lines, f.run_root / 'new-batch')
            self.assertEqual(fresh.ref_queries, 1)
            self.assertEqual(fresh.frozen['release']['projects'][0]['revision'], f.donor)

    def test_local_exact_refs_peel_without_remote_or_complete_snapshot_claim(self):
        with GitFixture() as f:
            raw, _ = setup(f)
            git(f.repo, 'tag', 'light', f.target)
            git(f.repo, 'tag', '-a', '-m', 'annotated', 'annotated', f.target)
            git(f.repo, 'tag', '-a', '-m', 'nested', 'nested', 'annotated')
            git(f.repo, 'tag', 'target', f.target)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.offline_local_refs(manager)):
                for ref in ('refs/heads/target', 'refs/tags/target', 'light', 'annotated', 'nested'):
                    with self.subTest(ref=ref):
                        pin, receipt = manager._advertise(self.origin, ref, {}, original=f.repo)
                        self.assertEqual(pin, f.target)
                        proof = manager.ref_advertisements[receipt]
                        self.assertEqual(proof['method'], 'git_local_ref_exact')
                        self.assertEqual(proof['local_source'], str(f.repo.resolve()))
                        self.assertEqual(proof['object_type'], 'UNVERIFIED')
                        self.assertFalse(proof['snapshot_complete'])
                with self.assertRaises(PreparationError) as caught:
                    manager._advertise(self.origin, 'target', {}, original=f.repo)
                self.assertEqual(caught.exception.kind, 'TARGET_REF_AMBIGUOUS')
            self.assertEqual(manager.fetches, 0)
            self.assertEqual(manager.remote_ref_queries, 0)

    def test_missing_local_ref_falls_back_to_remote_advertisement_only(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
            remote = f.root / 'remote.git'
            git(f.root, 'clone', '--bare', '--no-hardlinks', '-q', str(f.repo), str(remote))
            git(f.repo, 'branch', '-D', 'target')
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.local_advertisements(manager, remote)), \
                    mock.patch.object(manager, '_fetch', side_effect=AssertionError('reference lookup fetched objects')):
                pin, receipt = manager._advertise(self.origin, 'target', {}, original=f.repo)
            self.assertEqual(pin, f.target)
            self.assertEqual(manager.ref_advertisements[receipt]['method'], 'git_ls_remote_exact')
            self.assertEqual(manager.remote_ref_queries, 1)
            self.assertEqual(manager.fetches, 0)

    def test_local_source_without_matching_remote_does_not_supply_the_pin(self):
        for kind in ('missing_remote', 'different_origin'):
            with self.subTest(kind=kind), GitFixture() as f:
                raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
                remote = f.root / 'remote.git'
                git(f.root, 'clone', '--bare', '--no-hardlinks', '-q', str(f.repo), str(remote))
                git(remote, 'branch', '-f', 'target', f.donor)
                if kind == 'missing_remote':
                    git(f.repo, 'remote', 'remove', 'aosp')
                else:
                    git(f.repo, 'remote', 'set-url', 'aosp', 'https://android.googlesource.com/platform/other')
                manager = PreparationManager(raw, overlays=MemoryMounts())
                with mock.patch.object(manager, '_git', side_effect=self.local_advertisements(manager, remote)):
                    pin, receipt = manager._advertise(self.origin, 'target', {}, original=f.repo)
                self.assertEqual(pin, f.donor)
                self.assertEqual(manager.ref_advertisements[receipt]['method'], 'git_ls_remote_exact')
                self.assertEqual(manager.remote_ref_queries, 1)
                self.assertEqual(manager.fetches, 0)

    def test_local_source_or_git_metadata_outside_root_is_never_read(self):
        for kind in ('outside_repository', 'outside_gitdir', 'outside_common_config'):
            with self.subTest(kind=kind), GitFixture() as f:
                raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
                outside = f.root / 'outside'
                git(f.root, 'clone', '--no-hardlinks', '-q', str(f.repo), str(outside))
                original = outside
                if kind in ('outside_gitdir', 'outside_common_config'):
                    original = f.source_root / 'linked'; original.mkdir()
                    if kind == 'outside_gitdir':
                        (original / '.git').write_text('gitdir: ' + str(outside / '.git') + '\n')
                    else:
                        metadata = original / '.git'; metadata.mkdir()
                        common = f.source_root / 'common.git'; common.mkdir()
                        (metadata / 'commondir').write_text(str(common) + '\n')
                        (common / 'config').symlink_to(outside / '.git/config')
                manager = PreparationManager(raw, overlays=MemoryMounts())
                transport = self.local_advertisements(manager, f.repo)
                def guarded(root, *args, **kwargs):
                    self.assertNotEqual(Path(root).resolve(), original.resolve())
                    return transport(root, *args, **kwargs)
                with mock.patch.object(manager, '_git', side_effect=guarded), \
                        mock.patch.object(manager, '_fetch', side_effect=AssertionError('lookup fetched objects')):
                    pin, receipt = manager._advertise(self.origin, 'target', {}, original=original)
                self.assertEqual(pin, f.target)
                self.assertEqual(manager.ref_advertisements[receipt]['method'], 'git_ls_remote_exact')
                self.assertEqual(manager.remote_ref_queries, 1)
                self.assertEqual(manager.fetches, 0)

    def test_dangling_local_annotated_tag_remains_unverified_without_lazy_fetch(self):
        with GitFixture() as f:
            raw, _ = setup(f)
            git(f.repo, 'tag', '-a', '-m', 'annotated', 'annotated', f.target)
            git(f.repo, 'config', 'extensions.partialClone', 'origin')
            git(f.repo, 'config', 'remote.origin.promisor', 'true')
            git(f.repo, 'config', 'remote.origin.url', 'https://example.invalid/no-network')
            missing = f.repo / '.git/objects' / f.target[:2] / f.target[2:]
            missing.unlink()
            manager = PreparationManager(raw, overlays=MemoryMounts())
            run = ToolIO.run
            def offline_run(io, command, **kwargs):
                self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'], '')
                self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'], '1')
                self.assertEqual(kwargs['env']['GIT_NO_REPLACE_OBJECTS'], '1')
                return run(io, command, **kwargs)
            with mock.patch.object(manager, '_git', side_effect=self.offline_local_refs(manager)), \
                    mock.patch.object(ToolIO, 'run', offline_run):
                pin, receipt = manager._advertise(self.origin, 'annotated', {}, original=f.repo)
            self.assertEqual(pin, f.target)
            self.assertFalse(missing.exists())
            self.assertEqual(manager.ref_advertisements[receipt]['object_type'], 'UNVERIFIED')
            self.assertFalse(manager.ref_advertisements[receipt]['snapshot_complete'])
            self.assertEqual(manager.remote_ref_queries, 0)
            self.assertEqual(manager.fetches, 0)

    def test_dangling_branch_does_not_hide_local_name_ambiguity(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
            git(f.repo, 'tag', 'target', f.donor)
            missing = f.repo / '.git/objects' / f.target[:2] / f.target[2:]
            missing.unlink()
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.offline_local_refs(manager)):
                with self.assertRaises(PreparationError) as caught:
                    manager._advertise(self.origin, 'target', {}, original=f.repo)
            self.assertEqual(caught.exception.kind, 'TARGET_REF_AMBIGUOUS')
            self.assertFalse(missing.exists())
            self.assertEqual(manager.remote_ref_queries, 0)

    def test_missing_local_tag_object_falls_back_without_importing_objects(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
            git(f.repo, 'tag', '-a', '-m', 'annotated', 'annotated', f.target)
            annotation = git(f.repo, 'rev-parse', 'refs/tags/annotated')
            remote = f.root / 'remote.git'
            git(f.root, 'clone', '--bare', '--no-hardlinks', '-q', str(f.repo), str(remote))
            missing = f.repo / '.git/objects' / annotation[:2] / annotation[2:]
            missing.unlink()
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.local_advertisements(manager, remote)), \
                    mock.patch.object(manager, '_fetch', side_effect=AssertionError('tag lookup fetched objects')):
                pin, receipt = manager._advertise(self.origin, 'annotated', {}, original=f.repo)
            self.assertEqual(pin, f.target)
            self.assertFalse(missing.exists())
            self.assertEqual(manager.ref_advertisements[receipt]['method'], 'git_ls_remote_exact')
            self.assertEqual(manager.fetches, 0)

    def test_real_git_lightweight_annotated_and_ambiguous_refs(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
            git(f.repo, 'tag', 'light', f.target)
            git(f.repo, 'tag', '-a', '-m', 'annotated', 'annotated', f.target)
            git(f.repo, 'tag', 'target', f.target)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.local_advertisements(manager, f.repo)):
                for ref in ('refs/heads/target', 'refs/tags/target', 'light', 'annotated'):
                    pin, _ = manager._advertise(self.origin, ref, {})
                    self.assertEqual(pin, f.target)
                with self.assertRaises(PreparationError) as caught: manager._advertise(self.origin, 'target', {})
                self.assertEqual(caught.exception.kind, 'TARGET_REF_AMBIGUOUS')
            annotated = next(v for v in manager.ref_advertisements.values() if v['requested_revision'] == 'annotated')
            self.assertNotEqual(annotated['advertised_oid'], f.target)
            self.assertEqual(annotated['peeled_oid'], f.target)

    def test_three_manifests_keep_distinct_fixed_pins_with_shared_ref_memo(self):
        with GitFixture() as f:
            raw, row = setup(f); raw['preparation']['allow_fetch'] = True
            manifest = f.source_root / '.repo/manifests'; xml = manifest / 'default.xml'
            revisions = []
            for number, (repo_pin, other_pin) in enumerate(((f.target, 'target'), ('target', f.target), (f.donor, 'target'))):
                xml.write_text('<manifest><remote name="aosp" fetch=".."/><default remote="aosp" revision="target"/>'
                    f'<project name="platform/repo" path="repo" revision="{repo_pin}"/>'
                    f'<project name="platform/other" path="other" revision="{other_pin}"/></manifest>')
                git(manifest, 'commit', '-qam', 'fixed vector ' + str(number))
                revisions.append(git(manifest, 'rev-parse', 'HEAD'))
            lines = [(i + 1, json.dumps({**row, 'target_revision': revision})) for i, revision in enumerate(revisions)]
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.local_advertisements(manager, f.repo)), \
                    mock.patch.object(manager, '_fetch', side_effect=AssertionError('fetched an unselected target')):
                manager.freeze_inputs(lines, f.run_root)
            vectors = [{p['key']: p['revision'] for p in manager.frozen[r]['projects']} for r in revisions]
            self.assertEqual([v['repo'] for v in vectors], [f.target, f.target, f.donor])
            self.assertEqual([v['other'] for v in vectors], [f.target] * 3)
            self.assertEqual(manager.ref_queries, 2)  # Two origins, one common ref; no cross-origin reuse.
            self.assertEqual(manager.fetches, 0)
            self.assertFalse(list((f.root / 'cache/git').glob('target-*')))

    def test_untrusted_advertisements_and_missing_ref_fail_closed(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation']['allow_fetch'] = True
            manager = PreparationManager(raw, overlays=MemoryMounts())
            outputs = [
                (f.target + '\trefs/tags/other\n', 'TARGET_REF_INVALID'),
                (f.target + '\trefs/tags/release^{}\n', 'TARGET_REF_AMBIGUOUS'),
                (f.target + '\trefs/heads/release\n' + f.donor + '\trefs/heads/release\n', 'TARGET_REF_AMBIGUOUS'),
                ('invalid\trefs/heads/release\n', 'TARGET_REF_INVALID')]
            for output, kind in outputs:
                with self.subTest(kind=kind), mock.patch.object(manager, '_git', return_value=subprocess.CompletedProcess([], 0, output, '')):
                    with self.assertRaises(PreparationError) as caught: manager._advertise(self.origin, 'release', {})
                    self.assertEqual(caught.exception.kind, kind)
            with mock.patch.object(manager, '_git', return_value=subprocess.CompletedProcess([], 2, '', '')):
                with self.assertRaises(PreparationError) as caught: manager._advertise(self.origin, 'missing', {})
                self.assertEqual(caught.exception.kind, 'TARGET_REF_UNAVAILABLE')
            with mock.patch.object(manager, '_git', return_value=subprocess.CompletedProcess([], 128, '', 'HTTP 401')):
                with self.assertRaises(PreparationBlocked) as caught: manager._advertise(self.origin, 'release', {})
                self.assertEqual(caught.exception.kind, 'UPSTREAM_CREDENTIALS_UNAVAILABLE')

    def test_offline_invalid_ref_and_origin_never_start_query(self):
        with GitFixture() as f:
            raw, _ = setup(f); manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=AssertionError('network must remain disabled')):
                for ref in ('release', 'HEAD', 'refs/remotes/origin/main', 'release^{}', 'refs/tags/*', 'a/../b'):
                    with self.subTest(ref=ref), self.assertRaises(PreparationError): manager._advertise(self.origin, ref, {})
                with self.assertRaises(PreparationError): manager._advertise('https://example.invalid/repo', 'release', {})
            self.assertEqual(manager.ref_queries, 0)

    def test_query_limit_is_separate_and_survives_accounting_reload(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation'].update(allow_fetch=True, max_ref_queries=1)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            budget = f.run_root / 'preparation-budget.json'; manager._load_accounting(budget)
            memo = {}
            with mock.patch.object(manager, '_git', return_value=subprocess.CompletedProcess([], 2, '', '')):
                with self.assertRaises(PreparationError): manager._advertise(self.origin, 'missing', memo)
            with mock.patch.object(manager, '_git', side_effect=AssertionError('same missing ref queried twice')):
                with self.assertRaises(PreparationError): manager._advertise(self.origin, 'missing', memo)
            resumed = PreparationManager(raw, overlays=MemoryMounts()); resumed._load_accounting(budget, existing=True)
            with mock.patch.object(resumed, '_git', side_effect=AssertionError('exhausted query ran')):
                with self.assertRaises(PreparationBlocked) as caught: resumed._advertise(self.origin, 'release', {})
            self.assertEqual(caught.exception.kind, 'REF_QUERY_LIMIT')
            self.assertEqual(resumed.ref_queries, 1)
            self.assertEqual(resumed.fetches, 0)

    def test_query_output_and_timeout_are_bounded_and_reaped(self):
        with GitFixture() as f:
            raw, _ = setup(f); raw['preparation'].update(allow_fetch=True, fetch_timeout=1)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            fake = f.root / 'fake-git'; fake.write_text('#!' + sys.executable + '\nprint("x" * 70000)\n'); fake.chmod(0o700)
            manager._git_bin = str(fake)
            with self.assertRaises(PreparationError) as caught: manager._advertise(self.origin, 'release', {})
            self.assertEqual(caught.exception.kind, 'TARGET_REF_OUTPUT_LIMIT')
            fake.write_text('#!' + sys.executable + '\nimport time; time.sleep(10)\n')
            with self.assertRaises(PreparationError) as caught: manager._advertise(self.origin, 'release', {})
            self.assertEqual(caught.exception.kind, 'PREPARATION_TIMEOUT')
            self.assertLess(manager.seconds_used, 5)
            self.assertEqual(manager.ref_queries, 2)

    def test_noncommit_advertised_object_is_rejected_before_checkout(self):
        with GitFixture() as f:
            raw, row = setup(f); raw['preparation']['allow_fetch'] = True
            tree = git(f.repo, 'rev-parse', f.target + '^{tree}')
            git(f.repo, 'tag', '-a', '-m', 'tree tag', 'tree-tag', tree)
            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(manager, '_git', side_effect=self.local_advertisements(manager, f.repo)):
                pin, _ = manager._advertise(self.origin, 'tree-tag', {})
            self.assertEqual(pin, tree)
            manager.freeze_inputs([(1, json.dumps(row))], f.run_root)
            manager.frozen['release']['projects'][0]['revision'] = tree
            prepared = manager.prepare(RuntimeInput.parse(row), f.run_root / 'row')
            try:
                with self.assertRaises(PreparationError): prepared.materialize('repo')
                self.assertEqual(git(f.repo, 'rev-parse', 'HEAD'), f.target)
                self.assertEqual(git(f.repo, 'status', '--porcelain=v1'), '')
            finally: manager.release(prepared)


class BatchBudgetTest(TestCase):
    def test_deleted_budget_cannot_reset(self):
        from aosp_agent.lifecycle import RecoveryBlocked
        with GitFixture() as f:
            budget = BatchBudget(f.run_root)
            budget.path.unlink()
            with self.assertRaises(RecoveryBlocked): BatchBudget(f.run_root, existing=True)
    def test_model_output_and_time_limits_survive_resume(self):
        with GitFixture() as f:
            from aosp_agent.output_budget import create_budget, write_bytes
            f.run_root.mkdir(); create_budget(f.run_root, 1024 * 1024)
            resumed_root = f.root / 'resume'; resumed_root.mkdir(); create_budget(resumed_root, 1024 * 1024)
            limits = {'max_model_calls': 2, 'max_seconds': 100, 'max_output_bytes': 50000, 'min_free_bytes': 1}
            budget = BatchBudget(f.run_root, limits=limits, output_root=f.run_root)
            budget.admit_model()
            recovered = BatchBudget(f.run_root, limits=limits, output_root=f.root / 'resume')
            recovered.admit_model()
            with self.assertRaises(BatchBudgetExceeded) as caught: recovered.admit_model()
            self.assertEqual(caught.exception.kind, 'BATCH_MODEL_BUDGET_EXHAUSTED')
            # A large source checkout is not a logged artifact.
            (f.run_root / 'checkout').mkdir(); (f.run_root / 'checkout/source').write_bytes(b'x' * 50001)
            recovered.check()
            write_bytes(f.run_root / 'big.log', b'x' * 50001)
            with self.assertRaises(BatchBudgetExceeded) as caught: recovered.check()
            self.assertEqual(caught.exception.kind, 'BATCH_OUTPUT_BUDGET_EXHAUSTED')
            with mock.patch('aosp_agent.batch_budget.time.time', return_value=budget.snapshot()['started_at'] + 101):
                with self.assertRaises(BatchBudgetExceeded) as caught: recovered.remaining_seconds()
            self.assertEqual(caught.exception.kind, 'BATCH_TIME_BUDGET_EXHAUSTED')
