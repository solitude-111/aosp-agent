"""Offline, real-Git fixtures for reusable source-base preparation contracts.

The tests added here exercise controller decisions. A mount/provider double is
never evidence that a kernel-backed immutable snapshot was actually attached.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
from copy import deepcopy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest import TestCase, mock

from aosp_agent.build_environment import BuildEnvironmentBlocked
from aosp_agent.preparation import PreparationManager, PreparationBlocked, digest
from aosp_agent.runtime_input import RuntimeInput
from aosp_agent.source_base import SourceBaseBlocked
from engine_fixtures import GitFixture, git
from test_build_environment import config_for
from test_preparation import MemoryMounts, setup


class ThreeProjectFixture(GitFixture):
    """One protected target, one changeable dependency, one unrelated project."""

    def __init__(self):
        super().__init__()
        self.config, self.row = setup(self)
        self.project_roots = {'repo': self.repo}
        self.pins = {'repo': self.target}
        self.alternate_pins = {'repo': self.donor}
        for key in ('dependency', 'unrelated'):
            root = self.source_root / key
            root.mkdir()
            git(root, 'init', '-q')
            git(root, 'remote', 'add', 'aosp',
                'https://android.googlesource.com/platform/' + key)
            (root / 'tracked.txt').write_text(key + ' initial contents\n')
            (root / '.gitignore').write_text('ignored.bin\n')
            git(root, 'add', '.')
            git(root, 'commit', '-q', '-m', 'initial fixture contents')
            self.pins[key] = git(root, 'rev-parse', 'HEAD')
            (root / 'tracked.txt').write_text(key + ' changed contents\n')
            git(root, 'commit', '-qam', 'alternate fixture contents')
            self.alternate_pins[key] = git(root, 'rev-parse', 'HEAD')
            git(root, 'checkout', '--detach', '-q', self.pins[key])
            self.project_roots[key] = root
        self.manifest_repo = self.source_root / '.repo/manifests'
        self.set_manifest(self.pins)
        # Donor discovery is legitimate preparation work, separate from the
        # target repositories whose scans these tests forbid on reuse.
        donors = self.root / 'donors'
        donors.mkdir()
        donor = donors / 'repo.git'
        git(self.root, 'clone', '--bare', '-q', str(self.repo), str(donor))
        self.config['donor_map'] = {'platform/repo': str(donor)}

    def set_manifest(self, pins, *, copy_source='counter.py'):
        projects = []
        for key, pin in sorted(pins.items()):
            attributes = f'name="platform/{key}" path="{key}" revision="{pin}"'
            if key == 'repo':
                projects.append(f'<project {attributes}>'
                    f'<copyfile src="{copy_source}" dest="root-copy.py"/>'
                    '<linkfile src="counter.py" dest="root-link.py"/>'
                    '</project>')
            else:
                projects.append(f'<project {attributes}/>')
        (self.manifest_repo / 'default.xml').write_text(
            '<manifest><remote name="aosp" fetch=".."/>'
            '<default remote="aosp"/>' + ''.join(projects) + '</manifest>')
        git(self.manifest_repo, 'add', 'default.xml')
        git(self.manifest_repo, 'commit', '-q', '--allow-empty', '-m', 'fixed fixture vector')
        self.manifest_commit = git(self.manifest_repo, 'rev-parse', 'HEAD')
        self.row = {**self.row, 'target_revision': self.manifest_commit}
        return self.manifest_commit


@dataclass(frozen=True)
class GitInvocation:
    argv: tuple[str, ...]
    directory: Path


class GitCallSpy(AbstractContextManager):
    """Observe actual Git launches through every Python subprocess caller.

    This wraps Popen instead of just PreparationManager._git: an accidental
    full scan through discovery/capture_git must also fail a reuse assertion.
    Commands still execute against tiny local repositories; no Git result is
    synthesized. Network commands are rejected before creating their process.
    """

    def __init__(self, *, forbidden_roots=()):
        self.calls = []
        self.forbidden_roots = tuple(Path(root).resolve() for root in forbidden_roots)
        self._patcher = None

    @staticmethod
    def _directory(words, cwd):
        directory = Path(cwd or os.getcwd()).resolve()
        index = 1
        while index < len(words):
            word = words[index]
            if word == '-C' and index + 1 < len(words):
                directory = (directory / words[index + 1]).resolve()
                index += 2
            elif word.startswith('-C') and len(word) > 2:
                directory = (directory / word[2:]).resolve()
                index += 1
            elif word in ('-c', '--git-dir', '--work-tree'):
                index += 2
            elif word.startswith('-'):
                index += 1
            else:
                break
        return directory

    def __enter__(self):
        original = subprocess.Popen

        def observe(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv:
                words = tuple(os.fsdecode(value) for value in argv)
                git_index = next((index for index, word in enumerate(words)
                                  if Path(word).name == 'git'), None)
                if git_index is not None:
                    directory = self._directory(words[git_index:], kwargs.get('cwd'))
                    self.calls.append(GitInvocation(words, directory))
                    if any(word in ('fetch', 'ls-remote', 'push') for word in words):
                        raise AssertionError('source-base fixture attempted network Git: ' + repr(words))
                    if any(directory == root or directory.is_relative_to(root)
                           for root in self.forbidden_roots):
                        raise AssertionError('reused repository unexpectedly ran Git: ' + repr(words))
            return original(argv, *args, **kwargs)

        self._patcher = mock.patch('subprocess.Popen', side_effect=observe)
        self._patcher.start()
        return self

    def __exit__(self, *_args):
        self._patcher.stop()

    def calls_under(self, *roots):
        roots = tuple(Path(root).resolve() for root in roots)
        return [call for call in self.calls
                if any(call.directory == root or call.directory.is_relative_to(root)
                       for root in roots)]

    def touched_projects(self, project_roots):
        return {key for key, root in project_roots.items() if self.calls_under(root)}


class ControllerViewDouble:
    """Only the SourceBaseView protocol, with no filesystem isolation claim.

    The real provider/view tests own readonly mounts, kernel identity, COW,
    restored parent contents and mount/lease failure behavior. This double
    lets these tests observe preparation decisions and execute real Git only
    against disposable fixture checkouts.
    """
    instances = []

    def __init__(self, prepared, base, *, pins=None, layer=None, parent=None):
        self.prepared, self.base, self.parent = prepared, base, parent
        self.pins = dict(pins or prepared.environment['project_pins'])
        self.layer = Path(layer or prepared.record['layer_root'])
        self.writable = set(parent.writable if parent else ())
        self.writable_requests = []
        self.active, self.closed, self.stale = False, False, False
        self.instances.append(self)

    @property
    def descriptor(self):
        return {'version': 1, 'base_id': self.base.base_id,
            'base_receipt_sha256': self.prepared.manager.config['source_base']['receipt_sha256'],
            'base_vector_sha256': digest(self.base.project_pins),
            'project_pins_sha256': digest(self.pins),
            'writable_repositories': sorted(self.writable)}

    def activate(self):
        self.active = True
        self.layer.mkdir(parents=True, exist_ok=True)

    def ensure_writable(self, keys):
        keys = list(keys)
        self.writable_requests.append(keys)
        self.writable.update(keys)

    def refresh_manifest_files(self, operations):
        self.prepared.manager._manifest_files(operations)

    def verify(self, pins, descriptor):
        if self.stale or not self.active or pins != self.pins or descriptor != self.descriptor:
            raise PreparationBlocked('SOURCE_VIEW_INVALID', 'fixture source view proof is stale')
        return {'fixture_only': True}

    def close(self):
        self.active, self.closed = False, True


class SourceBasePreparationTest(TestCase):
    def setUp(self):
        ControllerViewDouble.instances = []
        self.view_patch = mock.patch('aosp_agent.prepared_source_base.SourceBaseView', ControllerViewDouble)
        self.view_patch.start()
        self.addCleanup(self.view_patch.stop)

    def base(self, fx):
        # Actual fixed objects are available, but the kernel seal is explicitly
        # assumed at this consumer boundary, never fabricated as Linux proof.
        return SimpleNamespace(base_id=digest(fx.pins), project_pins=dict(fx.pins),
            projects={key: {'commit': pin} for key, pin in fx.pins.items()},
            revalidate=mock.Mock(), close=mock.Mock())

    def manager(self, fx, base, *, config=None):
        config = deepcopy(config or fx.config)
        config['source_base'] = {'receipt': str(fx.root / 'registration.json'), 'receipt_sha256': 'b' * 64}
        manager = PreparationManager(config, overlays=MemoryMounts())
        patcher = mock.patch.object(manager, '_get_source_base', return_value=base)
        patcher.start()
        self.addCleanup(patcher.stop)
        return manager

    def freeze(self, manager, fx, name):
        run = fx.run_root / name
        manager.freeze_inputs([(1, json.dumps(fx.row))], run)
        self.assertEqual(manager.freeze_errors, {})
        return run

    def test_cross_manager_same_vector_reuses_all_targets_without_git(self):
        with ThreeProjectFixture() as fx:
            base = self.base(fx)
            for name in ('first-case', 'fresh-manager'):
                with self.subTest(case=name):
                    manager = self.manager(fx, base)
                    with GitCallSpy(forbidden_roots=fx.project_roots.values()) as trace, \
                            mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize:
                        run = self.freeze(manager, fx, name)
                        prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
                        prepared.materialize_all()
                        manager.release(prepared)
                    materialize.assert_not_called()
                    self.assertEqual(trace.touched_projects(fx.project_roots), set())
                    self.assertEqual(prepared.record['reused_projects'], sorted(fx.pins))
                    self.assertEqual(prepared.record['materialized'], sorted(fx.pins))
                    self.assertEqual(prepared.record.get('materialized_projects', []), [])
                    self.assertEqual(prepared.environment['materialized_vector_sha256'], digest(fx.pins))
                    self.assertEqual(prepared.record['restoration'], 'PASS')
                    self.assertTrue(prepared.source_view.closed)

    def test_named_manifest_refs_inherit_fixed_base_without_target_git_or_advertisement(self):
        with ThreeProjectFixture() as fx:
            base = self.base(fx)
            reference = 'sealed-fixture-release'
            for key, repo in fx.project_roots.items():
                git(repo, 'tag', reference, fx.pins[key])
                base.projects[key].update(origin='https://android.googlesource.com/platform/' + key,
                    references={reference: fx.pins[key]})
            fx.set_manifest({key: reference for key in fx.pins})
            manager = self.manager(fx, base)
            with GitCallSpy(forbidden_roots=fx.project_roots.values()) as trace, \
                    mock.patch.object(manager, '_advertise', side_effect=AssertionError('sealed ref must not be queried')):
                self.freeze(manager, fx, 'named-base-refs')
            frozen = manager.frozen[fx.manifest_commit]
            self.assertEqual({row['key']: row['revision'] for row in frozen['projects']}, fx.pins)
            self.assertEqual(trace.touched_projects(fx.project_roots), set())
            self.assertEqual(manager.ref_queries, 0)
            references = frozen['provenance']['target_ref_receipts']
            self.assertEqual(set(references), set(fx.pins))
            for key, receipt in references.items():
                proof = manager.ref_advertisements[receipt]
                self.assertEqual(proof['method'], 'immutable_source_base_reference')
                self.assertIs(proof['fresh_remote_advertisement'], False)
                self.assertEqual(proof['requested_revision'], reference)
                self.assertEqual(proof['resolved_oid'], fx.pins[key])
                self.assertEqual(proof['base_id'], base.base_id)

    def test_one_changed_pin_materializes_only_that_real_repository(self):
        with ThreeProjectFixture() as fx:
            base = self.base(fx)
            target = {**fx.pins, 'dependency': fx.alternate_pins['dependency']}
            fx.set_manifest(target)
            manager = self.manager(fx, base)
            run = self.freeze(manager, fx, 'delta')
            untouched = [fx.project_roots[key] for key in ('repo', 'unrelated')]
            with GitCallSpy(forbidden_roots=untouched) as trace, \
                    mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize:
                prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
                prepared.materialize_all()
                prepared.materialize_all()
            self.assertEqual([call.args[0].key for call in materialize.call_args_list], ['dependency'])
            self.assertEqual(trace.touched_projects(fx.project_roots), {'dependency'})
            self.assertEqual(git(fx.project_roots['dependency'], 'rev-parse', 'HEAD'), target['dependency'])
            self.assertEqual(prepared.record['reused_projects'], ['repo', 'unrelated'])
            self.assertEqual(prepared.record['materialized_projects'], ['dependency'])
            self.assertEqual(prepared.source_view.writable_requests, [['dependency']])
            self.assertEqual(prepared.environment['project_pins'], target)
            manager.release(prepared)

    def test_validation_same_vector_has_no_git_and_delta_keeps_parent_protocol(self):
        with ThreeProjectFixture() as fx:
            manager = self.manager(fx, self.base(fx))
            run = self.freeze(manager, fx, 'validation')
            prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
            prepared.ensure_writable(['repo'])
            parent = prepared.source_view
            with GitCallSpy(forbidden_roots=fx.project_roots.values()), \
                    mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize:
                with prepared.validation_view(dict(fx.pins)) as same:
                    child = ControllerViewDouble.instances[-1]
                    self.assertIs(child.parent, parent)
                    self.assertEqual(child.pins, fx.pins)
                    self.assertEqual(child.writable_requests, [[]])
                    self.assertEqual(same['validation_differences'], {})
                    self.assertNotEqual(child.layer, parent.layer)
                    same_layer = child.layer
            materialize.assert_not_called()
            self.assertTrue(child.closed)
            target = {**fx.pins, 'dependency': fx.alternate_pins['dependency']}
            with GitCallSpy(forbidden_roots=[fx.repo, fx.project_roots['unrelated']]) as trace, \
                    mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize:
                with prepared.validation_view(target) as changed:
                    child = ControllerViewDouble.instances[-1]
                    self.assertIs(child.parent, parent)
                    self.assertEqual(child.writable_requests, [['dependency']])
                    self.assertEqual(changed['original_project_pins'], fx.pins)
                    self.assertEqual(changed['project_pins'], target)
                    self.assertEqual(set(changed['validation_differences']), {'dependency'})
                    self.assertNotEqual(child.layer, same_layer)
                    self.assertNotEqual(changed['output_layer'], prepared.environment['output_layer'])
            self.assertEqual([call.args[0].key for call in materialize.call_args_list], ['dependency'])
            self.assertEqual(trace.touched_projects(fx.project_roots), {'dependency'})
            self.assertEqual(prepared.environment['project_pins'], fx.pins)
            self.assertEqual(parent.writable_requests, [['repo']])
            self.assertTrue(parent.active)
            self.assertTrue(child.closed)
            # The double did not isolate or restore bytes: only the controller
            # contract above is asserted. Real view tests own that guarantee.
            manager.release(prepared)

    def test_runner_and_output_changes_preserve_source_reuse_with_new_case_layers(self):
        with ThreeProjectFixture() as fx:
            base, config = self.base(fx), deepcopy(fx.config)
            config['build'] = config_for(fx)
            initial_runner = Path(config['build']['runner'])
            configurations = [deepcopy(config), deepcopy(config)]
            moved = deepcopy(config)
            other_runner = fx.root / 'other-builder.sh'
            other_runner.write_bytes(initial_runner.read_bytes())
            other_runner.chmod(0o755)
            moved['build']['runner'] = str(other_runner)
            configurations.append(moved)
            different_output = deepcopy(moved)
            different_output['build'].update(output_root=str(fx.root / 'out-next'),
                tmp_root=str(fx.root / 'tmp-next'))
            different_output['build']['environment'].pop('HOME', None)
            configurations.append(different_output)
            source_ids, source_layers, output_layers = [], [], []
            for index, current in enumerate(configurations):
                if index == 1:
                    initial_runner.write_text('#!/bin/sh\n# changed implementation\nexit 0\n')
                manager = self.manager(fx, base, config=current)
                with GitCallSpy(forbidden_roots=fx.project_roots.values()), \
                        mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize:
                    run = self.freeze(manager, fx, 'configuration-' + str(index))
                    prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
                    prepared.materialize_all()
                    source_ids.append(prepared.environment['source_view']['base_id'])
                    source_layers.append(prepared.record['layer_root'])
                    output_layers.append(prepared.environment['output_layer'])
                    manager.release(prepared)
                materialize.assert_not_called()
            self.assertEqual(set(source_ids), {base.base_id})
            self.assertEqual(len(set(source_layers)), len(configurations))
            self.assertEqual(len(set(output_layers)), len(configurations))

    def test_invalid_registration_blocks_before_donor_or_legacy_fallback(self):
        with ThreeProjectFixture() as fx:
            config = {**fx.config, 'source_base': {
                'receipt': str(fx.root / 'missing-registration.json'), 'receipt_sha256': 'b' * 64}}
            manager = PreparationManager(config, overlays=MemoryMounts())
            with GitCallSpy() as trace, mock.patch.object(manager, '_store') as store, \
                    mock.patch.object(manager, '_materialize') as materialize:
                with self.assertRaises(SourceBaseBlocked):
                    manager.prepare(RuntimeInput.parse(fx.row), fx.run_root / 'blocked')
            self.assertEqual(trace.calls, [])
            store.assert_not_called()
            materialize.assert_not_called()
            self.assertEqual(manager.overlays.calls, [])
            self.assertIsNone(manager.active)

    def test_stale_source_view_is_not_reported_as_materialized_success(self):
        with ThreeProjectFixture() as fx:
            manager = self.manager(fx, self.base(fx))
            run = self.freeze(manager, fx, 'stale')
            prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
            prepared.source_view.stale = True
            with GitCallSpy(forbidden_roots=fx.project_roots.values()), \
                    mock.patch.object(manager, '_materialize') as materialize:
                with self.assertRaisesRegex(PreparationBlocked, 'source view proof is stale'):
                    prepared.materialize_all()
            materialize.assert_not_called()
            self.assertNotIn('materialized_vector_sha256', prepared.environment)
            saved = json.loads(prepared.receipt_path.read_text())
            self.assertNotIn('materialized_vector_sha256', saved['environment'])
            manager.release(prepared)

    def test_base_layout_mismatch_blocks_without_scanning_unaffected_projects(self):
        with ThreeProjectFixture() as fx:
            base = self.base(fx)
            base.projects.pop('unrelated')
            manager = self.manager(fx, base)
            run = self.freeze(manager, fx, 'wrong-layout')
            prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
            with GitCallSpy(forbidden_roots=fx.project_roots.values()), \
                    mock.patch.object(manager, '_materialize') as materialize:
                with self.assertRaisesRegex(BuildEnvironmentBlocked, 'project layout differs'):
                    prepared.materialize_all()
            materialize.assert_not_called()
            manager.release(prepared)

    def test_legacy_preparation_still_checks_every_project_and_root_manifest_files(self):
        with ThreeProjectFixture() as fx:
            manager = PreparationManager(fx.config, overlays=MemoryMounts())
            run = self.freeze(manager, fx, 'legacy')
            prepared = manager.prepare(RuntimeInput.parse(fx.row), run / 'row')
            with GitCallSpy() as trace, \
                    mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize:
                prepared.materialize_all()
            self.assertEqual({call.args[0].key for call in materialize.call_args_list}, set(fx.pins))
            self.assertEqual(trace.touched_projects(fx.project_roots), set(fx.pins))
            self.assertIsNone(prepared.source_view)
            self.assertEqual((fx.source_root / 'root-copy.py').read_bytes(), (fx.repo / 'counter.py').read_bytes())
            self.assertEqual((fx.source_root / 'root-link.py').resolve(), fx.repo / 'counter.py')
            manager.release(prepared)
