"""Legacy delta decisions with real tiny Git and simulated overlay mounts.

The copying double proves controller paths and restoration expectations, not
Linux mount behavior. No source-base provider or shared checkout is involved.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import shutil
from unittest import TestCase, mock

from aosp_agent.preparation import PreparationManager, PreparationBlocked
from aosp_agent.failure_policy import classify_failure
from aosp_agent.runtime_input import RuntimeInput
from engine_fixtures import GitFixture, git
from test_build_environment import config_for
from test_preparation import setup


class CopyOverlays:
    def __init__(self, scratch):
        self.scratch = scratch
        scratch.mkdir()
        self.mount_records, self.mounted, self.calls = {}, [], []
        self.counter = 0
        self.bad_identity = self.fail_unmount = False

    def check_namespace(self):
        pass

    def mount(self, root, layer, *, lower=None):
        root, layer = Path(root).resolve(), Path(layer).resolve()
        lower = Path(lower).resolve() if lower is not None else root
        upper, work = layer / 'upper', layer / 'work'
        upper.mkdir(parents=True); work.mkdir()
        self.counter += 1
        saved = self.scratch / str(self.counter)
        root.rename(saved)
        shutil.copytree(saved if lower == root else lower, root, symlinks=True)
        row = {'kind': 'overlay', 'root': root, 'upper': upper, 'work': work,
               'lower': lower, 'mount_id': str(self.counter), 'saved': saved}
        self.mount_records.setdefault(str(root), []).append(row)
        self.mounted.append(root)
        self.calls.append((root, layer, lower))

    def verify(self, root):
        if self.bad_identity:
            raise PreparationBlocked('ISOLATION_UNVERIFIED', 'simulated visible mount replacement')
        root = Path(root).resolve()
        row = self.mount_records[str(root)][-1]
        return {'mount_id': row['mount_id'], 'target': str(root)}

    def unmount(self, root):
        if self.fail_unmount:
            raise OSError('simulated busy derived mount')
        root = Path(root).resolve()
        row = self.mount_records[str(root)][-1]
        shutil.rmtree(row['upper'])
        shutil.copytree(root, row['upper'], symlinks=True)
        shutil.rmtree(root)
        row['saved'].rename(root)
        self.mount_records[str(root)].pop()
        if not self.mount_records[str(root)]:
            del self.mount_records[str(root)]
        index = len(self.mounted) - 1 - self.mounted[::-1].index(root)
        self.mounted.pop(index)


@contextmanager
def prepared_fixture(*, complete=True):
    with GitFixture() as fx:
        config, row = setup(fx)
        pins, repositories = {'repo': fx.target}, {'repo': fx.repo}
        for key in ('dependency', 'unrelated'):
            repo = fx.source_root / key
            repo.mkdir(); git(repo, 'init', '-q')
            (repo / 'tracked.txt').write_text(key + '\n')
            git(repo, 'add', '.'); git(repo, 'commit', '-qm', 'original')
            pins[key] = git(repo, 'rev-parse', 'HEAD')
            repositories[key] = repo
        dependency = repositories['dependency']
        (dependency / 'tracked.txt').write_text('new dependency\n')
        git(dependency, 'commit', '-qam', 'alternate')
        alternate = git(dependency, 'rev-parse', 'HEAD')
        git(dependency, 'checkout', '-q', '--detach', pins['dependency'])
        manifests = fx.source_root / '.repo/manifests'
        (manifests / 'default.xml').write_text('<manifest><remote name="aosp" fetch=".."/>'
            '<default remote="aosp"/>' + ''.join(
                f'<project name="platform/{key}" path="{key}" revision="{pin}"/>'
                for key, pin in sorted(pins.items())) + '</manifest>')
        git(manifests, 'commit', '-qam', 'three fixed projects')
        row['target_revision'] = git(manifests, 'rev-parse', 'HEAD')
        config['build'] = config_for(fx)
        overlays = CopyOverlays(fx.root / 'simulated-mounts')
        manager = PreparationManager(config, overlays=overlays)
        manager.freeze_inputs([(1, json.dumps(row))], fx.run_root)
        prepared = manager.prepare(RuntimeInput.parse(row), fx.run_root / 'row')
        try:
            if complete:
                prepared.materialize_all()
            yield fx, manager, prepared, pins, alternate, repositories
        finally:
            overlays.fail_unmount = False
            # Preserve normal parent ownership while unwinding any deliberately
            # failed or injected child fixture; never perform host mounts.
            roots = [(Path(root).resolve(), name) for root, name in manager._overlay_roots()]
            for root, _ in reversed(roots):
                while len(overlays.mount_records.get(str(root), [])) > 1:
                    overlays.unmount(root)
            manager.active = prepared
            if overlays.mounted:
                manager.release(prepared)


class LegacyPreparationDeltaTest(TestCase):
    def test_changed_pin_only_materializes_that_repository_and_restores_parent(self):
        with prepared_fixture() as (fx, manager, prepared, pins, alternate, repositories):
            selected = {**pins, 'dependency': alternate}
            with mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize, \
                    mock.patch.object(manager, '_git', wraps=manager._git) as commands:
                with prepared.validation_view(selected) as environment:
                    self.assertEqual(environment['reused_projects'], ['repo', 'unrelated'])
                    self.assertEqual(environment['materialized_projects'], ['dependency'])
                    self.assertEqual(environment['original_project_pins'], pins)
                    self.assertEqual(environment['project_pins'], selected)
                    self.assertEqual(environment['preparation_scope'], 'active_parent_delta')
                    self.assertEqual(git(repositories['dependency'], 'rev-parse', 'HEAD'), alternate)
                    saved = json.loads((Path(environment['source_layer']).parent / 'environment.json').read_text())
                    self.assertEqual(saved['materialized_projects'], ['dependency'])
            self.assertEqual([call.args[0].key for call in materialize.call_args_list], ['dependency'])
            touched = {Path(call.args[0]).resolve() for call in commands.call_args_list}
            self.assertEqual(touched, {repositories['dependency']})
            self.assertEqual(git(repositories['dependency'], 'rev-parse', 'HEAD'), pins['dependency'])
            self.assertEqual(prepared.environment['project_pins'], pins)
            self.assertEqual(prepared.materialized, set(pins))

    def test_identical_vector_has_zero_git_and_fresh_source_output_and_tmp_layers(self):
        with prepared_fixture() as (fx, manager, prepared, pins, _, repositories):
            output, temporary = Path(manager.config['build']['output_root']), Path(manager.config['build']['tmp_root'])
            (output / 'parent-output').write_text('parent artifact')
            (temporary / 'parent-tmp').write_text('parent temporary')
            layers = []
            with mock.patch.object(manager, '_materialize', wraps=manager._materialize) as materialize, \
                    mock.patch.object(manager, '_git', wraps=manager._git) as commands:
                for _attempt in range(2):
                    with prepared.validation_view(dict(pins)) as environment:
                        layer = Path(environment['source_layer']).parent
                        layers.append(layer)
                        self.assertEqual(environment['output_layer'], str(layer / 'output_root'))
                        self.assertNotEqual(environment['output_layer'], prepared.environment['output_layer'])
                        self.assertEqual(environment['reused_projects'], sorted(pins))
                        self.assertEqual(environment['materialized_projects'], [])
                        self.assertFalse((repositories['unrelated'] / 'prior-derived-marker').exists())
                        self.assertEqual(list(output.iterdir()), [])
                        self.assertEqual(list(temporary.iterdir()), [])
                        (repositories['unrelated'] / 'prior-derived-marker').write_text('only in child')
                        (output / 'child-output').write_text('child')
                        (temporary / 'child-tmp').write_text('child')
                    self.assertFalse((repositories['unrelated'] / 'prior-derived-marker').exists())
                    self.assertEqual([p.name for p in output.iterdir()], ['parent-output'])
                    self.assertEqual([p.name for p in temporary.iterdir()], ['parent-tmp'])
            self.assertNotEqual(*layers)
            self.assertTrue((layers[0] / 'source/upper/unrelated/prior-derived-marker').is_file())
            materialize.assert_not_called()
            commands.assert_not_called()

    def test_incomplete_inactive_or_inconsistent_parent_blocks_without_fallback(self):
        for invalid in ('not_materialized', 'missing_hash', 'inactive', 'pin_mismatch'):
            with self.subTest(invalid=invalid), prepared_fixture() as (_, manager, prepared, pins, alternate, _repos):
                if invalid == 'not_materialized':
                    prepared.materialized.remove('dependency')
                elif invalid == 'missing_hash':
                    prepared.environment.pop('materialized_vector_sha256')
                elif invalid == 'inactive':
                    manager.active = None
                else:
                    prepared.environment['project_pins'] = {**pins, 'dependency': alternate}
                calls = len(manager.overlays.calls)
                with mock.patch.object(manager, '_materialize') as materialize, \
                        mock.patch.object(manager, '_git') as commands:
                    with self.assertRaisesRegex(PreparationBlocked, 'parent') as blocked:
                        with prepared.validation_view(deepcopy(prepared.environment['project_pins'])):
                            self.fail('invalid parent must never yield a derived view')
                    self.assertEqual(blocked.exception.kind, 'SOURCE_VIEW_UNVERIFIED')
                self.assertEqual(len(manager.overlays.calls), calls)
                materialize.assert_not_called(); commands.assert_not_called()

    def test_owned_top_mount_must_still_be_the_parent_layer(self):
        with prepared_fixture() as (fx, manager, prepared, pins, _, _repos):
            with prepared.validation_view(dict(pins)):
                calls = len(manager.overlays.calls)
                self.assertIs(manager.active, prepared)
                with self.assertRaisesRegex(PreparationBlocked, 'parent layer'):
                    with prepared.validation_view(dict(pins)):
                        self.fail('a derived top mount is not the prepared parent')
                self.assertEqual(len(manager.overlays.calls), calls)
            manager.overlays.bad_identity = True
            with self.assertRaisesRegex(PreparationBlocked, 'mount replacement') as blocked:
                with prepared.validation_view(dict(pins)):
                    self.fail('changed mount identity must block')
            self.assertEqual(blocked.exception.kind, 'SOURCE_VIEW_UNVERIFIED')
            serialized = json.loads(json.dumps({'error': {'kind': blocked.exception.kind,
                                                         'message': str(blocked.exception)}}))
            self.assertEqual(classify_failure(serialized), {
                'scope': 'shared', 'action': 'PAUSE_BATCH', 'kind': 'SOURCE_VIEW_UNVERIFIED'})
            manager.overlays.bad_identity = False

    def test_derived_unmount_failure_blocks_reuse_and_preserves_parent_record(self):
        with prepared_fixture() as (_, manager, prepared, pins, _, _repos):
            with self.assertRaisesRegex(PreparationBlocked, 'did not restore'):
                with prepared.validation_view(dict(pins)):
                    manager.overlays.fail_unmount = True
            self.assertNotEqual(prepared.record.get('restoration'), 'PASS')
            manager.overlays.fail_unmount = False
            with self.assertRaisesRegex(PreparationBlocked, 'parent layer'):
                with prepared.validation_view(dict(pins)):
                    self.fail('an unrestored child cannot be credited as the parent')

    def test_silent_noop_unmount_is_not_accepted_as_parent_restoration(self):
        with prepared_fixture() as (_, manager, prepared, pins, _, _repos):
            with mock.patch.object(manager.overlays, 'unmount', return_value=None):
                with self.assertRaisesRegex(PreparationBlocked, 'did not restore') as blocked:
                    with prepared.validation_view(dict(pins)):
                        pass
            self.assertEqual(blocked.exception.kind, 'ISOLATION_RESTORE_UNVERIFIED')
            self.assertTrue(all(len(stack) == 2 for stack in manager.overlays.mount_records.values()))
