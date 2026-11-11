"""Scoped writable views over a kernel-verified, registered source base.

The root bind remains read-only. Only explicitly admitted repositories receive
an overlay and private Git metadata. Saved uppers are retained and reopened on
resume; they never inherit the sealed base's clean-audit credit.
"""
from __future__ import annotations

from contextvars import ContextVar
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .source_base import SourceBaseBlocked


_ACTIVE_VIEW = ContextVar('active_prepared_source_base', default=None)
_OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')
MAX_METADATA_BYTES = 64 * 1024**2
MAX_METADATA_FILES = 20000
MAX_COPY_BYTES = 32 * 1024**2


def _require(condition, message):
    if not condition:
        raise SourceBaseBlocked(message, kind='SOURCE_VIEW_UNVERIFIED')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def _relative(value):
    _require(isinstance(value, str) and value and not value.startswith('/')
             and all(part not in ('', '.', '..') for part in value.split('/'))
             and not any(char in value for char in '\\\0\n'), 'invalid source-view relative path')
    return value


def _contained(path, root):
    path, root = Path(path), Path(root)
    _require(path.is_absolute() and path.resolve() == path and path.is_relative_to(root)
             and path != root, 'source-view state path escapes its owned layer')
    return path


def verify_active_source_view(source_root, vector, descriptor):
    view = _ACTIVE_VIEW.get()
    _require(view is not None and view.root == Path(source_root), 'no active source-base view owns this source root')
    return view.verify(vector, descriptor)


class SourceBaseView:
    def __init__(self, prepared, base, *, pins=None, layer=None, parent=None):
        self.prepared, self.manager, self.base, self.parent = prepared, prepared.manager, base, parent
        self.overlays = self.manager.overlays
        self.root = Path(self.manager.config['source_root'])
        self.project_pins = dict(pins if pins is not None else prepared.environment['project_pins'])
        _require(set(self.project_pins) == set(base.projects)
                 and all(isinstance(pin, str) and _OID.fullmatch(pin) for pin in self.project_pins.values()),
                 'source-base reuse requires the same complete project layout')
        _require(set(prepared.catalog.projects) == set(base.projects), 'prepared project layout differs from sealed base')
        _require(prepared.record['frozen'].get('manifest_files', []) == base.catalog.get('manifest_files', []),
                 'manifest projection layout differs from sealed base')
        self._mounts, self._expected, self._token = [], {}, None
        self._active, self._failed = False, False
        self.writable, self.metadata = set(), {}
        binding = base.descriptor
        fixed = {'version': 1, 'base_id': binding['base_id'], 'base_receipt_sha256': binding['receipt_sha256'],
                 'source_root': str(self.root), 'project_pins': self.project_pins}
        owner = Path(prepared.record['layer_root'])
        _require(owner.is_absolute() and owner.resolve() == owner, 'source-view owner layer is not canonical')
        saved = prepared.record.get('source_view_state') if parent is None else None
        self._resuming = saved is not None
        if saved is not None:
            _require(isinstance(saved, dict) and all(saved.get(k) == v for k, v in fixed.items()),
                     'saved source view belongs to another base, vector or source root')
            self.state = deepcopy(saved)
            self.layer = _contained(Path(saved['instance_layer']), owner)
            _require(self.layer.is_dir() and self.layer.parent == owner
                     and re.fullmatch(r'source-view-[0-9a-f]{32}', self.layer.name), 'saved source-view layer is absent or invalid')
            _require(isinstance(saved.get('writable'), list) and sorted(set(saved['writable'])) == saved['writable']
                     and set(saved['writable']) <= set(base.projects), 'saved writable scope is invalid')
            _require(isinstance(saved.get('metadata'), dict)
                     and set(saved['metadata']) == set(saved['writable'])
                     and set(saved.get('repository_layers', {})) == set(saved['writable']),
                     'saved source-view metadata is incomplete')
            _require(isinstance(saved.get('copyfile_bindings'), list), 'saved manifest bindings are invalid')
        else:
            self.layer = _contained(Path(layer) if layer is not None else owner / ('source-view-' + uuid.uuid4().hex), owner)
            _require(not self.layer.exists(), 'new source-view layer already exists')
            self.layer.mkdir(parents=True)
            self.state = {**fixed, 'instance_layer': str(self.layer), 'writable': [], 'metadata': {},
                          'repository_layers': {}, 'copyfile_bindings': [], 'state': 'PLANNED'}
            self._save()

    @property
    def descriptor(self):
        binding = self.base.descriptor
        return {'version': 1, 'base_id': binding['base_id'], 'base_receipt_sha256': binding['receipt_sha256'],
                'base_vector_sha256': binding['project_vector_sha256'],
                'project_pins_sha256': _digest(self.project_pins), 'writable_repositories': sorted(self.writable)}

    def _save(self):
        from .preparation import write_receipt
        if self.parent is None:
            self.prepared.record['source_view_state'] = deepcopy(self.state)
            self.prepared.save()
        else:
            write_receipt(self.layer / 'source-view-state.json', self.state)

    def _track(self, target):
        target = Path(target)
        # Track ownership before persisting, so a failed receipt write still rolls back.
        self._mounts.append(target)
        proof = self.overlays.verify(target)
        self._expected[str(target)] = proof['mount_id']
        self.state['mounts'] = [{'target': str(path), 'mount_id': self._expected[str(path)]} for path in self._mounts]
        self._save()

    def _bind(self, source, target, *, readonly):
        self.overlays.bind(source, target, readonly=readonly)
        self._track(target)

    def _overlay(self, target, layer, *, lower=None):
        self.overlays.mount(target, layer, lower=lower)
        self._track(target)

    def activate(self):
        _require(not self._active and not self._mounts and not self._failed, 'source view cannot be activated twice')
        self.base.revalidate()
        self.overlays.check_namespace()
        _require(self.root.resolve() == self.root and self.root.is_dir(), 'source view root must be a real directory')
        try:
            if self.parent is None:
                _require(not self.overlays.source_mounts(self.root), 'source root already contains an unowned mount')
                self._bind(self.base.mount_root, self.root, readonly=True)
            else:
                _require(_ACTIVE_VIEW.get() is self.parent and self.parent._active, 'derived view has no active parent')
                self.parent.verify(self.parent.project_pins, self.parent.descriptor)
            build = self.manager.config.get('build', {})
            if build.get('enabled'):
                for key in ('output_root', 'tmp_root'):
                    target = Path(build[key])
                    _require(not target.is_relative_to(self.root) and not self.root.is_relative_to(target),
                             'build output overlaps the source view')
                    target.mkdir(parents=True, exist_ok=True)
                    empty = self.layer / (key + '-empty')
                    if self._resuming:
                        _require(empty.is_dir() and not empty.is_symlink() and not any(empty.iterdir()),
                                 'saved build lower layer is absent or not empty')
                        _require((self.layer / key / 'upper').is_dir() and (self.layer / key / 'work').is_dir(),
                                 'saved build overlay is incomplete')
                    else:
                        empty.mkdir()
                    self._overlay(target, self.layer / key, lower=empty)
            self._active = True
            self._token = _ACTIVE_VIEW.set(self)
            if self._resuming:
                for key in self.state['writable']:
                    self._open_repository(key, resume=True)
                for item in self.state['copyfile_bindings']:
                    self._restore_copyfile(item)
            elif self.parent is not None:
                self.ensure_writable(sorted(self.parent.writable))
            self.state['state'] = 'ACTIVE'
            self._save()
            self._verify_mounts()
            return self
        except BaseException:
            self.close()
            raise

    def _scope(self, key):
        _relative(key)
        _require(key in self.base.projects, 'writable repository is outside the sealed catalogue')
        _require(not any(other != key and (other.startswith(key + '/') or key.startswith(other + '/'))
                         for other in self.base.projects), 'nested writable project layout is not supported')
        repo = self.root / key
        _require(repo.resolve() == repo and repo.is_dir(), 'repository path is not a real contained directory')
        return repo

    def ensure_writable(self, keys):
        _require(self._active and not self._failed and _ACTIVE_VIEW.get() is self, 'source view is not the active writable owner')
        self.base.revalidate()
        self._verify_mounts()
        keys = sorted(set(keys))
        for key in keys:
            self._scope(key)
        for key in keys:
            if key not in self.writable:
                self._open_repository(key, resume=False)
        self._verify_mounts()

    def _copy_metadata(self, source, destination, allowed_root):
        """Copy bounded metadata bytes, never hardlink indexes/refs or borrow writes."""
        source, allowed_root = Path(source), Path(allowed_root)
        started = time.monotonic()
        self.manager._resources()
        limit = min(60., self.manager.policy['max_seconds'] - self.manager.seconds_used)
        from .execution_budget import ACTIVE_EXECUTION
        ledger = ACTIVE_EXECUTION.get()
        if ledger is not None:
            limit = min(limit, ledger.remaining_seconds())
        _require(limit > 0, 'metadata copy has no remaining time')
        total, count = 0, 0
        self.manager._save_accounting(limit)
        def copy_entry(src, dst, depth=0):
            nonlocal total, count
            _require(time.monotonic() - started < limit and depth < 64, 'metadata copy exceeded its time or depth bound')
            actual = src.resolve()
            _require(actual.is_relative_to(allowed_root), 'Git metadata link escapes its controlled source')
            info = actual.stat()
            count += 1
            _require(count <= MAX_METADATA_FILES, 'Git metadata exceeds the file bound')
            if stat.S_ISDIR(info.st_mode):
                dst.mkdir(mode=0o700)
                for child in sorted(actual.iterdir()):
                    if depth == 0 and child.name in ('objects', 'worktrees'):
                        continue
                    copy_entry(child, dst / child.name, depth + 1)
            else:
                _require(stat.S_ISREG(info.st_mode), 'Git metadata contains a special file')
                total += info.st_size
                _require(total <= MAX_METADATA_BYTES, 'Git metadata exceeds its byte bound')
                reservation = ledger.reserve_io(info.st_size + 1, 'source_base_metadata') if ledger is not None else None
                actual_bytes = 0
                try:
                    with actual.open('rb') as reader, dst.open('xb') as writer:
                        while True:
                            chunk = reader.read(min(65536, info.st_size - actual_bytes + 1))
                            if not chunk:
                                break
                            actual_bytes += len(chunk)
                            _require(actual_bytes <= info.st_size and time.monotonic() - started < limit,
                                     'Git metadata changed or exceeded its time bound')
                            writer.write(chunk)
                        _require(actual_bytes == info.st_size, 'Git metadata changed while being isolated')
                        writer.flush(); os.fsync(writer.fileno())
                finally:
                    if reservation is not None:
                        ledger.settle_io(reservation, actual_bytes)
        try:
            copy_entry(source, destination)
        finally:
            self.manager.seconds_used += time.monotonic() - started
            self.manager._save_accounting()

    def _open_repository(self, key, *, resume):
        repo = self._scope(key)
        name = hashlib.sha256(key.encode()).hexdigest()
        private, layer = self.layer / 'git' / name, self.layer / 'repositories' / name
        if resume:
            metadata = self.state['metadata'][key]
            _require(metadata == {'path': str(private), 'state': 'READY'}
                     and self.state['repository_layers'][key] == str(layer), 'saved repository layer binding changed')
            _contained(private, self.layer); _contained(layer, self.layer)
            _require(private.is_dir() and (private / 'objects').is_dir()
                     and (layer / 'upper').is_dir() and (layer / 'work').is_dir(), 'saved writable repository layer is incomplete')
        else:
            row = self.base.projects[key]
            _require(row['git_dir'] == row['common_dir'], 'linked-worktree Git metadata is not supported by source-base reuse')
            self.state['writable'] = sorted(set(self.state['writable']) | {key})
            self.state['metadata'][key] = {'path': str(private), 'state': 'COPYING'}
            self.state['repository_layers'][key] = str(layer)
            self._save()
            private.parent.mkdir(exist_ok=True)
            if self.parent is not None and key in self.parent.writable:
                source, allowed = Path(self.parent.metadata[key]), self.parent.layer
                objects = source / 'objects'
            else:
                source, allowed = Path(self.base.mount_root) / row['git_dir'], Path(self.base.mount_root)
                objects = Path(self.base.mount_root) / row['objects_dir']
            self._copy_metadata(source, private, allowed)
            (private / 'objects' / 'info').mkdir(parents=True)
            (private / 'objects' / 'info' / 'alternates').write_text(str(objects) + '\n')
            # The catalogue's relocatable worktree path must never be reused here.
            for setting, value in (('core.worktree', str(repo)), ('core.bare', 'false')):
                result = self.manager._git(private, '--git-dir=' + str(private), 'config', setting, value)
                _require(result.returncode == 0, 'could not isolate private Git configuration')
            self.state['metadata'][key]['state'] = 'READY'
            self._save()
        self._verify_private_metadata(private, repo)
        self._overlay(repo, layer)
        marker = repo / '.git'
        if resume:
            _require(marker.is_dir() and not marker.is_symlink(), 'saved private Git mount point changed')
        else:
            if marker.is_symlink() or marker.is_file():
                marker.unlink()
            if not marker.exists():
                marker.mkdir()
        _require(marker.is_dir() and not marker.is_symlink(), 'private Git mount point is invalid')
        self._bind(private, marker, readonly=False)
        self.metadata[key] = str(private)
        self.writable.add(key)
        self._save()

    def _verify_private_metadata(self, private, repo):
        # All links were flattened during the first bounded copy. Reopening must
        # not let a replaced refs/index/objects path write into the sealed base
        # or another checkout. Inspect only this admitted private Git directory.
        _contained(private, self.layer)
        count = 0
        for directory, dirs, files in os.walk(private, followlinks=False):
            for name in [*dirs, *files]:
                path = Path(directory) / name
                count += 1
                _require(count <= MAX_METADATA_FILES and not path.is_symlink(),
                         'private Git metadata is too large or contains a replaced symbolic link')
                _require(stat.S_ISDIR(path.stat().st_mode) or stat.S_ISREG(path.stat().st_mode),
                         'private Git metadata contains a special file')
        result = self.manager._git(private, '--git-dir=' + str(private), 'rev-parse',
                                   '--show-toplevel', '--absolute-git-dir')
        _require(result.returncode == 0 and result.stdout.splitlines() == [str(repo), str(private)],
                 'effective private Git worktree or metadata path differs')

    def _read_copy(self, path):
        info = path.stat()
        _require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_COPY_BYTES, 'manifest copy exceeds its file bound')
        from .execution_budget import ACTIVE_EXECUTION
        ledger = ACTIVE_EXECUTION.get()
        reservation = ledger.reserve_io(info.st_size + 1, 'source_base_manifest') if ledger is not None else None
        data = b''
        try:
            with path.open('rb') as stream:
                data = stream.read(info.st_size + 1)
            _require(len(data) == info.st_size, 'manifest copy changed while being read')
            return data
        finally:
            if reservation is not None:
                ledger.settle_io(reservation, len(data))

    def _restore_copyfile(self, item):
        _require(isinstance(item, dict) and set(item) == {'dest', 'path', 'sha256'}, 'invalid saved manifest binding')
        declared = {op['dest'] for op in self.base.catalog.get('manifest_files', []) if op['kind'] == 'copyfile'}
        _require(item['dest'] in declared, 'saved manifest binding is outside the sealed layout')
        source = _contained(Path(item['path']), self.layer)
        _require(hashlib.sha256(self._read_copy(source)).hexdigest() == item['sha256'], 'saved manifest copy changed')
        dest = self.root / _relative(item['dest'])
        _require(dest.resolve() == dest and dest.is_file(), 'manifest destination is not a real file')
        self._bind(source, dest, readonly=True)

    def refresh_manifest_files(self, operations):
        _require(self._active and _ACTIVE_VIEW.get() is self, 'manifest refresh requires the active source view')
        self.base.revalidate()
        self._verify_mounts()
        _require(operations == self.base.catalog.get('manifest_files', []), 'manifest projection layout changed')
        for item in operations:
            source = self.root / item['project'] / item['src']
            dest = self.root / _relative(item['dest'])
            _require(source.resolve().is_relative_to(self.root / item['project'])
                     and dest.parent.resolve() == dest.parent, 'manifest projection escaped its repository')
            if item['kind'] == 'linkfile':
                _require(dest.is_symlink() and os.readlink(dest) == os.path.relpath(source, dest.parent)
                         and dest.resolve() == source.resolve(), 'manifest link layout changed')
                continue
            _require(item['kind'] == 'copyfile' and not dest.is_symlink(), 'unsupported manifest projection')
            # Sealed, unchanged projects already have an independently audited projection.
            if item['project'] not in self.writable:
                continue
            data = self._read_copy(source)
            if data == self._read_copy(dest):
                continue
            _require(not any(dest.is_relative_to(self.root / key) for key in self.base.projects),
                     'changed manifest copy overlaps a project audit scope')
            directory = self.layer / 'manifest-copies'
            directory.mkdir(exist_ok=True)
            path = directory / uuid.uuid4().hex
            with path.open('xb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            record = {'dest': item['dest'], 'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()}
            self.state['copyfile_bindings'].append(record)
            self._save()
            self._restore_copyfile(record)
        self._verify_mounts()

    def _visible_expected(self):
        expected = self.parent._visible_expected() if self.parent is not None else {}
        expected.update(self._expected)
        return expected

    def _verify_mounts(self):
        _require(not self._failed, 'source view restoration is unverified')
        expected = self._visible_expected()
        source_targets = {path for path in expected if Path(path).is_relative_to(self.root)}
        _require(self.overlays.source_mounts(self.root) == source_targets, 'source view contains an unexpected mount')
        observed = {}
        for path, mount_id in expected.items():
            proof = self.overlays.verify(Path(path))
            _require(proof['mount_id'] == mount_id, 'source-view top mount was replaced')
            observed[path] = proof
        return observed

    def verify(self, vector, descriptor):
        _require(self._active and _ACTIVE_VIEW.get() is self and not self._failed, 'source view is not active')
        _require(dict(vector) == self.project_pins and descriptor == self.descriptor,
                 'source-view descriptor or fixed vector changed')
        sealed = self.base.revalidate()
        mounts = self._verify_mounts()
        readonly = set(vector) - self.writable
        _require(all(vector[key] == self.base.project_pins[key] for key in readonly),
                 'changed project has not received an isolated writable layer')
        rows = {key: deepcopy(self.base.audit['repositories'][key]) for key in sorted(readonly)}
        return {'base_id': self.descriptor['base_id'], 'base_receipt_sha256': self.descriptor['base_receipt_sha256'],
                'writable_repositories': sorted(self.writable), 'repositories': rows,
                'runtime_mount_proof': {'base': sealed, 'mounts': mounts}}

    def close(self):
        if not self._mounts and self._token is None:
            return
        try:
            while self._mounts:
                target = self._mounts[-1]
                proof = self.overlays.verify(target)
                _require(proof['mount_id'] == self._expected[str(target)], 'cannot unmount a replaced source-view layer')
                self.overlays.unmount(target)
                self._mounts.pop()
                # A repeated copyfile destination may have an earlier owned bind underneath.
                if target in self._mounts:
                    self._expected[str(target)] = self.overlays.verify(target)['mount_id']
                else:
                    self._expected.pop(str(target), None)
        except BaseException as exc:
            self._failed = True
            self.state['state'] = 'RESTORE_BLOCKED'
            self._save()
            raise SourceBaseBlocked('source-view layer could not be restored; preserved for recovery',
                                    kind='ISOLATION_RESTORE_UNVERIFIED') from exc
        if self._token is not None:
            _ACTIVE_VIEW.reset(self._token)
            self._token = None
        self._active = False
        self.state['state'] = 'RELEASED'
        self.state['mounts'] = []
        self._save()
