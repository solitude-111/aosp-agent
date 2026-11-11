"""Verify externally sealed source bases; never provision or silently downgrade.

The supported provider is an fs-verity protected image mounted read-only through
a read-only loop device as SquashFS. JSON describes the expected image; kernel
ioctls and the visible mount establish its actual identity. Registration requires
an independent full audit. Reopening a registered base never invokes Git.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
from urllib.parse import urlsplit

from .lifecycle import RecoveryBlocked


PROVIDER = 'fsverity_squashfs'
PROTOCOL = 1
MAX_JSON = 16 * 1024**2
FS_IOC_MEASURE_VERITY = 0xC0046686
LOOP_GET_STATUS64 = 0x4C05
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')


class SourceBaseBlocked(RecoveryBlocked):
    def __init__(self, message, *, kind='SOURCE_BASE_INVALID'):
        super().__init__(message)
        self.kind = kind


def _require(condition, message):
    if not condition:
        raise SourceBaseBlocked(message)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def _pairs(values):
    result = {}
    for key, value in values:
        _require(key not in result, 'duplicate source-base JSON key')
        result[key] = value
    return result


def _json(data):
    try:
        return json.loads(data, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (ValueError, UnicodeError) as exc:
        raise SourceBaseBlocked('invalid source-base JSON') from exc


def _relative(value):
    _require(isinstance(value, str) and value and not value.startswith('/')
             and '\\' not in value and '\0' not in value,
             'source-base path must be source-root relative')
    _require(all(part not in ('', '.', '..') for part in value.split('/')),
             'source-base path is not normalized')
    return value


def _absolute(value):
    _require(isinstance(value, str) and value.startswith('/') and str(Path(value)) == value
             and '..' not in Path(value).parts and '\0' not in value,
             'source-base path must be normalized and absolute')
    return Path(value)


def _open_path(path, *, directory=False):
    """Reject symlinks in every component, not just in the final filename."""
    path = _absolute(str(path))
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if not last or directory:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_fd(descriptor, limit=MAX_JSON):
    _require(stat.S_ISREG(os.fstat(descriptor).st_mode), 'source-base document is not a regular file')
    _require(os.fstat(descriptor).st_size <= limit, 'source-base document exceeds its byte bound')
    data = os.pread(descriptor, limit + 1, 0)
    _require(len(data) <= limit, 'source-base document grew beyond its byte bound')
    return data


def _read_path(path):
    descriptor = _open_path(path)
    try:
        return _read_fd(descriptor)
    finally:
        os.close(descriptor)


def _read_at(root_fd, relative):
    parts = _relative(relative).split('/')
    descriptor = os.dup(root_fd)
    try:
        for index, part in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if index != len(parts) - 1:
                flags |= os.O_DIRECTORY
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return _read_fd(descriptor)
    finally:
        os.close(descriptor)


def _proc(path, limit):
    with open(path) as stream:
        value = stream.read(limit + 1)
    _require(len(value) <= limit, 'kernel mount identity exceeds its read bound')
    return value


def _unescape(value):
    return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)


def _visible_mount(descriptor):
    ids = re.findall(r'^mnt_id:\s*([1-9][0-9]*)\s*$',
                     _proc('/proc/self/fdinfo/' + str(descriptor), 65536), re.MULTILINE)
    _require(len(ids) == 1, 'visible source-base mount ID is absent or ambiguous')
    lines = [line for line in _proc('/proc/self/mountinfo', 4 * 1024**2).splitlines()
             if line.split(' ', 1)[0] == ids[0]]
    _require(len(lines) == 1, 'visible source-base mount entry is absent or ambiguous')
    before, after = lines[0].split(' - ')
    fields, filesystem = before.split(), after.split()
    _require(len(fields) >= 6 and len(filesystem) == 3, 'invalid mountinfo identity')
    return {'mount_id': int(ids[0]), 'device': fields[2], 'root': _unescape(fields[3]),
            'target': _unescape(fields[4]), 'options': fields[5].split(','),
            'filesystem': filesystem[0], 'source': _unescape(filesystem[1]),
            'super_options': filesystem[2].split(',')}


def _measure_verity(descriptor):
    data = bytearray(struct.pack('=HH', 0, 32) + bytes(32))
    fcntl.ioctl(descriptor, FS_IOC_MEASURE_VERITY, data, True)
    algorithm, size = struct.unpack_from('=HH', data)
    _require(algorithm == 1 and size == 32, 'source-base image must use SHA-256 fs-verity')
    return bytes(data[4:36]).hex()


def _loop_info(descriptor):
    data = bytearray(232)
    fcntl.ioctl(descriptor, LOOP_GET_STATUS64, data, True)
    values = struct.unpack('=QQQQQIIII64s64s32sQQ', data)
    return dict(zip(('device', 'inode', 'rdevice', 'offset', 'sizelimit', 'number',
                     'encryption', 'key_size', 'flags'), values[:9]))


def _reject_submounts(root):
    # A read-only image at the root says nothing about a writable mount placed
    # over one of its projects. The base provider admits no such substitutions.
    prefix = root.rstrip('/') + '/'
    for line in _proc('/proc/self/mountinfo', 4 * 1024**2).splitlines():
        fields = line.split(' - ', 1)[0].split()
        _require(len(fields) >= 6, 'invalid kernel mount table')
        _require(not _unescape(fields[4]).startswith(prefix),
                 'a nested mount covers part of the sealed source base')


def _verify_kernel(image_fd, mount_fd, loop_fd, spec):
    image, mounted, loop = os.fstat(image_fd), os.fstat(mount_fd), os.fstat(loop_fd)
    _require(stat.S_ISREG(image.st_mode), 'source-base image is not regular')
    _require(stat.S_ISBLK(loop.st_mode), 'source-base backing device is not a loop block device')
    digest = _measure_verity(image_fd)
    _require(digest == spec['verity_digest'], 'source-base fs-verity digest changed')
    mount = _visible_mount(mount_fd)
    _require(mount['filesystem'] == 'squashfs' and mount['root'] == '/'
             and mount['target'] == spec['mount_root']
             and 'ro' in mount['options'] and 'ro' in mount['super_options'],
             'source-base must be the complete visible read-only SquashFS mount')
    _require(mounted.st_dev == loop.st_rdev
             and mount['device'] == f'{os.major(loop.st_rdev)}:{os.minor(loop.st_rdev)}',
             'source-base mount does not use the held loop device')
    info = _loop_info(loop_fd)
    _require(info['device'] == image.st_dev and info['inode'] == image.st_ino
             and info['rdevice'] == 0 and info['offset'] == 0 and info['sizelimit'] == 0
             and info['encryption'] == 0 and info['key_size'] == 0 and info['flags'] & 1,
             'loop device does not bind the exact sealed image read-only')
    _require(os.fstatvfs(mount_fd).f_flag & os.ST_RDONLY,
             'source-base filesystem is not read-only')
    _reject_submounts(spec['mount_root'])
    return {'provider': PROVIDER, 'verity_digest': digest, 'mount': mount,
            'loop': info, 'image_device': image.st_dev, 'image_inode': image.st_ino,
            'image_bytes': image.st_size}


def _validate_spec(spec):
    _require(isinstance(spec, dict) and set(spec) ==
             {'provider', 'image', 'mount_root', 'verity_digest', 'catalog_path', 'catalog_sha256'},
             'unsupported source-base specification')
    _require(spec['provider'] == PROVIDER, 'unsupported source-base provider')
    for key in ('image', 'mount_root'):
        _absolute(spec[key])
    for key in ('verity_digest', 'catalog_sha256'):
        _require(isinstance(spec[key], str) and SHA256.fullmatch(spec[key]), 'invalid source-base digest')
    _relative(spec['catalog_path'])


def _validate_catalog(catalog):
    _require(isinstance(catalog, dict) and type(catalog.get('version')) is int and catalog['version'] == PROTOCOL,
             'unsupported source-base catalogue protocol')
    projects = catalog.get('projects')
    _require(isinstance(projects, dict) and 0 < len(projects) <= 100000,
             'source-base needs a bounded complete project catalogue')
    for key, row in projects.items():
        _relative(key)
        _require(isinstance(row, dict), 'invalid source-base project')
        for field in ('commit', 'tree'):
            _require(isinstance(row.get(field), str) and OID.fullmatch(row[field]), 'invalid fixed source-base object')
        for field in ('git_dir', 'common_dir', 'objects_dir'):
            _relative(row.get(field))
        _require(isinstance(row.get('audit'), dict), 'source-base catalogue lacks a stable audit row')
        if 'source_revision' in row:
            _require(isinstance(row['source_revision'], str) and 0 < len(row['source_revision']) <= 1024
                     and not any(ord(c) < 32 for c in row['source_revision']), 'invalid frozen source revision')
        if 'origin' in row:
            _require(isinstance(row['origin'], str), 'invalid frozen project origin')
            origin = urlsplit(row['origin'])
            _require(origin.scheme == 'https' and origin.hostname and not origin.username
                     and not origin.password and not origin.query and not origin.fragment
                     and not any(ord(c) < 33 for c in row['origin']), 'frozen project origin must be HTTPS')
        if 'references' in row:
            _require(isinstance(row['references'], dict) and len(row['references']) <= 4096,
                     'invalid frozen reference mapping')
            for reference, commit in row['references'].items():
                _require(isinstance(reference, str) and 0 < len(reference) <= 1024
                         and not any(ord(c) < 32 for c in reference)
                         and isinstance(commit, str) and OID.fullmatch(commit),
                         'invalid frozen reference or fixed object')
    _require(isinstance(catalog.get('manifest_files'), list) and len(catalog['manifest_files']) <= 4096,
             'source-base lacks a bounded manifest-file projection')
    return projects


def _validate_audit(audit, projects, catalog):
    _require(isinstance(audit, dict) and audit.get('status') == 'PASS'
             and isinstance(audit.get('repositories'), dict)
             and set(audit['repositories']) == set(projects),
             'registration requires a complete independent successful audit')
    for key, project in projects.items():
        row = audit['repositories'][key]
        _require(row == project['audit'] and row.get('head') == project['commit']
                 and row.get('tree') == project['tree'] and row.get('status') == ''
                 and type(row.get('index_check_returncode')) is int and row['index_check_returncode'] == 0
                 and type(row.get('worktree_check_returncode')) is int and row['worktree_check_returncode'] == 0
                 and row.get('index_flags_verified') is True
                 and row.get('undeclared_ignored_files') == []
                 and isinstance(row.get('ignored_files'), list)
                 and isinstance(row.get('declared_ignored_inputs'), dict)
                 and set(row['ignored_files']) == set(row['declared_ignored_inputs']),
                 'source-base audit is dirty, incomplete or differs from the sealed catalogue: ' + key)
    references = {key: {field: row[field] for field in ('source_revision', 'origin', 'references') if field in row}
                  for key, row in projects.items() if any(field in row for field in ('source_revision', 'origin', 'references'))}
    if references:
        _require(audit.get('project_references') == references, 'initial audit did not verify frozen project references')
    if 'manifest_provenance' in catalog:
        _require(isinstance(catalog['manifest_provenance'], dict)
                 and audit.get('manifest_provenance') == catalog['manifest_provenance'],
                 'initial audit did not verify manifest provenance')
    if 'frozen_manifest' in catalog:
        _require(isinstance(catalog['frozen_manifest'], dict)
                 and audit.get('frozen_manifest_sha256') == _digest(catalog['frozen_manifest']),
                 'initial audit did not verify the frozen manifest')


class SourceBaseHandle:
    def __init__(self, spec):
        self._fds = []
        self.binding = None
        self.audit = None
        try:
            if sys.platform != 'linux':
                raise SourceBaseBlocked('source-base kernel proof requires Linux', kind='SOURCE_BASE_UNAVAILABLE')
            _validate_spec(spec)
            self.spec = dict(spec)
            self.mount_root = Path(spec['mount_root'])
            self.image_fd = _open_path(spec['image']); self._fds.append(self.image_fd)
            self.mount_fd = _open_path(spec['mount_root'], directory=True); self._fds.append(self.mount_fd)
            mount = _visible_mount(self.mount_fd)
            _require(re.fullmatch(r'/dev/loop[0-9]+', mount['source']), 'source-base is not mounted from an identifiable loop device')
            self.loop_fd = _open_path(mount['source']); self._fds.append(self.loop_fd)
            self.proof = _verify_kernel(self.image_fd, self.mount_fd, self.loop_fd, self.spec)
            data = _read_at(self.mount_fd, spec['catalog_path'])
            _require(hashlib.sha256(data).hexdigest() == spec['catalog_sha256'], 'sealed catalogue hash differs')
            self.catalog = _json(data)
            self.projects = _validate_catalog(self.catalog)
            self.project_pins = {key: row['commit'] for key, row in self.projects.items()}
            self.base_id = _digest({'protocol': PROTOCOL, 'provider': PROVIDER,
                                    'verity_digest': spec['verity_digest'], 'catalog_sha256': spec['catalog_sha256']})
            self.revalidate()
        except BaseException as exc:
            self.close()
            if isinstance(exc, SourceBaseBlocked):
                raise
            if isinstance(exc, (OSError, ValueError, TypeError, KeyError)):
                raise SourceBaseBlocked('source-base kernel capability or evidence unavailable: ' + str(exc),
                                        kind='SOURCE_BASE_UNAVAILABLE') from exc
            raise

    @property
    def descriptor(self):
        _require(self.binding is not None, 'unregistered source base has no reusable descriptor')
        return {'version': PROTOCOL, 'provider': PROVIDER, 'base_id': self.base_id,
                **self.binding, 'catalog_sha256': self.spec['catalog_sha256'],
                'verity_digest': self.spec['verity_digest'], 'project_vector_sha256': _digest(self.project_pins)}

    def revalidate(self):
        _require(bool(self._fds), 'source-base handle is closed')
        try:
            # A saved FD cannot authorize a different object now visible by path.
            for path, held, directory in ((self.spec['image'], self.image_fd, False),
                                           (self.spec['mount_root'], self.mount_fd, True)):
                fresh = _open_path(path, directory=directory)
                try:
                    a, b = os.fstat(fresh), os.fstat(held)
                    _require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'source-base path was replaced')
                    if directory:
                        _require(_visible_mount(fresh)['mount_id'] == _visible_mount(held)['mount_id'],
                                 'source-base visible mount was replaced')
                finally:
                    os.close(fresh)
            self.proof = _verify_kernel(self.image_fd, self.mount_fd, self.loop_fd, self.spec)
            return self.proof
        except OSError as exc:
            raise SourceBaseBlocked('source-base seal is no longer verifiable', kind='SOURCE_BASE_UNAVAILABLE') from exc

    def close(self):
        while self._fds:
            os.close(self._fds.pop())

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def _publish(path, value):
    path = _absolute(str(path))
    encoded = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()
    _require(len(encoded) <= MAX_JSON, 'source-base registration exceeds its byte bound')
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(encoded)
            stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path)  # Atomic and exclusive: never replace an old registration.
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        os.unlink(temporary)


def register_source_base(spec, receipt_path, *, audit):
    """Register an already sealed image after the caller's first full Git audit.

The callback must inspect the held immutable view, including object closure and
metadata containment. Its full clean rows must equal the sealed catalogue; the
catalogue's self-declared rows alone never grant reuse permission.
"""
    _require(callable(audit), 'an independent first-registration audit is required')
    receipt_path = _absolute(str(receipt_path))
    _require(not os.path.lexists(receipt_path), 'source-base registration already exists')
    with SourceBaseHandle(spec) as handle:
        result = audit(handle)
        _validate_audit(result, handle.projects, handle.catalog)
        handle.revalidate()
        receipt = {'version': PROTOCOL, 'state': 'READY', 'base_id': handle.base_id,
                   'spec': dict(spec), 'audit': result}
        try:
            _publish(Path(receipt_path), receipt)
        except OSError as exc:
            raise SourceBaseBlocked('source-base registration could not be published exclusively') from exc
    data = _read_path(receipt_path)
    return {'receipt': str(Path(receipt_path)), 'receipt_sha256': hashlib.sha256(data).hexdigest()}


def open_source_base(binding):
    """Open a previously registered base; no Git, provisioning or legacy fallback."""
    _require(isinstance(binding, dict) and set(binding) == {'receipt', 'receipt_sha256'}
             and isinstance(binding['receipt_sha256'], str) and SHA256.fullmatch(binding['receipt_sha256']),
             'invalid source-base binding')
    try:
        data = _read_path(binding['receipt'])
        _require(hashlib.sha256(data).hexdigest() == binding['receipt_sha256'], 'source-base registration receipt changed')
        receipt = _json(data)
        _require(type(receipt.get('version')) is int and receipt['version'] == PROTOCOL and receipt.get('state') == 'READY',
                 'source-base has no completed first registration')
        handle = SourceBaseHandle(receipt['spec'])
        try:
            _require(receipt.get('base_id') == handle.base_id, 'source-base registration identity changed')
            _validate_audit(receipt.get('audit'), handle.projects, handle.catalog)
            handle.binding = dict(binding)
            handle.audit = receipt['audit']
            return handle
        except BaseException:
            handle.close()
            raise
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, SourceBaseBlocked): raise
        raise SourceBaseBlocked('registered source base is unavailable: ' + str(exc),
                                kind='SOURCE_BASE_UNAVAILABLE') from exc
