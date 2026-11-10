"""Import fixed Git snapshots without parent-history walks or borrowed objects."""
from contextlib import contextmanager
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import tempfile
import time


class SnapshotImportError(RuntimeError):
    kind = 'OBJECT_SNAPSHOT_IMPORT_FAILED'


def _environment(alternates=()):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
               GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1', GIT_ALLOW_PROTOCOL='')
    if alternates:
        paths = [str(Path(path).resolve(strict=True)) for path in alternates]
        if any('\n' in path or os.pathsep in path for path in paths):
            raise SnapshotImportError('invalid alternate object path')
        env['GIT_ALTERNATE_OBJECT_DIRECTORIES'] = os.pathsep.join(paths)
    return env


def _git(root, args):
    return ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
            '-c', 'gc.auto=0', '-c', 'pack.threads=1', '-c', 'pack.windowMemory=64m',
            '-C', str(root), *args]


def _space(root, reserve, additional=0):
    if shutil.disk_usage(root).free < reserve + additional:
        raise SnapshotImportError('snapshot import would violate the disk free-space reserve')


def _file_digest(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(data)
    return digest.digest()


def _run(command, *, env, deadline, root, reserve, limit, sink=None, stdin=None):
    """Drain both pipes with explicit time/output/disk bounds; never fetch."""
    if time.monotonic() >= deadline:
        raise SnapshotImportError('snapshot import time limit exhausted')
    process = subprocess.Popen(command, stdin=stdin or subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env)
    output, errors, count = bytearray(), bytearray(), 0
    selector = selectors.DefaultSelector()
    for stream in (process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SnapshotImportError('snapshot import time limit exhausted')
            _space(root, reserve)
            for key, _ in selector.select(min(.1, remaining)):
                data = os.read(key.fileobj.fileno(), 1024 * 1024)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                count += len(data)
                if count > limit:
                    raise SnapshotImportError('snapshot import byte limit exhausted')
                if key.fileobj is process.stderr:
                    if len(errors) + len(data) > 65536:
                        raise SnapshotImportError('snapshot import diagnostic limit exhausted')
                    errors.extend(data)
                elif sink is not None:
                    _space(root, reserve, len(data))
                    sink.write(data)
                else:
                    output.extend(data)
        process.wait(timeout=max(.001, deadline - time.monotonic()))
        if process.returncode:
            # Commands contain only local paths and object IDs; diagnostics do
            # not contain fetch URLs, credentials, source content or patch text.
            raise SnapshotImportError('snapshot Git command failed: ' + errors.decode(errors='replace')[-1000:])
        return bytes(output), count
    except subprocess.TimeoutExpired as exc:
        raise SnapshotImportError('snapshot import time limit exhausted') from exc
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()


@contextmanager
def _locked(destination, deadline):
    lock = destination.parent / (destination.name + '.lock')
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SnapshotImportError('snapshot cache lock time limit exhausted')
                time.sleep(.01)
        yield
    finally:
        os.close(fd)


def import_snapshot(source_repo, destination_bare, commits, *, alternate_objects=(),
                    max_bytes, timeout, min_free_bytes, max_objects=500000):
    """Materialize commit/tree/blob closures for exactly the fixed revisions.

    ``source_repo`` may read its existing alternates plus ``alternate_objects``.
    Destination packs contain every enumerated object; old destination
    alternates are removed only after installation, then completeness is checked
    with no alternate environment. No source refs/config/checkout are written.
    Cache initialization and choice of allowed source stores belong to callers.
    """
    if (type(max_bytes) is not int or max_bytes <= 0
            or type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
            or type(min_free_bytes) is not int or min_free_bytes < 0
            or type(max_objects) is not int or max_objects <= 0):
        raise ValueError('snapshot limits must be positive (disk reserve may be zero)')
    roots = sorted(set(commits))
    if not roots or any(not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', sha) for sha in roots):
        raise ValueError('snapshot roots must be full fixed Git object IDs')
    source = Path(source_repo).resolve(strict=True)
    supplied = Path(destination_bare)
    if supplied.is_symlink():
        raise SnapshotImportError('destination cache must not be a symlink')
    destination = supplied.resolve(strict=True)
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise SnapshotImportError('snapshot source and destination must be independent')
    started = time.monotonic()
    deadline = started + timeout
    source_env, destination_env = _environment(alternate_objects), _environment()
    metadata_limit = min(max_bytes, 32 * 1024 * 1024)
    with _locked(destination, deadline):
        _space(destination, min_free_bytes)
        bare, _ = _run(_git(destination, ['rev-parse', '--is-bare-repository']), env=destination_env,
            deadline=deadline, root=destination, reserve=min_free_bytes, limit=4096)
        if bare.strip() != b'true':
            raise SnapshotImportError('snapshot destination must be a bare repository')
        for sha in roots:
            kind, _ = _run(_git(source, ['cat-file', '-t', sha]), env=source_env, deadline=deadline,
                root=destination, reserve=min_free_bytes, limit=4096)
            if kind.strip() != b'commit':
                raise SnapshotImportError('snapshot root is not a commit')
        listed, _ = _run(_git(source, ['rev-list', '--objects', '--no-object-names', '--missing=print',
                                     '--no-walk', *roots]), env=source_env, deadline=deadline,
            root=destination, reserve=min_free_bytes, limit=metadata_limit)
        ids = sorted(set(listed.decode('ascii').splitlines()))
        if not ids or len(ids) > max_objects or any(not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', sha) for sha in ids):
            raise SnapshotImportError('snapshot is incomplete or exceeds the object limit')
        objects = ('\n'.join(ids) + '\n').encode()
        pack_dir = destination / 'objects/pack'
        if pack_dir.is_symlink() or not pack_dir.resolve().is_relative_to(destination):
            raise SnapshotImportError('snapshot pack directory escapes its cache')
        pack_dir.mkdir(exist_ok=True)
        _space(destination, min_free_bytes, len(objects))
        with tempfile.TemporaryDirectory(prefix='.snapshot-', dir=destination) as staging:
            stage = Path(staging)
            ids_path, pack, index = stage / 'objects.list', stage / 'snapshot.pack', stage / 'snapshot.idx'
            ids_path.write_bytes(objects)
            with ids_path.open('rb') as input_stream, pack.open('wb') as output_stream:
                _run(_git(source, ['pack-objects', '--stdout']), env=source_env, deadline=deadline,
                    root=destination, reserve=min_free_bytes, limit=max_bytes - len(objects),
                    sink=output_stream, stdin=input_stream)
                output_stream.flush()
                os.fsync(output_stream.fileno())
            pack_bytes = pack.stat().st_size
            # Indexing verifies the complete non-thin pack. --strict would also
            # require parent history intentionally excluded from this snapshot.
            index_bound = len(ids) * 64 + 4096
            if pack_bytes + len(objects) + index_bound > max_bytes:
                raise SnapshotImportError('snapshot index reservation exceeds the byte limit')
            _space(destination, min_free_bytes, index_bound)
            digest, _ = _run(_git(destination, ['index-pack', '--index-version=2', '-o', str(index), str(pack)]),
                env=destination_env, deadline=deadline, root=destination, reserve=min_free_bytes, limit=4096)
            pack_id = digest.decode('ascii').strip()
            if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', pack_id):
                raise SnapshotImportError('Git did not return a valid pack identity')
            index_bytes = index.stat().st_size
            if pack_bytes + index_bytes + len(objects) > max_bytes:
                raise SnapshotImportError('snapshot pack and index exceed the byte limit')
            for path, suffix in ((pack, '.pack'), (index, '.idx')):
                target = pack_dir / ('pack-' + pack_id + suffix)
                if target.is_symlink():
                    raise SnapshotImportError('snapshot pack destination is a symlink')
                if target.exists():
                    if target.stat().st_size != path.stat().st_size:
                        raise SnapshotImportError('existing snapshot pack identity is inconsistent')
                    if _file_digest(target) != _file_digest(path):
                        raise SnapshotImportError('existing snapshot pack bytes are inconsistent')
                else:
                    path.replace(target)
            fd = os.open(pack_dir, os.O_RDONLY | os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
            alternates = destination / 'objects/info/alternates'
            if (alternates.is_symlink() or not alternates.parent.resolve().is_relative_to(destination)
                    or alternates.exists() and not alternates.is_file()):
                raise SnapshotImportError('destination alternates must not be a symlink')
            backup = stage / 'prior-alternates'
            if alternates.exists():
                alternates.replace(backup)
            try:
                checked, _ = _run(_git(destination, ['rev-list', '--objects', '--no-object-names', '--missing=print',
                                                   '--no-walk', *roots]), env=destination_env, deadline=deadline,
                    root=destination, reserve=min_free_bytes, limit=metadata_limit)
                if sorted(set(checked.decode('ascii').splitlines())) != ids:
                    raise SnapshotImportError('destination snapshot is not independently complete')
            except BaseException:
                if backup.exists(): backup.replace(alternates)
                raise
            fd = os.open(alternates.parent, os.O_RDONLY | os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        return {'status': 'IMPORTED', 'commits': roots, 'object_count': len(ids),
                'packed_bytes': pack_bytes, 'index_bytes': index_bytes,
                'seconds': round(time.monotonic() - started, 6), 'pack_id': pack_id,
                'independent': True, 'parent_history_included': False}
