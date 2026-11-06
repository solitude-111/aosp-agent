"""Disposable pinned-object cache with bounded serialized data and LRU eviction."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid


class ObjectCache:
    def __init__(self, directory, *, max_bytes=256 * 1024 * 1024,
                 max_entry_bytes=16 * 1024 * 1024, max_entries=1024):
        if any(type(v) is not int or v < 1 for v in (max_bytes, max_entry_bytes, max_entries)):
            raise ValueError('cache limits must be positive integers')
        self.directory = Path(directory).resolve()
        self.max_bytes, self.max_entry_bytes = max_bytes, min(max_entry_bytes, max_bytes)
        self.max_entries = max_entries
        self.hits = self.misses = self.evicted = self.bypassed = 0
        self.observed_bytes = 0
        self.initialized = False
        self.unavailable = None

    def data(self):
        return dict(hits=self.hits, misses=self.misses, evicted=self.evicted, bypassed=self.bypassed,
                    max_bytes=self.max_bytes, max_entry_bytes=self.max_entry_bytes,
                    max_entries=self.max_entries, observed_serialized_bytes=self.observed_bytes,
                    quota_adopted=self.initialized, unavailable=self.unavailable,
                    scope='managed_cache_entries_and_in_progress_serialized_write')

    @contextmanager
    def _locked(self):
        from .retrieval import ACTIVE_BUDGET
        budget = ACTIVE_BUDGET.get()
        timeout = min(2, budget.remaining()) if budget else 2
        self.directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.directory / '.cache.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('object cache lock busy; use uncached source read')
                    time.sleep(.02)
            self.scan_deadline = time.monotonic() + timeout
            self._shared_limits()
            yield
        finally:
            os.close(fd)

    def _check_scan_time(self):
        from .retrieval import ACTIVE_BUDGET
        budget = ACTIVE_BUDGET.get()
        if budget:
            budget.remaining()
        if time.monotonic() >= self.scan_deadline:
            raise TimeoutError('cache maintenance budget exhausted')

    def _shared_limits(self):
        """A shared cache adopts the strictest limits requested by its users.

        This prevents a previously initialized writer from undoing a tighter
        quota. Raising limits requires a different/cleared cache directory.
        The fixed-size policy and lock are metadata, outside the entry quota.
        """
        path = self.directory / '.limits'
        requested = dict(max_bytes=self.max_bytes, max_entry_bytes=self.max_entry_bytes,
                         max_entries=self.max_entries)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                    raise OSError('invalid cache quota metadata')
                previous = json.loads(stream.read(4097))
            if set(previous) != set(requested) or any(type(v) is not int or v < 1 for v in previous.values()):
                raise ValueError('invalid quota fields')
        except FileNotFoundError:
            previous = None
        except (ValueError, TypeError) as exc:
            raise OSError('invalid cache quota metadata') from exc
        effective = {key: min(value, previous[key]) if previous else value for key, value in requested.items()}
        if effective != requested:
            self.initialized = False
        for key, value in effective.items():
            setattr(self, key, value)
        if effective != previous:
            temporary = self.directory / '.limits.tmp'
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    json.dump(effective, stream)
                temporary.replace(path)
            finally:
                temporary.unlink(missing_ok=True)

    def _entries(self):
        """Only our hashed entries are disposable; never follow cache symlinks.

        The first access adopts/prunes legacy entries. Subsequent hits avoid a
        directory scan; writes scan at most the configured managed entry count
        after adoption. One flock covers eviction and the temporary write.
        """
        entries = []
        with os.scandir(self.directory) as prefixes:
            for prefix in prefixes:
                self._check_scan_time()
                if not re.fullmatch('[0-9a-f]{2}', prefix.name):
                    continue
                if not prefix.is_dir(follow_symlinks=False):
                    raise OSError('invalid cache prefix directory')
                with os.scandir(prefix.path) as children:
                    for child in children:
                        self._check_scan_time()
                        match = re.fullmatch(r'([0-9a-f]{64})(?:\.[0-9a-f]{32})?\.(json|tmp)', child.name)
                        if not match or not match[1].startswith(prefix.name):
                            continue
                        path = Path(child.path)
                        info = child.stat(follow_symlinks=False)
                        if (match[2] == 'tmp' or stat.S_ISLNK(info.st_mode)
                                or (stat.S_ISREG(info.st_mode) and info.st_size > self.max_entry_bytes)):
                            path.unlink(); self.evicted += 1
                        elif stat.S_ISREG(info.st_mode):
                            entries.append((info.st_mtime_ns, path, info.st_size))
                        else:
                            raise OSError('invalid cache entry type')
        return sorted(entries)

    def _trim(self, incoming=0, replace=None):
        entries = self._entries()
        used = sum(size for _, _, size in entries)
        count = len(entries)
        if replace is not None:
            retained = []
            for age, path, size in entries:
                if path == replace:
                    path.unlink(); used -= size; count -= 1; self.evicted += 1
                else:
                    retained.append((age, path, size))
            entries = retained
        for _, path, size in entries:
            if used + incoming > self.max_bytes or count + bool(incoming) > self.max_entries:
                path.unlink(); used -= size; count -= 1; self.evicted += 1
        self.observed_bytes = used
        self.initialized = True

    def _read(self, path, identity, args):
        if path.parent.is_symlink():
            raise OSError('cache prefix is a symlink')
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > self.max_entry_bytes:
                    raise ValueError('oversized or non-regular cache entry')
                raw = stream.read(self.max_entry_bytes + 1)
                if len(raw) != info.st_size:
                    raise ValueError('cache entry changed during read')
            row = json.loads(raw)
            value = row['result']
            if (row['identity'] != identity or not isinstance(value['stdout'], str)
                    or not isinstance(value['stderr'], str) or type(value['returncode']) is not int
                    or value['returncode'] not in ((0, 1) if args[0] == 'grep' else (0,))
                    or row['sha256'] != hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()):
                raise ValueError('invalid cached result')
            os.utime(path, None, follow_symlinks=False)
            return subprocess.CompletedProcess(args, **value)
        except (ValueError, KeyError, TypeError):
            path.unlink(missing_ok=True)
            return None
        except FileNotFoundError:
            return None

    def query(self, repo, commit, args, execute):
        if not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', commit):
            raise ValueError('object cache requires a full pinned commit ID')
        if not args:
            raise ValueError('object cache requires a query')
        if self.unavailable:
            self.misses += 1; self.bypassed += 1
            return execute()
        identity = json.dumps([1, str(Path(repo).resolve()), commit, list(args)], sort_keys=True)
        key = hashlib.sha256(identity.encode()).hexdigest()
        path = self.directory / key[:2] / (key + '.json')
        try:
            with self._locked():
                if not self.initialized:
                    self._trim()
                value = self._read(path, identity, args)
                if value is not None:
                    self.hits += 1
                    return value
        except OSError as exc:
            self.bypassed += 1
            self.unavailable = type(exc).__name__
        self.misses += 1
        # Never hold the cache lock while reading Git. Failure is not absence.
        result = execute()
        if self.unavailable:
            return result
        if result.returncode not in ((0, 1) if args[0] == 'grep' else (0,)):
            return result
        if sum(len(s.encode()) for s in (result.stdout, result.stderr)) > self.max_entry_bytes:
            self.bypassed += 1
            return result
        value = {'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
        row = {'identity': identity, 'result': value,
               'sha256': hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()}
        payload = json.dumps(row).encode()
        if len(payload) > self.max_entry_bytes:
            self.bypassed += 1
            return result
        try:
            with self._locked():
                if len(payload) > self.max_entry_bytes:
                    self.bypassed += 1
                    return result
                self._trim(incoming=len(payload), replace=path)
                if path.parent.is_symlink():
                    raise OSError('cache prefix is a symlink')
                path.parent.mkdir(parents=True, exist_ok=True)
                temporary = path.with_suffix('.' + uuid.uuid4().hex + '.tmp')
                try:
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(payload)
                    temporary.replace(path)
                    self.observed_bytes += len(payload)
                finally:
                    temporary.unlink(missing_ok=True)
        except OSError as exc:
            self.bypassed += 1  # Cache/disk failure cannot erase successful source evidence.
            self.unavailable = type(exc).__name__
        return result
