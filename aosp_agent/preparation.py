"""Controller-owned preparation and persistent per-case Linux overlay views.

The model remains offline. Only this controller can fetch from configured HTTPS
origins; source stores are read-only inputs and fetched objects live in our cache.
"""
from contextlib import contextmanager
from dataclasses import asdict, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import stat
import tempfile
import threading
import time
from urllib.parse import urljoin, urlsplit
import xml.etree.ElementTree as ET

from .case import validate_relative_path
from .git_policy import offline_git_env
from .lifecycle import RecoveryBlocked
from .project_catalog import Project, ProjectCatalog, catalog_at_revision
from .runtime_input import RuntimeInput, donor_path, project_name, resolve_sources
from .server_config import validate_config, safe_origin, config_digest
from .tool_io import ToolIO, QueryOutputLimit
from .retrieval import ReadBudget


SHA = re.compile(r'[0-9a-f]{40}|[0-9a-f]{64}')


class PreparationError(RuntimeError):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind, self.limit_scope = kind, 'case'


class PreparationBlocked(RecoveryBlocked):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind, self.limit_scope = kind, 'batch'


def write_receipt(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def project_origin(manifest_origin, project):
    if not project.fetch:
        raise PreparationError('UPSTREAM_UNRESOLVED', 'manifest project has no fetch origin: ' + project.key)
    base = urljoin(manifest_origin, project.fetch.rstrip('/') + '/')
    return safe_origin(urljoin(base, project.name))


class LinuxOverlays:
    """Mount only inside the launcher's private namespace, preserving each upper."""
    def __init__(self, parent_namespace=None):
        self.parent_namespace = parent_namespace
        self.mounted = []

    def check_namespace(self):
        if sys.platform != 'linux' or not self.parent_namespace:
            raise PreparationBlocked('ISOLATION_UNAVAILABLE', 'run through run-patches to enter a private Linux mount namespace')
        current = os.readlink('/proc/self/ns/mnt')
        if current == self.parent_namespace:
            raise PreparationBlocked('ISOLATION_UNAVAILABLE', 'shared mount namespace cannot host a source overlay')

    @staticmethod
    def command(args):
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode:
            raise PreparationBlocked('ISOLATION_UNAVAILABLE', 'mount operation failed: ' + result.stderr.decode(errors='replace')[-500:])
        return result.stdout.decode().strip()

    def mount(self, root, layer):
        self.check_namespace()
        root, layer = Path(root).resolve(), Path(layer).resolve()
        if not root.is_dir() or any(char in str(root) + str(layer) for char in ',:\n'):
            raise PreparationBlocked('ISOLATION_UNAVAILABLE', 'overlay paths must be existing directories without option separators')
        upper, work = layer / 'upper', layer / 'work'
        if upper.is_symlink() or work.is_symlink():
            raise PreparationBlocked('ISOLATION_RECEIPT_INVALID', 'overlay backing directories cannot be symlinks')
        upper.mkdir(parents=True, exist_ok=True); work.mkdir(exist_ok=True)
        self.command(['mount', '-t', 'overlay', 'overlay', '-o',
            f'lowerdir={root},upperdir={upper},workdir={work},userxattr', str(root)])
        self.mounted.append(root)
        try:
            if self.command(['findmnt', '-n', '-T', str(root), '-o', 'FSTYPE']) != 'overlay':
                raise PreparationBlocked('ISOLATION_UNVERIFIED', 'source overlay mount could not be verified')
        except BaseException:
            self.unmount(root)
            raise

    def unmount(self, root):
        root = Path(root).resolve()
        self.command(['umount', str(root)])
        self.mounted.remove(root)


class PreparedCatalog(ProjectCatalog):
    def __init__(self, prepared, projects, provenance):
        super().__init__(prepared.manager.config['source_root'], projects, provenance)
        self.prepared = prepared

    def pin(self, key):
        self.prepared.materialize(key)
        return super().pin(key)


class PreparedCase:
    def __init__(self, manager, task, receipt_path, record, donor_map):
        self.manager, self.task = manager, task
        self.receipt_path, self.record, self.donor_map = Path(receipt_path), record, donor_map
        projects = [Project(**row) for row in record['frozen']['projects']]
        self.catalog = PreparedCatalog(self, projects, record['frozen']['provenance'])
        self.environment = record['environment']
        self.materialized = set(record.get('materialized', []))
        self.mounted = []

    def save(self):
        self.record['materialized'] = sorted(self.materialized)
        write_receipt(self.receipt_path, self.record)

    def materialize(self, key):
        if key in self.materialized:
            return
        project = self.catalog.projects[key]
        self.manager._materialize(project)
        self.materialized.add(key)
        self.save()

    def materialize_all(self):
        try:
            self.manager._check_build_inventory(self)
            for key in sorted(self.catalog.projects, key=lambda value: (value.count('/'), value)):
                if key not in self.materialized:
                    self.manager._materialize(self.catalog.projects[key])
                    self.materialized.add(key)
                    if len(self.materialized) % 25 == 0: self.save()
            self.manager._manifest_files(self.record['frozen'].get('manifest_files', []))
            self.environment['materialized_vector_sha256'] = digest(self.environment['project_pins'])
        finally:
            self.save()
        return self.environment

    @contextmanager
    def validation_view(self, validation_pins):
        if set(validation_pins) != set(self.environment['project_pins']) or any(not SHA.fullmatch(v) for v in validation_pins.values()):
            raise PreparationError('VALIDATION_VECTOR_INVALID', 'validation view requires a complete fixed project vector')
        layer = Path(self.record['layer_root']) / ('validation-' + digest(validation_pins)[:20])
        mounted = []
        try:
            self.manager._check_build_inventory(self)
            for root, name in self.manager._overlay_roots():
                self.manager.overlays.mount(root, layer / name); mounted.append(root)
            for key in sorted(validation_pins, key=lambda value: (value.count('/'), value)):
                self.manager._materialize(replace(self.catalog.projects[key], revision=validation_pins[key]))
            self.manager._manifest_files(self.record['frozen'].get('manifest_files', []))
            environment = {**self.environment, 'project_pins': dict(validation_pins),
                'original_project_pins': dict(self.environment['project_pins']),
                'validation_differences': {key: {'original': self.environment['project_pins'][key], 'validation': sha}
                    for key, sha in validation_pins.items() if sha != self.environment['project_pins'][key]},
                'source_layer': str(layer / 'source'), 'derived_validation_environment': True,
                'target_vector_sha256': digest(validation_pins), 'materialized_vector_sha256': digest(validation_pins)}
            write_receipt(layer / 'environment.json', environment)
            yield environment
        finally:
            try:
                for root in reversed(mounted): self.manager.overlays.unmount(root)
            except BaseException as exc:
                raise PreparationBlocked('ISOLATION_RESTORE_UNVERIFIED', 'validation overlay did not restore') from exc


class PreparationManager:
    def __init__(self, config, *, parent_namespace=None, overlays=None):
        self.config = validate_config(config)
        self.overlays = overlays or LinuxOverlays(parent_namespace)
        self.policy = self.config['preparation']
        self.frozen, self.fetches, self.seconds_used = {}, 0, 0.0
        self.ref_queries, self.ref_advertisements = 0, {}
        self.local_ref_queries, self.remote_ref_queries = 0, 0
        self.active = None
        self.accounting_path = None
        self._git_bin = shutil.which('git')
        if not self._git_bin: raise PreparationBlocked('GIT_UNAVAILABLE', 'Git executable is unavailable')

    def serialized_config(self):
        return self.config

    @classmethod
    def from_saved(cls, config, **kwargs):
        return cls(config, **kwargs)

    def _save_accounting(self, reserved_seconds=0):
        if self.accounting_path:
            write_receipt(self.accounting_path, {'version': 1, 'config_sha256': config_digest(self.config),
                'fetches': self.fetches, 'ref_queries': self.ref_queries,
                'local_ref_queries': self.local_ref_queries, 'remote_ref_queries': self.remote_ref_queries,
                'seconds_used': self.seconds_used, 'reserved_seconds': reserved_seconds})

    def _load_accounting(self, path, *, existing=False):
        self.accounting_path = Path(path).resolve()
        if existing and not self.accounting_path.is_file():
            raise PreparationBlocked('PREPARATION_ACCOUNTING_UNAVAILABLE', 'saved preparation accounting is missing')
        if self.accounting_path.exists():
            state = json.loads(self.accounting_path.read_text())
            if state.get('config_sha256') != config_digest(self.config):
                raise PreparationBlocked('PREPARATION_CONFIG_CHANGED', 'preparation accounting policy changed')
            self.fetches = state['fetches']
            self.ref_queries = state.get('ref_queries', 0)
            self.local_ref_queries = state.get('local_ref_queries', 0)
            self.remote_ref_queries = state.get('remote_ref_queries', self.ref_queries)
            self.seconds_used = state['seconds_used'] + state.get('reserved_seconds', 0)
        self._save_accounting()

    def _resources(self):
        cache = Path(self.config['cache_root']); cache.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(cache).free < self.policy['min_free_bytes']:
            raise PreparationBlocked('DISK_SPACE_LOW', 'shared disk free space is below the configured reserve')
        if self.seconds_used >= self.policy['max_seconds']:
            raise PreparationBlocked('PREPARATION_TIME_LIMIT', 'controller preparation time limit exhausted')

    def _cache_bytes(self):
        total = 0
        for base, directories, files in os.walk(Path(self.config['cache_root']) / 'git', followlinks=False):
            for name in files:
                path = Path(base) / name
                if not path.is_symlink():
                    try: total += path.stat().st_size
                    except FileNotFoundError: pass
        return total

    def _git(self, root, *args, online=False, timeout=None, max_output=32 * 1024 * 1024):
        self._resources()
        if timeout is None:
            timeout = self.policy['local_command_timeout']
        inherited = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        env = offline_git_env(dict(inherited, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                                   GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1'))
        if online:
            # Only this invocation may use HTTPS; model environments remain offline.
            env['GIT_ALLOW_PROTOCOL'] = 'https'
            env.pop('GIT_CONFIG_COUNT', None)
        command = [self._git_bin, '-c', 'core.hooksPath=/dev/null', '-c', 'protocol.allow=never',
                   '-c', 'protocol.https.allow=always' if online else 'protocol.https.allow=never',
                   '-c', 'http.followRedirects=false', '-C', str(root), *args]
        if online:
            # Bound any individual pack/temp file in the fetch subprocess tree.
            command = [sys.executable, '-c', 'import os,resource,sys; n=int(sys.argv[1]); '
                'resource.setrlimit(resource.RLIMIT_FSIZE,(n,n)); os.execv(sys.argv[2],sys.argv[2:])',
                str(self.policy['max_fetch_file_bytes']), *command]
        limit = min(timeout, self.policy['max_seconds'] - self.seconds_used)
        read_budget = ReadBudget(seconds=limit + 5, output_bytes=2 * max_output,
                                 tracks_investigation=False)
        if read_budget.ledger is not None:
            # This controller calls ToolIO directly, outside agent_tools.git's
            # admission path. Claim once before any process or time reservation.
            limit = read_budget.command_timeout(limit)
        started = time.monotonic()
        self._save_accounting(limit)
        cancelled, stopped = threading.Event(), threading.Event()
        resource_failures = []
        def monitor():
            while not stopped.wait(.25):
                try:
                    if self._cache_bytes() > self.policy['max_cache_bytes']:
                        raise PreparationBlocked('CACHE_CAPACITY_EXCEEDED', 'bounded fetch exceeded the managed cache capacity')
                    if shutil.disk_usage(self.config['cache_root']).free < self.policy['min_free_bytes']:
                        raise PreparationBlocked('DISK_SPACE_LOW', 'bounded fetch reached the shared disk reserve')
                except BaseException as exc:
                    resource_failures.append(exc); cancelled.set(); return
        watcher = threading.Thread(target=monitor, daemon=True) if online else None
        if watcher: watcher.start()
        io = ToolIO(read_budget, cancelled, started + limit + 1, max_output=max_output)
        try:
            result = io.run(command, env=env, timeout=limit, check=False)
            if resource_failures: raise resource_failures[0]
            return result
        except subprocess.TimeoutExpired as exc:
            raise PreparationError('PREPARATION_TIMEOUT', 'bounded Git preparation command timed out') from exc
        except BaseException:
            if resource_failures: raise resource_failures[0]
            raise
        finally:
            stopped.set()
            if watcher: watcher.join(timeout=5)
            self.seconds_used += time.monotonic() - started
            self._save_accounting()

    def _allowed(self, origin):
        origin = safe_origin(origin)
        if not any(origin == prefix or origin.startswith(prefix + '/') for prefix in self.config['allowed_upstreams']):
            raise PreparationError('UPSTREAM_NOT_ALLOWED', 'upstream is outside configured HTTPS origins')
        return origin

    def _store(self, origin, original=None, *, role='donor'):
        self._allowed(origin)
        # Donor alternates may ultimately point into the shared source tree.
        # Target checkouts must never point back to such a donor cache.
        if role not in ('donor', 'target', 'manifest'): raise ValueError('invalid managed store role')
        root = Path(self.config['cache_root']) / 'git' / (role + '-' + hashlib.sha256(origin.encode()).hexdigest() + '.git')
        root.parent.mkdir(parents=True, exist_ok=True)
        with (root.parent / (root.name + '.lock')).open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if not root.exists():
                root.mkdir()
                if self._git(root, 'init', '--bare', '-q').returncode:
                    raise PreparationError('CACHE_INITIALIZATION_FAILED', 'could not initialize local object cache')
            if (root / 'objects/info/alternates').exists():
                raise PreparationBlocked('CACHE_NOT_INDEPENDENT', 'managed snapshot cache may not borrow source objects')
        return root

    def _fetch(self, store, origin, revision, *, refetch=False):
        started = time.monotonic()
        origin = self._allowed(origin)
        if not self.policy['allow_fetch']:
            raise PreparationError('OBJECTS_UNAVAILABLE', 'required objects are missing and controller fetch is disabled')
        if self.fetches >= self.policy['max_fetches']:
            raise PreparationBlocked('FETCH_LIMIT', 'bounded controller fetch count exhausted')
        if self._cache_bytes() >= self.policy['max_cache_bytes']:
            raise PreparationBlocked('CACHE_CAPACITY_EXCEEDED', 'managed object cache has reached its configured size limit')
        self.fetches += 1
        self._save_accounting()
        if refetch:
            # Git 2.34 (supported hosts) has no --refetch. A fresh bare store
            # advertises no existing commit, so missing blobs cannot be skipped
            # by negotiation. Import only the fixed snapshot afterward.
            with tempfile.TemporaryDirectory(prefix='acquire-', suffix='.git', dir=store.parent) as temporary:
                acquired = Path(temporary)
                if self._git(acquired, 'init', '--bare', '-q').returncode:
                    raise PreparationError('CACHE_INITIALIZATION_FAILED', 'temporary acquisition store initialization failed')
                result = self._git(acquired, 'fetch', '--no-tags', '--depth=1', origin, revision,
                                   online=True, timeout=self.policy['fetch_timeout'])
                self._fetch_result(result)
                resolved = self._git(acquired, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}').stdout.strip()
                if not SHA.fullmatch(resolved) or SHA.fullmatch(revision) and resolved != revision:
                    raise PreparationError('OBJECT_ID_MISMATCH', 'upstream supplied a different fixed commit')
                self._import_snapshot(acquired, store, resolved)
        else:
            with (store.parent / (store.name + '.lock')).open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                result = self._git(store, 'fetch', '--no-tags', '--depth=1', origin, revision, online=True,
                                   timeout=self.policy['fetch_timeout'])
            self._fetch_result(result)
        if self._cache_bytes() > self.policy['max_cache_bytes']:
            raise PreparationBlocked('CACHE_CAPACITY_EXCEEDED', 'managed object cache exceeds its configured size limit')
        acquired = resolved if refetch else self._git(store, 'rev-parse', '--verify', 'FETCH_HEAD^{commit}').stdout.strip()
        write_receipt(store / ('acquisition-' + hashlib.sha256(revision.encode()).hexdigest() + '.json'), {
            'origin': origin, 'requested_revision': revision, 'resolved_commit': acquired,
            'scope': 'controller_bounded_https', 'seconds': time.monotonic() - started,
            'fetch_number': self.fetches, 'fetch_limit': self.policy['max_fetches'],
            'timeout': self.policy['fetch_timeout'], 'file_byte_limit': self.policy['max_fetch_file_bytes'],
            'temporary_store_removed': bool(refetch)})
        self._resources()
        return acquired

    @staticmethod
    def _fetch_result(result):
        if result.returncode:
            error = result.stderr.lower()
            if any(term in error for term in ('authentication failed', 'could not read username', 'http 401', 'returned error: 401')):
                raise PreparationBlocked('UPSTREAM_CREDENTIALS_UNAVAILABLE', 'configured upstream credentials are unavailable')
            if 'no space left' in error or 'disk quota exceeded' in error:
                raise PreparationBlocked('DISK_SPACE_LOW', 'object preparation ran out of shared disk space')
            # Do not persist credentials or server response bodies. Preserve a
            # stable transport category for controller diagnostics/retries.
            if 'unknown option' in error: detail = 'unsupported Git option'
            elif 'could not resolve' in error: detail = 'DNS resolution failed'
            elif 'could not connect' in error or 'failed to connect' in error: detail = 'connection failed'
            elif 'certificate' in error: detail = 'TLS certificate verification failed'
            elif 'not our ref' in error or 'couldn\'t find remote ref' in error: detail = 'requested object/ref unavailable'
            elif 'file size limit' in error: detail = 'fetch file-size limit reached'
            else: detail = 'Git fetch returned an error'
            raise PreparationError('OBJECT_FETCH_FAILED', 'allowed upstream did not supply required objects: ' + detail)

    def _resolve(self, store, revision, origin, original=None):
        if original and Path(original).is_dir():
            local = self._git(original, 'rev-parse', '--verify', revision + '^{commit}')
            if local.returncode == 0 and SHA.fullmatch(local.stdout.strip()):
                return local.stdout.strip()
        result = self._git(store, 'rev-parse', '--verify', revision + '^{commit}')
        if result.returncode == 0 and SHA.fullmatch(result.stdout.strip()): return result.stdout.strip()
        resolved = self._fetch(store, origin, revision)
        if not SHA.fullmatch(resolved):
            raise PreparationError('OBJECTS_UNAVAILABLE', 'fetch did not resolve the requested commit')
        if SHA.fullmatch(revision) and resolved != revision:
            raise PreparationError('OBJECT_ID_MISMATCH', 'fetched commit differs from requested object ID')
        return resolved

    def _advertise(self, origin, revision, memo, original=None):
        """Pin one observed name without acquiring any project objects.

        Prefer an origin-matched checkout's local snapshot, then remote metadata.
        IDs are not proof of object type or snapshot completeness. Only one
        freeze owns this memo; new batches observe the references again.
        """
        origin = self._allowed(origin)
        if (not isinstance(revision, str) or len(revision) > 1024
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]*', revision)
                or '..' in revision or '//' in revision
                or any(part.startswith('.') or part.endswith(('.', '.lock')) for part in revision.split('/'))
                or revision.endswith('/') or revision == 'HEAD'):
            raise PreparationError('TARGET_REF_INVALID', 'target revision must name one branch or tag')
        if revision.startswith('refs/'):
            if not revision.startswith(('refs/heads/', 'refs/tags/')):
                raise PreparationError('TARGET_REF_INVALID', 'only branch and tag references are supported')
            names = [revision]
        else:
            names = ['refs/heads/' + revision, 'refs/tags/' + revision]
        key = (origin, revision)
        if key in memo:
            if isinstance(memo[key], PreparationError): raise memo[key]
            return memo[key]
        try:
            local = self._local_ref(original, origin, revision, names) if original is not None else None
            memo[key] = local if local is not None else self._query_ref(origin, revision, names)
        except PreparationError as exc:
            memo[key] = exc
            raise
        return memo[key]

    def _claim_ref_query(self, source):
        self._resources()
        if self.ref_queries >= self.policy['max_ref_queries']:
            raise PreparationBlocked('REF_QUERY_LIMIT', 'bounded controller reference query count exhausted')
        self.ref_queries += 1
        if source == 'local': self.local_ref_queries += 1
        else: self.remote_ref_queries += 1
        self._save_accounting()

    @staticmethod
    def _origin_identity(value):
        parsed = urlsplit(safe_origin(value))
        path = parsed.path.rstrip('/')
        if path.endswith('.git'): path = path[:-4]
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or 443, path

    def _local_ref(self, original, origin, revision, names):
        """Read only the declared checkout's metadata, never a borrowed cache.

        Enumerating names must not require their objects: a dangling branch may
        still make a short name ambiguous with a tag. Peeling is a separate,
        offline, bounded operation, and its result remains type-unverified.
        """
        root = Path(self.config['source_root'])
        repo = Path(original).absolute()
        if not repo.is_relative_to(root) or repo.resolve() != repo or not repo.is_dir(): return None
        entry = repo / '.git'
        if not os.path.lexists(entry) or not entry.resolve().is_relative_to(root): return None
        try:
            if entry.is_dir():
                metadata = entry.resolve()
            else:
                with entry.open('rb') as stream: data = stream.read(4097)
                if len(data) > 4096 or not data.startswith(b'gitdir: '): return None
                metadata = (repo / data[8:].decode().strip()).resolve()
            if not metadata.is_relative_to(root): return None
            common = metadata
            common_file = metadata / 'commondir'
            if common_file.exists():
                if not common_file.resolve().is_relative_to(root): return None
                with common_file.open('rb') as stream: data = stream.read(4097)
                if len(data) > 4096: return None
                common = (metadata / data.decode().strip()).resolve()
                if not common.is_relative_to(root): return None
            if any(not path.resolve().is_relative_to(root) for path in
                   (metadata / 'config', common / 'config', metadata / 'config.worktree')): return None
        except (OSError, UnicodeError):
            return None
        self._claim_ref_query('local')
        started = time.monotonic()
        timeout, output_limit = 3, 64 * 1024
        def query(*args):
            return self._git(repo, *args, timeout=timeout, max_output=output_limit)
        try:
            configured = query('config', '--local', '--get-regexp', r'^remote\..*\.url$')
            matched = []
            if configured.returncode == 0:
                for line in configured.stdout.splitlines():
                    field, separator, url = line.partition(' ')
                    try:
                        if separator and self._origin_identity(url) == self._origin_identity(origin): matched.append(field)
                    except ValueError: pass
            if not matched: return None
            listing = query('for-each-ref', '--format=%(objectname)%09%(refname)', '--', *names)
            references = {}
            for line in listing.stdout.splitlines():
                fields = line.split('\t')
                if len(fields) != 2 or not SHA.fullmatch(fields[0]): return None
                oid, name = fields
                if name not in names: continue  # for-each-ref also matches descendants.
                if name in references and references[name] != oid:
                    raise PreparationError('TARGET_REF_AMBIGUOUS', 'local reference has conflicting object IDs')
                references[name] = oid
            if len(references) > 1:
                raise PreparationError('TARGET_REF_AMBIGUOUS', 'local branch and tag share this name; use an exact reference')
            if listing.returncode or len(references) != 1: return None
            name, oid = next(iter(references.items()))
            peeled = None
            output_bytes = len(configured.stdout.encode()) + len(listing.stdout.encode())
            if name.startswith('refs/tags/'):
                result = query('show-ref', '--dereference', '--verify', '--', name)
                if result.returncode: return None
                output_bytes += len(result.stdout.encode())
                observed = {}
                for line in result.stdout.splitlines():
                    fields = line.split()
                    if len(fields) != 2 or not SHA.fullmatch(fields[0]) or fields[1] not in (name, name + '^{}'): return None
                    if fields[1] in observed and observed[fields[1]] != fields[0]: return None
                    observed[fields[1]] = fields[0]
                if observed.get(name) != oid: return None
                peeled = observed.get(name + '^{}')
        except QueryOutputLimit:
            return None
        except PreparationError as exc:
            if exc.kind == 'PREPARATION_TIMEOUT': return None
            raise
        pin = peeled or oid
        ident = digest({'origin': origin, 'revision': revision})
        self.ref_advertisements[ident] = {'origin': origin, 'requested_revision': revision,
            'advertised_ref': name, 'advertised_oid': oid, 'peeled_oid': peeled, 'resolved_oid': pin,
            'object_type': 'UNVERIFIED', 'snapshot_complete': False, 'method': 'git_local_ref_exact',
            'local_source': str(repo), 'local_git_dir': str(metadata), 'matched_remote_fields': sorted(matched),
            'origin_basis': 'matching_local_remote_url', 'freshness': 'local_snapshot_observed_at_freeze',
            'query_number': self.ref_queries, 'timeout_per_command': timeout, 'output_limit_per_command': output_limit,
            'output_bytes': output_bytes, 'seconds': time.monotonic() - started, 'observed_at': time.time()}
        return pin, ident

    def _query_ref(self, origin, revision, names):
        if not self.policy['allow_fetch']:
            raise PreparationError('TARGET_REF_UNAVAILABLE', 'no reliable local target ref and upstream queries are disabled')
        self._claim_ref_query('remote')
        patterns = [name for base in names for name in
                    ([base, base + '^{}'] if base.startswith('refs/tags/') else [base])]
        started = time.monotonic()
        timeout, output_limit = min(30, self.policy['fetch_timeout']), 64 * 1024
        try:
            result = self._git(self.config['cache_root'], 'ls-remote', '--exit-code', '--', origin, *patterns,
                               online=True, timeout=timeout, max_output=output_limit)
        except QueryOutputLimit as exc:
            raise PreparationError('TARGET_REF_OUTPUT_LIMIT', 'remote reference advertisement exceeded its metadata bound') from exc
        if result.returncode == 2 and not result.stdout.strip():
            raise PreparationError('TARGET_REF_UNAVAILABLE', 'allowed upstream did not advertise the exact target reference')
        self._fetch_result(result)
        advertised = {}
        for line in result.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) != 2 or not SHA.fullmatch(fields[0]) or fields[1] not in patterns:
                raise PreparationError('TARGET_REF_INVALID', 'upstream returned an unexpected reference advertisement')
            oid, name = fields
            if name in advertised and advertised[name] != oid:
                raise PreparationError('TARGET_REF_AMBIGUOUS', 'upstream advertised conflicting IDs for one reference')
            advertised[name] = oid
        selected = [name for name in names if name in advertised]
        if (len(selected) != 1 or any(name.endswith('^{}') and name[:-3] not in advertised for name in advertised)):
            raise PreparationError('TARGET_REF_AMBIGUOUS' if advertised else 'TARGET_REF_UNAVAILABLE',
                                   'target reference is missing or ambiguous; use an exact branch or tag name')
        name = selected[0]
        pin = advertised.get(name + '^{}', advertised[name])
        receipt = {'origin': origin, 'requested_revision': revision, 'advertised_ref': name,
            'advertised_oid': advertised[name], 'peeled_oid': advertised.get(name + '^{}'), 'resolved_oid': pin,
            'object_type': 'UNVERIFIED', 'snapshot_complete': False, 'method': 'git_ls_remote_exact',
            'query_number': self.ref_queries, 'timeout': timeout, 'output_limit': output_limit,
            'output_bytes': len(result.stdout.encode()) + len(result.stderr.encode()),
            'seconds': time.monotonic() - started, 'observed_at': time.time()}
        ident = digest({'origin': origin, 'revision': revision})
        self.ref_advertisements[ident] = receipt
        return pin, ident

    def _import_snapshot(self, original, store, commit):
        from .object_snapshot import import_snapshot, SnapshotImportError
        self._resources()
        limit = min(self.policy['fetch_timeout'], self.policy['max_seconds'] - self.seconds_used)
        remaining = self.policy['max_cache_bytes'] - self._cache_bytes()
        if remaining <= 0: raise PreparationBlocked('CACHE_CAPACITY_EXCEEDED', 'managed cache is full')
        self._save_accounting(limit)
        started = time.monotonic()
        try:
            receipt = import_snapshot(original, store, [commit],
                max_bytes=min(self.policy['max_fetch_file_bytes'], remaining), timeout=limit,
                min_free_bytes=self.policy['min_free_bytes'])
            write_receipt(store / ('snapshot-' + commit + '.json'), receipt)
        except SnapshotImportError as exc:
            if 'disk' in str(exc): raise PreparationBlocked('DISK_SPACE_LOW', str(exc)) from exc
            raise PreparationError('OBJECT_SNAPSHOT_IMPORT_FAILED', str(exc)) from exc
        finally:
            self.seconds_used += time.monotonic() - started
            self._save_accounting()

    def _snapshot(self, store, commit, origin, original=None):
        if not self._complete(store, commit):
            if original and Path(original).is_dir() and self._complete(original, commit):
                self._import_snapshot(original, store, commit)
            else:
                self._fetch(store, origin, commit, refetch=True)
            if not self._complete(store, commit): raise PreparationError('OBJECTS_UNAVAILABLE', 'fixed commit tree or blobs remain unavailable')

    def _complete(self, store, commit):
        result = self._git(store, 'rev-list', '--objects', '--no-object-names', '--missing=print', '--no-walk', commit)
        return result.returncode == 0 and not any(line.startswith('?') for line in result.stdout.splitlines())

    def _read_manifest_files(self, store, commit, catalog):
        """Retain versioned repo copy/link directives needed by the full view."""
        operations, destinations = [], set()
        def project(node, parent_name='', parent_path=''):
            name = '/'.join(filter(None, (parent_name, node.attrib['name'])))
            path = '/'.join(filter(None, (parent_path, node.get('path', node.attrib['name']))))
            matches = [p for p in catalog.projects.values() if p.name == name]
            exact = [p for p in matches if p.key == path]
            selected = exact or matches
            for item in node:
                if item.tag == 'project': project(item, name, path)
                elif item.tag in ('copyfile', 'linkfile') and selected:
                    if len(selected) != 1:
                        raise PreparationError('MANIFEST_FILES_UNSUPPORTED', 'ambiguous manifest copy/link owner')
                    src, dest = item.attrib['src'], validate_relative_path(item.attrib['dest'])
                    if src != '.': validate_relative_path(src)
                    if any(char in src for char in '*?[') or dest in destinations:
                        raise PreparationError('MANIFEST_FILES_UNSUPPORTED', 'wildcard or duplicate manifest file destination')
                    destinations.add(dest)
                    operations.append({'kind': item.tag, 'project': selected[0].key, 'src': src, 'dest': dest})
        def document(name, stack=()):
            name = validate_relative_path(name)
            if name in stack or len(stack) >= 32:
                raise PreparationError('MANIFEST_FILES_UNSUPPORTED', 'manifest include cycle')
            result = self._git(store, 'show', '--no-ext-diff', '--no-textconv', commit + ':' + name)
            if result.returncode: raise PreparationError('MANIFEST_FILES_UNAVAILABLE', 'fixed manifest file missing')
            for node in ET.fromstring(result.stdout):
                if node.tag == 'include': document(node.attrib['name'], (*stack, name))
                elif node.tag == 'project': project(node)
        document(self.config['manifest_name'])
        return operations

    def _manifest_files(self, operations):
        if self.active is None: raise PreparationBlocked('ISOLATION_INACTIVE', 'manifest files need an active overlay')
        self.overlays.check_namespace()
        root = Path(self.config['source_root'])
        for operation in operations:
            repository = root / validate_relative_path(operation['project'])
            source = repository / operation['src']
            destination = root / validate_relative_path(operation['dest'])
            if (not source.resolve().is_relative_to(repository) or not source.exists()
                    or not destination.parent.resolve().is_relative_to(root)
                    or destination.parent.resolve() != destination.parent):
                raise PreparationError('MANIFEST_FILES_UNAVAILABLE', 'manifest copy/link path escapes the fixed view')
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_dir() and not destination.is_symlink():
                raise PreparationError('MANIFEST_FILES_UNAVAILABLE', 'manifest copy/link destination is a directory')
            if operation['kind'] == 'linkfile':
                destination.unlink(missing_ok=True)
                destination.symlink_to(os.path.relpath(source, destination.parent))
            else:
                if not source.is_file() or source.stat().st_size > 32 * 1024 * 1024:
                    raise PreparationError('MANIFEST_FILES_UNAVAILABLE', 'manifest copyfile exceeds its file bound')
                fd = os.open(source.resolve(), os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise PreparationError('MANIFEST_FILES_UNAVAILABLE', 'manifest source is not a regular file')
                    content = stream.read(32 * 1024 * 1024 + 1)
                if len(content) > 32 * 1024 * 1024:
                    raise PreparationError('MANIFEST_FILES_UNAVAILABLE', 'manifest copyfile grew past its file bound')
                destination.unlink(missing_ok=True)
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, info.st_mode & 0o777)
                with os.fdopen(fd, 'wb') as stream: stream.write(content)

    def _check_build_inventory(self, prepared):
        from .build_environment import BuildEnvironmentBlocked
        root = Path(self.config['source_root'])
        listed = root / '.repo/project.list'
        if listed.is_file():
            with listed.open('rb') as stream: raw = stream.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise BuildEnvironmentBlocked('checkout inventory exceeds the metadata bound')
            paths = {validate_relative_path(line) for line in raw.decode().splitlines() if line.strip()}
        else:
            from .project_catalog import catalog_from_checkout
            try:
                checkout = catalog_from_checkout(root)
                if checkout is None: raise ValueError('missing effective checkout manifest')
                paths = set(checkout.projects)
            except (ValueError, subprocess.SubprocessError) as exc:
                raise BuildEnvironmentBlocked('shared checkout inventory is unavailable') from exc
        extra = sorted(paths - set(prepared.catalog.projects))
        prepared.environment['extra_projects'] = extra
        if extra:
            prepared.environment['profile_gaps'] = ['uncontrolled_checkouts_outside_target_manifest']
            prepared.save()
            raise BuildEnvironmentBlocked('shared checkout contains projects outside the fixed manifest: ' + ', '.join(extra[:20]))
        prepared.environment['profile_gaps'] = []

    def freeze_inputs(self, lines, run_dir, *, frozen_receipt=None, accounting_root=None, require_existing=False):
        """Freeze all named manifest/branch refs once, before running any model."""
        path = Path(frozen_receipt).resolve() if frozen_receipt else Path(run_dir) / 'preparation-frozen.json'
        accounting = Path(accounting_root).resolve() if accounting_root is not None else path.parent
        self._load_accounting(accounting / 'preparation-budget.json', existing=require_existing or path.exists())
        input_digest = digest(lines)
        if path.exists():
            saved = json.loads(path.read_text())
            if saved['config_sha256'] != config_digest(self.config) or saved.get('input_sha256') != input_digest:
                raise PreparationBlocked('PREPARATION_CONFIG_CHANGED', 'preparation policy differs from saved batch')
            self.frozen = saved['revisions']
            self.freeze_errors = saved.get('errors', {})
            self.ref_advertisements = saved.get('ref_advertisements', {})
            return str(path)
        errors = {}
        ref_memo = {}
        for number, line in lines:
            try: task = RuntimeInput.parse(json.loads(line))
            except (ValueError, TypeError): continue  # Existing batch preserves invalid rows.
            if task.target_revision in self.frozen or task.target_revision in errors: continue
            try:
                source = Path(self.config['source_root'])
                original = source / '.repo/manifests'
                origin = self.config['manifest_origin']
                store = self._store(origin, original, role='manifest')
                commit = self._resolve(store, task.target_revision, origin, original)
                self._snapshot(store, commit, origin, original)
                catalog = catalog_at_revision(source, commit, manifest_repo=store, manifest_name=self.config['manifest_name'])
                manifest_files = self._read_manifest_files(store, commit, catalog)
                projects, ref_receipts = [], {}
                for project in catalog.projects.values():
                    if SHA.fullmatch(project.revision):
                        pin = project.revision
                    else:
                        url = project_origin(origin, project)
                        pin, reference = self._advertise(url, project.revision, ref_memo, original=source / project.key)
                        ref_receipts[project.key] = reference
                    projects.append(asdict(replace(project, revision=pin)))
                provenance = {**catalog.provenance, 'requested_revision': task.target_revision,
                    'target_policy': 'complete_vector_frozen_before_batch', 'manifest_store': str(store),
                    'manifest_origin': origin, 'manifest_file_operations_sha256': digest(manifest_files),
                    'target_ref_receipts': ref_receipts, 'ref_advertisements_file': str(path),
                    'target_object_verification': 'DEFERRED_UNTIL_MATERIALIZATION'}
                self.frozen[task.target_revision] = {'projects': projects, 'provenance': provenance,
                                                   'manifest_files': manifest_files}
            except PreparationError as exc:
                errors[task.target_revision] = {'kind': exc.kind, 'message': str(exc)}
            except (ValueError, subprocess.SubprocessError) as exc:
                errors[task.target_revision] = {'kind': 'TARGET_MANIFEST_INVALID', 'message': str(exc)[:1000]}
        self.freeze_errors = errors
        write_receipt(path, {'version': 1, 'config_sha256': config_digest(self.config), 'input_sha256': input_digest,
                            'revisions': self.frozen, 'errors': errors,
                            'ref_advertisements': self.ref_advertisements})
        return str(path)

    def _overlay_roots(self):
        result = [(self.config['source_root'], 'source')]
        build = self.config.get('build', {})
        if build.get('enabled'):
            for key in ('output_root', 'tmp_root'):
                if build.get(key): result.append((build[key], key))
        return result

    def _activate(self, prepared):
        if self.active is not None: raise PreparationBlocked('ISOLATION_BUSY', 'another case overlay is still active')
        try:
            for root, name in self._overlay_roots():
                if name != 'source': Path(root).mkdir(parents=True, exist_ok=True)
                self.overlays.mount(root, Path(prepared.record['layer_root']) / name)
                prepared.mounted.append(root)
            self.active = prepared
            prepared.record.update(state='ACTIVE', process_id=os.getpid(), mount_namespace=os.readlink('/proc/self/ns/mnt') if sys.platform == 'linux' else 'test')
            prepared.save()
        except BaseException:
            try:
                for root in reversed(prepared.mounted): self.overlays.unmount(root)
            except BaseException as exc:
                raise PreparationBlocked('ISOLATION_RESTORE_UNVERIFIED', 'failed preparation left an active overlay') from exc
            prepared.mounted.clear()
            self.active = None
            raise

    def prepare(self, task, row_dir):
        if task.target_revision not in self.frozen:
            error = getattr(self, 'freeze_errors', {}).get(task.target_revision, {})
            raise PreparationError(error.get('kind', 'TARGET_REVISION_UNAVAILABLE'), error.get('message', 'target manifest could not be frozen'))
        frozen = self.frozen[task.target_revision]
        donor_map = {}
        for donor in task.donors:
            origin = donor if '://' in donor else 'https://android.googlesource.com/' + project_name(donor)
            original = donor_path(donor, self.config['donor_root'], self.config['donor_map'])
            store = self._store(origin, original)
            donor_map[donor] = str(store)
            for revision in (*task.commits, *task.parents):
                try:
                    commit = self._resolve(store, revision, origin, original)
                    self._snapshot(store, commit, origin, original)
                except PreparationError:
                    pass  # Other donors may own this commit; resolve_sources checks every pair.
        resolution = resolve_sources(task, self.config['donor_root'], donor_map=donor_map)
        if resolution['status'] != 'READY':
            raise PreparationError('SOURCE_OBJECTS_UNAVAILABLE', 'one or more supplied donor commit/parent pairs remain unavailable')
        row_dir = Path(row_dir).resolve()
        layer = Path(self.config['isolation_root']) / hashlib.sha256(str(row_dir).encode()).hexdigest()
        pins = {project['key']: project['revision'] for project in frozen['projects']}
        environment = {'manifest': frozen['provenance'], 'project_pins': pins,
            'manifest_files': frozen.get('manifest_files', []),
            'source_root': self.config['source_root'], 'source_layer': str(layer / 'source'),
            'output_root': self.config.get('build', {}).get('output_root'),
            'tmp_root': self.config.get('build', {}).get('tmp_root'),
            'output_layer': str(layer / 'output_root'), 'target_vector_sha256': digest(pins)}
        record = {'version': 1, 'input_task_id': task.task_id, 'target_revision': task.target_revision,
            'config_sha256': config_digest(self.config), 'frozen': frozen, 'donor_map': donor_map,
            'preparation_accounting': str(self.accounting_path) if self.accounting_path else None,
            'layer_root': str(layer), 'environment': environment, 'state': 'PREPARED', 'materialized': []}
        prepared = PreparedCase(self, task, row_dir / 'preparation.json', record, donor_map)
        prepared.save()
        self._activate(prepared)
        return prepared

    def _materialize(self, project):
        if self.active is None: raise PreparationBlocked('ISOLATION_INACTIVE', 'target checkout requires an active private view')
        self.overlays.check_namespace()
        root = Path(self.config['source_root'])
        repo = root / validate_relative_path(project.key)
        if not repo.resolve().is_relative_to(root) or repo.resolve() != repo:
            raise PreparationBlocked('SOURCE_PATH_OUTSIDE_ISOLATION', 'target project path uses a symlink or escapes the source overlay')
        origin = project_origin(self.config['manifest_origin'], project)
        self._allowed(origin)
        complete = repo.is_dir() and os.path.lexists(repo / '.git') and self._complete(repo, project.revision)
        store = None
        if not complete:
            # No source->cache->source alternate cycle: target caches own fetched
            # objects; only the isolated checkout points into that cache.
            store = self._store(origin, role='target')
            self._snapshot(store, project.revision, origin)
        kind = self._git(store if store is not None else repo, 'cat-file', '-t', project.revision)
        if kind.returncode or kind.stdout.strip() != 'commit':
            raise PreparationError('TARGET_OBJECT_NOT_COMMIT', 'fixed target object is not a commit: ' + project.key)
        repo.mkdir(parents=True, exist_ok=True)
        if not os.path.lexists(repo / '.git'):
            result = self._git(repo, 'init', '-q')
            if result.returncode: raise PreparationError('TARGET_CHECKOUT_FAILED', 'could not initialize isolated project')
        metadata = self._git(repo, 'rev-parse', '--absolute-git-dir')
        git_dir = Path(metadata.stdout.strip()).resolve()
        if metadata.returncode or not git_dir.is_relative_to(root):
            raise PreparationBlocked('GIT_METADATA_OUTSIDE_ISOLATION', 'target Git metadata escapes the source overlay')
        status = self._git(repo, '-c', 'core.fsmonitor=false', 'status', '--porcelain=v1', '--untracked-files=normal')
        if status.returncode or status.stdout:
            raise PreparationError('TARGET_BASELINE_DIRTY', 'isolated target project contains preexisting changes: ' + project.key)
        if store is not None:
            alternate = git_dir / 'objects/info/alternates'
            alternate.parent.mkdir(parents=True, exist_ok=True)
            existing = alternate.read_text().splitlines() if alternate.exists() else []
            entry = str(store / 'objects')
            if entry not in existing: alternate.write_text('\n'.join([*existing, entry]) + '\n')
        head = self._git(repo, 'rev-parse', '--verify', 'HEAD')
        if head.stdout.strip() != project.revision:
            result = self._git(repo, 'switch', '--no-overwrite-ignore', '--detach', project.revision, timeout=120)
            if result.returncode: raise PreparationError('TARGET_CHECKOUT_FAILED', 'fixed isolated target could not be checked out: ' + project.key)
        if self._git(repo, 'rev-parse', 'HEAD').stdout.strip() != project.revision:
            raise PreparationError('TARGET_PIN_MISMATCH', 'prepared target does not match the fixed manifest')

    def release(self, prepared):
        try:
            for root in reversed(prepared.mounted): self.overlays.unmount(root)
            prepared.mounted.clear()
        except BaseException as exc:
            prepared.record.update(state='RESTORE_BLOCKED', restoration='UNVERIFIED')
            prepared.save()
            raise PreparationBlocked('ISOLATION_RESTORE_UNVERIFIED', 'case overlay could not be unmounted cleanly') from exc
        prepared.record.update(state='RELEASED', restoration='PASS')
        prepared.save()
        self.active = None

    @contextmanager
    def activate_receipt(self, path):
        path = Path(path).resolve()
        record = json.loads(path.read_text())
        if record.get('version') != 1 or record.get('config_sha256') != config_digest(self.config):
            raise PreparationBlocked('PREPARATION_CONFIG_CHANGED', 'saved isolation receipt is incompatible')
        layer = Path(record['layer_root']).resolve()
        expected = Path(self.config['isolation_root']) / hashlib.sha256(str(path.parent).encode()).hexdigest()
        if layer != expected or record['environment']['source_root'] != self.config['source_root']:
            raise PreparationBlocked('ISOLATION_RECEIPT_INVALID', 'saved layer is outside configured isolation root')
        prepared = PreparedCase(self, None, path, record, record['donor_map'])
        if record.get('preparation_accounting'):
            accounting = Path(record['preparation_accounting']).resolve()
            if not accounting.is_relative_to(Path(self.config['run_root'])):
                raise PreparationBlocked('ISOLATION_RECEIPT_INVALID', 'preparation accounting escapes run root')
            self._load_accounting(accounting, existing=True)
        self._activate(prepared)
        try:
            yield prepared
        finally:
            self.release(prepared)
