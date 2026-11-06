"""Process-backed run leases and graceful cancellation; stale JSON is not liveness."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
import fcntl
import inspect
import json
import os
from pathlib import Path
import signal
import threading
import uuid


class LeaseBusy(RuntimeError):
    """An active task is a scheduling barrier, never an ordinary row failure."""


class RecoveryBlocked(ValueError):
    """Prior source restoration has not been established."""


@dataclass
class Lease:
    path: Path
    stream: object
    pid: int
    root: Path | None = None

    def require(self, *, path=None, root=None):
        if self.pid != os.getpid() or self.stream.closed:
            raise LeaseBusy('lease ownership expired')
        if path is not None and self.path != path:
            raise LeaseBusy('run lease belongs to a different task')
        if root is not None and (self.root is None or not root.is_relative_to(self.root)):
            raise LeaseBusy('source lease does not cover the requested tree')


ACTIVE_SOURCE_LEASE = ContextVar('aosp_source_lease', default=None)
_SOURCE_OPERATIONS = ContextVar('aosp_source_operations', default=())
SOURCE_LEASE_FD = 'AOSP_AGENT_SOURCE_LEASE_FD'


def operation_lease(owner):
    """Only methods on the same active controller inherit implicitly.

    A different controller must explicitly receive the lease. Context-local
    ownership also prevents another thread using the same object from bypassing
    the process-backed source barrier.
    """
    return next((lease for current, lease in reversed(_SOURCE_OPERATIONS.get())
                 if current is owner), None)


def source_guard(root_name):
    """Guard a public execution operation, including constructor source reads.

    Internal serial callers may pass the private ``_source_lease`` keyword.
    It is consumed here, validated by source_lease, and never serialized.
    """
    def decorate(method):
        signature = inspect.signature(method)
        @wraps(method)
        def guarded(self, *args, **kwargs):
            inherited = kwargs.pop('_source_lease', None) or operation_lease(self)
            arguments = signature.bind(self, *args, **kwargs).arguments
            root = arguments[root_name] if root_name in arguments else getattr(self, root_name)
            with source_lease(root, inherited) as lease:
                token = _SOURCE_OPERATIONS.set((*_SOURCE_OPERATIONS.get(), (self, lease)))
                try:
                    return method(self, *args, **kwargs)
                finally:
                    _SOURCE_OPERATIONS.reset(token)
        return guarded
    return decorate


class RunCancelled(KeyboardInterrupt):
    pass


@contextmanager
def cancellation_signals():
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous, stopping = {}, False
    def stop(signum, _frame):
        nonlocal stopping
        if stopping:
            return  # Let process/transaction cleanup finish after the first signal.
        stopping = True
        raise RunCancelled(f'cancelled by signal {signum}')
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, stop)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextmanager
def run_lease(run_dir, inherited=None):
    path = Path(run_dir).resolve() / 'run.lock'
    if inherited is not None:
        inherited.require(path=path)
        yield inherited
        return
    with path.open('a+') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LeaseBusy('run is already active; refusing concurrent execution') from exc
        stream.seek(0); stream.truncate(); stream.write(str(os.getpid())); stream.flush()
        try:
            yield Lease(path, stream, os.getpid())
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


@contextmanager
def _registry_guard():
    # One local registry per OS user, independent of task/run/cache directories.
    # Resolve source paths before comparing, including parent/child roots.
    directory = Path('/tmp') / f'aosp-agent-source-leases-{os.getuid()}'
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != os.getuid():
        raise LeaseBusy('unsafe source lease registry')
    with (directory / 'registry.lock').open('a+') as guard:
        fcntl.flock(guard, fcntl.LOCK_EX)
        yield directory


def _live_root(path):
    with path.open('r+') as existing:
        try:
            fcntl.flock(existing, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return Path(json.load(existing)['root'])
        path.unlink()  # Stale entries are removed only while holding registry.lock.
        return None


@contextmanager
def source_lease(root, inherited=None):
    root = Path(root).resolve()
    if inherited is not None:
        inherited.require(root=root)
        token = ACTIVE_SOURCE_LEASE.set(inherited)
        try:
            yield inherited
        finally:
            ACTIVE_SOURCE_LEASE.reset(token)
        return
    with _registry_guard() as directory:
        for path in directory.glob('source-*.lock'):
            active = _live_root(path)
            if active and (root.is_relative_to(active) or active.is_relative_to(root)):
                raise LeaseBusy('source tree is already active; refusing overlapping execution')
        path = directory / ('source-' + uuid.uuid4().hex + '.lock')
        stream = path.open('x+')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stream.write(json.dumps({'kind': 'source_lease', 'root': str(root), 'pid': os.getpid()}))
        stream.flush()
    lease = Lease(path, stream, os.getpid(), root)
    token = ACTIVE_SOURCE_LEASE.set(lease)
    try:
        yield lease
    finally:
        ACTIVE_SOURCE_LEASE.reset(token)
        # Do not LOCK_UN: a verifier/builder may still own an inherited copy of
        # this open file description after its controller dies or exits.
        stream.close()
        with _registry_guard():
            if path.exists():
                _live_root(path)


def source_subprocess_contract(env):
    """Keep the tree lease alive in verifier and builder processes, including
    their restoration grace period. Return a copied env and Popen pass_fds.
    """
    env = dict(env)
    lease = ACTIVE_SOURCE_LEASE.get()
    if lease is not None:
        lease.require()
        descriptor = lease.stream.fileno()
    elif env.get(SOURCE_LEASE_FD):
        descriptor = int(env[SOURCE_LEASE_FD])
        if descriptor < 3:
            raise LeaseBusy('invalid inherited source lease descriptor')
        metadata = json.loads(os.pread(descriptor, 16384, 0))
        if metadata.get('kind') != 'source_lease':
            raise LeaseBusy('inherited descriptor is not a source lease')
    else:
        return env, ()
    env[SOURCE_LEASE_FD] = str(descriptor)
    return env, (descriptor,)


def process_state(run_dir):
    path = Path(run_dir) / 'run.lock'
    if not path.exists():
        return 'NO_LEASE_RECORD'
    with path.open('r') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 'ACTIVE_LEASE'
        else:
            fcntl.flock(stream, fcntl.LOCK_UN)
            return 'NO_ACTIVE_LEASE'
