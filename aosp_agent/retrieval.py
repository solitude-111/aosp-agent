"""Bounded reads and immutable-object caching; mutable audits bypass the cache."""
from collections.abc import Mapping
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import locale
import math
import re
from pathlib import Path
import subprocess
import time
import threading

from .case import validate_relative_path


ACTIVE_BUDGET = ContextVar('aosp_read_budget', default=None)
ACTIVE_MODEL_BUDGET = ContextVar('aosp_model_budget', default=None)
DISCOVERY_RESERVE = ContextVar('aosp_discovery_reserve', default=None)
ACTIVE_READ_PHASE = ContextVar('aosp_read_phase', default=None)


def record_read_activity(**counts):
    active = ACTIVE_READ_PHASE.get()
    if active is not None:
        owner, phase = active
        with owner._lock:
            owner._phases.setdefault(phase, Counter()).update(counts)


def capture_git(argv, *, check, errors=None, input=None, **options):
    """Capture controller Git bytes before applying normal subprocess text decoding."""
    from .execution_budget import ACTIVE_EXECUTION
    from .tool_io import ACTIVE_TOOL_IO
    ledger = ACTIVE_EXECUTION.get()
    if ledger is not None and ACTIVE_BUDGET.get() is None and ACTIVE_TOOL_IO.get() is None:
        options['timeout'] = ledger.controller_git_timeout(options.get('timeout', 45), argv)
    if ACTIVE_READ_PHASE.get() is None:
        return subprocess.run(argv, check=check, text=True, errors=errors, input=input,
                              capture_output=True, **options)
    encoding = locale.getpreferredencoding(False)
    data = input.encode(encoding, errors or 'strict') if input is not None else None
    try:
        result = subprocess.run(argv, input=data, capture_output=True, **options)
    except subprocess.TimeoutExpired as exc:
        record_read_activity(git_output_bytes=len(exc.output or b'') + len(exc.stderr or b''))
        raise
    record_read_activity(git_output_bytes=len(result.stdout) + len(result.stderr))
    for name in ('stdout', 'stderr'):
        text = getattr(result, name).decode(encoding, errors or 'strict')
        setattr(result, name, text.replace('\r\n', '\n').replace('\r', '\n'))
    if check:
        result.check_returncode()
    return result


class BudgetExceeded(RuntimeError):
    pass


class DiscoveryDeferred(RuntimeError):
    """Optional retrieval reached its soft limit before impact analysis."""


class ReadBudget:
    def __init__(self, seconds=900, operations=2000, output_bytes=64 * 1024 * 1024, *, ledger=None,
                 tracks_investigation=True):
        if (isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds)
                or seconds <= 0 or isinstance(operations, bool) or not isinstance(operations, int) or operations < 1):
            raise ValueError('read budget must be finite and positive')
        if type(output_bytes) is not int or output_bytes < 1:
            raise ValueError('output byte budget must be positive')
        self.started, self.seconds, self.operations = time.monotonic(), seconds, operations
        self.tracks_investigation = tracks_investigation
        self.used, self.paused_seconds = 0, 0
        self.byte_limit, self.bytes_used = output_bytes, 0
        if ledger is None:
            from .execution_budget import ACTIVE_EXECUTION
            ledger = ACTIVE_EXECUTION.get()
        self.ledger = ledger
        if ledger is not None:
            self.byte_limit = ledger.limits['io_bytes']
            self.operations = ledger.limits['tool_operations']
        self.bytes_reserved = 0
        self._reservations = {}
        self._reservation_sequence = 0
        self._boundaries = Counter()
        self._lock = threading.RLock()
        self._phases = {}

    def remaining(self):
        elapsed = time.monotonic() - self.started - self.paused_seconds
        allowance = self.seconds
        if self.ledger is not None and self.tracks_investigation:
            self.ledger.set_investigation_time(elapsed, active=True)
            active = ACTIVE_READ_PHASE.get()
            allowance = self.ledger.investigation_allowance(elapsed, active[1] if active else 'INVESTIGATION')
        left = allowance - elapsed
        if self.ledger is not None:
            left = min(left, self.ledger.remaining_seconds())
        if left <= 0:
            raise BudgetExceeded('total investigation time budget exhausted')
        return left

    def command_timeout(self, timeout):
        with self._lock:
            left = self.remaining()
            if DISCOVERY_RESERVE.get() is self:
                left = self.discovery_remaining()
            if self.ledger is None and self.used >= self.operations:
                raise BudgetExceeded('total read/tool operation budget exhausted')
            if self.ledger is not None:
                self.ledger.charge('tool_operations')
            self.used += 1
            record_read_activity(operations=1)
            return min(timeout, left)

    def discovery_remaining(self):
        with self._lock:
            left = self.remaining() - self.seconds / 2
            if self.operations - self.used <= self.operations // 2:
                raise DiscoveryDeferred('DISCOVERY_OPERATION_RESERVE')
            if left <= 0:
                raise DiscoveryDeferred('DISCOVERY_TIME_RESERVE')
            return left

    @contextmanager
    def reserve_for_impact(self):
        token = DISCOVERY_RESERVE.set(self)
        try:
            yield
        finally:
            DISCOVERY_RESERVE.reset(token)

    def reserve_bytes(self, size, category='tool_data'):
        """Admit bytes before I/O. The returned receipt must be settled once."""
        if type(size) is not int or size < 0:
            raise ValueError('byte reservation must be nonnegative')
        with self._lock:
            self.remaining()
            if self.ledger is None and self.bytes_used + self.bytes_reserved + size > self.byte_limit:
                raise BudgetExceeded('model tool I/O byte budget exhausted')
            shared = self.ledger.reserve_io(size, category) if self.ledger is not None else None
            self._reservation_sequence += 1
            receipt = self._reservation_sequence
            self._reservations[receipt] = (size, category, shared, ACTIVE_READ_PHASE.get())
            self.bytes_reserved += size
            record_read_activity(io_reserved_bytes=size)
            return receipt

    def settle_bytes(self, receipt, actual):
        """Settlement does not check deadlines: cleanup must release unused quota."""
        with self._lock:
            size, category, shared, phase = self._reservations[receipt]
            if type(actual) is not int or not 0 <= actual <= size:
                raise ValueError('actual byte consumption exceeds reservation')
            if self.ledger is not None:
                self.ledger.settle_io(shared, actual)
            del self._reservations[receipt]
            self.bytes_reserved -= size
            self.bytes_used += actual
            self._boundaries[category] += actual
            if phase is not None:
                owner, name = phase
                with owner._lock:
                    owner._phases.setdefault(name, Counter()).update(
                        io_consumed_bytes=actual, io_released_bytes=size - actual,
                        **{category + '_bytes': actual})

    def claim_bytes(self, size, category='tool_data'):
        """Charge a known, actually processed byte count (no outstanding reserve)."""
        receipt = self.reserve_bytes(size, category)
        self.settle_bytes(receipt, size)

    def remaining_bytes(self):
        with self._lock:
            return (self.ledger.remaining_io() if self.ledger is not None else
                    self.byte_limit - self.bytes_used - self.bytes_reserved)

    def data(self):
        return {'seconds': self.seconds, 'elapsed_seconds': round(time.monotonic() - self.started - self.paused_seconds, 3),
                'tracks_investigation': self.tracks_investigation,
                'operation_limit': self.operations, 'operations_used': self.used,
                'model_io_bytes_reserved': self.bytes_reserved, 'model_io_bytes_consumed': self.bytes_used,
                'model_io_byte_limit': self.byte_limit,
                'io_by_boundary': dict(self._boundaries),
                **({'case_io': {k: v for k, v in self.ledger.snapshot().items()
                               if k in ('io_consumed', 'io_reserved', 'io_limit', 'io_by_boundary')}}
                   if self.ledger is not None else {}),
                'operation_accounting': 'controller Git processes plus broker requests and their Git subqueries; legacy unscoped SDK counts tool-start events',
                'byte_accounting': 'settled broker request, source capture, file I/O and reply boundaries; not physical disk I/O'}

    def phase_data(self):
        with self._lock:
            return {phase: {key: counts[key] for key in set(counts) | {'operations', 'git_output_bytes',
                        'broker_file_read_bytes', 'io_reserved_bytes', 'io_consumed_bytes', 'io_released_bytes'}}
                    for phase, counts in self._phases.items()}

    @contextmanager
    def phase(self, name):
        token = ACTIVE_READ_PHASE.set((self, name))
        try:
            yield
        finally:
            ACTIVE_READ_PHASE.reset(token)

    @contextmanager
    def active(self):
        token = ACTIVE_BUDGET.set(self)
        try:
            yield self
        finally:
            ACTIVE_BUDGET.reset(token)


@contextmanager
def suspend_investigation_budget():
    """Pause only investigation time; case tool/time limits remain enforced.

    Controller Git bytes are telemetry. Model broker I/O remains charged through
    ToolIO even when a migration/build owner suspends investigation time.
    """
    budget = ACTIVE_BUDGET.get()
    if budget and budget.ledger is not None and budget.tracks_investigation:
        budget.ledger.set_investigation_time(budget.data()['elapsed_seconds'], active=False)
    token = ACTIVE_BUDGET.set(None)
    started = time.monotonic()
    try:
        yield
    finally:
        if budget:
            budget.paused_seconds += time.monotonic() - started
            if budget.ledger is not None and budget.tracks_investigation:
                budget.ledger.set_investigation_time(budget.data()['elapsed_seconds'], active=True)
        ACTIVE_BUDGET.reset(token)


from .object_cache import ObjectCache


class LazyTree(Mapping):
    """Read exact pinned tree entries on demand; enumeration is explicit escalation."""
    def __init__(self, root, head, cache=None, progress=None):
        self.root, self.head, self.cache, self.progress = root, head, cache, progress
        self.entries, self.absent, self.complete = {}, set(), False
        self.subtrees = {}

    def query(self, *args, stage='read_tree', check=True):
        from .discovery import read_git
        execute = lambda: read_git(self.root, *args, stage=stage, check=check, progress=self.progress)
        return self.cache.query(self.root, self.head, args, execute) if self.cache else execute()

    def _parse(self, text):
        found = {}
        for entry in filter(None, text.split('\0')):
            meta, name = entry.split('\t', 1)
            try:
                validate_relative_path(name)
            except ValueError:
                continue
            mode, kind, oid = meta.split()
            if kind == 'blob':
                found[name] = mode
        return found

    def __getitem__(self, path):
        validate_relative_path(path)
        if path not in self.entries and path not in self.absent and not self.complete:
            self._read_paths([path])
        return self.entries[path]

    def _read_paths(self, paths):
        result = self.query('ls-tree', '-z', '--full-tree', self.head, '--', *paths)
        found = self._parse(result.stdout)
        for path in paths:
            if path in found:
                self.entries[path] = found[path]
            else:
                self.absent.add(path)

    def prefetch(self, paths):
        """Check exact paths in bounded argv batches and reuse their pinned modes."""
        if self.complete:
            return
        pending = sorted(set(paths) - self.entries.keys() - self.absent)
        batch = []
        batch_bytes = 0
        for path in pending:
            validate_relative_path(path)
            path_bytes = len(path.encode()) + 1
            if batch and (len(batch) >= 128 or batch_bytes + path_bytes > 64 * 1024):
                self._read_paths(batch)
                batch = []
                batch_bytes = 0
            batch.append(path)
            batch_bytes += path_bytes
        if batch:
            self._read_paths(batch)

    def enumerate(self):
        if not self.complete:
            result = self.query('ls-tree', '-r', '-z', '--full-tree', self.head)
            self.entries = self._parse(result.stdout)
            self.complete = True
        return self.entries

    def paths_under(self, directory):
        """Read one pinned subtree without declaring the project enumerated."""
        validate_relative_path(directory)
        prefix = directory.rstrip('/') + '/'
        if self.complete:
            return {p: mode for p, mode in self.entries.items() if p.startswith(prefix)}
        if directory not in self.subtrees:
            result = self.query('ls-tree', '-r', '-z', '--full-tree', self.head, '--', directory)
            found = {p: mode for p, mode in self._parse(result.stdout).items() if p.startswith(prefix)}
            self.entries.update(found)
            self.subtrees[directory] = found
        return self.subtrees[directory]

    def __iter__(self):
        return iter(self.enumerate())

    def __len__(self):
        return len(self.enumerate())

    def nearby_build_files(self, paths):
        names = set()
        for path in paths:
            directory = Path(path).parent
            for parent in (directory, *directory.parents):
                name = (parent / 'Android.bp').as_posix()
                if self.get(name) in ('100644', '100755'):
                    names.add(name)
        return sorted(names)
