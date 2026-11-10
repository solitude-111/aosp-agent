"""Durable case-wide accounting shared by rounds, repositories and resumptions.

The small checkpoint is part of the existing run directory, referenced from
run.json. It contains counters, not reports or a second results database.
Admission is persisted before work. An interrupted reservation is charged
conservatively after the caller has established that its previous owner stopped.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from functools import wraps
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import threading
import time
import uuid

from .lifecycle import RecoveryBlocked


ACTIVE_EXECUTION = ContextVar('aosp_execution_budget', default=None)
ACTIVE_OPERATION = ContextVar('aosp_execution_operation', default=None)
MODEL_CONTEXT = ContextVar('aosp_model_phase', default={})
ACTIVE_CONTROLLER_AUDIT = ContextVar('aosp_controller_audit', default=None)
AUDIT_GRACE_SECONDS = 120
AUDIT_GRACE_OPERATIONS = 20000
_AUDIT_PHASES = {'engine.audit_diff', 'diff._originals_unchanged', 'build_environment._source_snapshot'}
VERSION = 1
DEFAULT_LIMITS = {
    'candidate_turns': 6, 'model_calls': 48, 'investigation_rounds': 3,
    'tool_operations': 2000, 'report_corrections': 6,
    'io_bytes': 64 * 1024 * 1024, 'execution_seconds': 7200,
    'investigation_seconds': 900,
}


def exceeded(kind):
    from .retrieval import BudgetExceeded
    error = BudgetExceeded('case budget exhausted: ' + kind)
    error.kind, error.limit_scope, error.limit_kind = 'CASE_BUDGET_EXHAUSTED', 'case', kind
    return error


def controller_audit(phase):
    """Only controller integrity checks may finish after a case hard limit.

    This never grants model/tool access or permits edits, builds or replanning.
    Investigation time is paused just as it is for the migration/build owner.
    """
    if phase not in _AUDIT_PHASES:
        raise ValueError('unknown controller audit phase')
    def decorate(function):
        @wraps(function)
        def audited(*args, **kwargs):
            from .retrieval import suspend_investigation_budget
            from .tool_io import ACTIVE_TOOL_IO
            if ACTIVE_TOOL_IO.get() is not None:
                raise exceeded('controller_audit_unavailable_to_model_tools')
            token = ACTIVE_CONTROLLER_AUDIT.set(phase)
            try:
                with suspend_investigation_budget():
                    return function(*args, **kwargs)
            finally:
                ACTIVE_CONTROLLER_AUDIT.reset(token)
        return audited
    return decorate


def _audit_read_command(argv):
    args = list(argv)[1:]
    while args:
        if args[0] in ('-c', '--git-dir', '--work-tree', '-C'):
            args = args[2:]
        elif args[0].startswith(('--git-dir=', '--work-tree=')):
            args = args[1:]
        else:
            break
    if args and args[0] == 'cat-file':
        return (len(args) == 3 and args[1] == '-t' and len(args[2]) in (40, 64)
                and all(char in '0123456789abcdef' for char in args[2]))
    return (bool(args) and args[0] in {'rev-parse', 'status', 'diff', 'ls-files', 'ls-tree'}
            and not any(a.startswith('--output') or a in {'--ext-diff', '--textconv', '--no-index'}
                        for a in args[1:]))


def _atomic(path, value):
    encoded = (json.dumps(value, sort_keys=True, ensure_ascii=False) + '\n').encode()
    if len(encoded) > 256 * 1024:
        raise RecoveryBlocked('execution accounting checkpoint exceeds its metadata bound')
    temporary = path.with_name(path.name + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class ExecutionBudget:
    def __init__(self, root, input_sha256, *, limits=None, existing=False):
        self.root = Path(root).resolve()
        self.path = self.root / 'execution-budget.json'
        self.lock_path = self.root / 'execution-budget.lock'
        self._lock = threading.RLock()
        self._session_started = None
        self.object_cache = None
        self.batch_budget = None
        configured = {**DEFAULT_LIMITS, **(limits or {})}
        for key, value in configured.items():
            if (key not in DEFAULT_LIMITS or isinstance(value, bool)
                    or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0
                    or not key.endswith('_seconds') and not isinstance(value, int)):
                raise ValueError('invalid execution limit: ' + key)
        self.root.mkdir(parents=True, exist_ok=True)
        with self._locked(create=not existing) as state:
            if existing:
                if state.get('input_sha256') != input_sha256:
                    raise RecoveryBlocked('execution budget belongs to different input')
                # Resume uses saved policy; a changed CLI must create a new task.
                if limits is not None and state['limits'] != configured:
                    raise RecoveryBlocked('execution limits changed across resumption')
            else:
                state.update(version=VERSION, lineage_id=uuid.uuid4().hex,
                    input_sha256=input_sha256, limits=configured, consumed={},
                    io_consumed=0, io_reserved=0, io_by_boundary={}, reservations={},
                    by_stage={}, by_repository={}, sequence=0, active_operations={},
                    execution_ms=0, investigation_ms=0, recovery_settlements=[],
                    progress={'facts': [], 'revision': 0}, extensions=[], error_streaks={})
                self._save(state)
            self.lineage_id = state['lineage_id']
            self.limits = dict(state['limits'])

    @contextmanager
    def _locked(self, *, create=False):
        with self._lock:
            fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                if create:
                    if self.path.exists():
                        raise RecoveryBlocked('case budget already exists')
                    state = {}
                else:
                    if self.path.is_symlink() or self.path.stat().st_size > 256 * 1024:
                        raise RecoveryBlocked('invalid execution budget checkpoint')
                    state = json.loads(self.path.read_text())
                    if state.get('version') != VERSION:
                        raise RecoveryBlocked('incompatible execution accounting protocol')
                    if (state.get('io_consumed', -1) < 0 or state.get('io_reserved', -1) < 0
                            or state['io_reserved'] != sum(x['size'] for x in state['reservations'].values())
                            or state['io_consumed'] + state['io_reserved'] > state['limits']['io_bytes']):
                        raise RecoveryBlocked('inconsistent execution accounting checkpoint')
                yield state
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise RecoveryBlocked('execution accounting checkpoint unavailable: ' + type(exc).__name__) from exc
            finally:
                os.close(fd)

    def _save(self, state):
        if self._session_started is not None:
            state['execution_ms'] += self._elapsed_ms()
            self._session_started = time.monotonic()
            if state.get('active_session'):
                state['active_session']['heartbeat_at'] = time.time()
        state['sequence'] = state.get('sequence', 0) + 1
        _atomic(self.path, state)

    def configure(self, limits, stage_limits):
        """Resolve legacy/stage CLI precedence once, before admitting any work."""
        with self._locked() as state:
            if state.get('configured'):
                if limits != state['limits'] or stage_limits != state.get('stage_limits'):
                    raise RecoveryBlocked('resolved stage limits changed across resumption')
                return
            if state['consumed'] or state['io_consumed']:
                raise RecoveryBlocked('cannot configure a consumed execution budget')
            for key, value in {**limits, **stage_limits}.items():
                if (isinstance(value, bool) or not isinstance(value, (int, float))
                        or not math.isfinite(value) or value < 0
                        or value == 0 and key != 'max_stage_extensions'):
                    raise ValueError('stage limits must be positive')
            state.update(limits=dict(limits), stage_limits=dict(stage_limits), configured=True)
            self._save(state)
            self.limits = dict(limits)

    def phase_limit(self, name, default):
        with self._locked() as state:
            return state.get('stage_limits', {}).get(name, default)

    def import_preparation(self, receipt):
        """Account already completed source preparation once, before admission.

        The row's ReadBudget predates its combined patch hash. Snapshot it before
        binding this ledger; resumption never imports another allowance.
        """
        with self._locked() as state:
            if state.get('preparation_imported'):
                return
            operations = receipt.get('operations_used', 0)
            amount = receipt.get('model_io_bytes_consumed', 0)
            seconds = receipt.get('elapsed_seconds', 0)
            if operations > state['limits']['tool_operations'] or amount > state['limits']['io_bytes']:
                raise exceeded('preparation')
            if state['consumed'] or state['io_consumed'] or state['io_reserved']:
                raise RecoveryBlocked('cannot import preparation into an already consumed case')
            state['consumed']['tool_operations'] = operations
            state['by_stage']['PREPARATION'] = {'tool_operations': operations, 'io_bytes': amount}
            state['io_consumed'] = amount
            state['io_by_boundary'] = dict(receipt.get('io_by_boundary', {}))
            if sum(state['io_by_boundary'].values()) != amount:
                raise RecoveryBlocked('source preparation byte receipt is inconsistent')
            state['execution_ms'] += int(seconds * 1000)
            state['investigation_ms'] = max(state['investigation_ms'], int(seconds * 1000))
            state['preparation_imported'] = True
            self._save(state)

    def record_progress(self, phase, verified_facts):
        """Accept only controller-grounded facts, never report wording or size."""
        facts = {hashlib.sha256(json.dumps(fact, sort_keys=True).encode()).hexdigest()
                 for fact in verified_facts}
        if not facts:
            return
        with self._locked() as state:
            progress = state.setdefault('progress', {'facts': [], 'revision': 0})
            existing = set(progress['facts'])
            added = facts - existing
            if added:
                if len(existing | added) > 1024:
                    return  # Bounded receipt metadata; excess facts grant no time.
                progress.update(facts=sorted(existing | added), revision=progress['revision'] + 1,
                                phase=phase)
                self._save(state)

    def investigation_allowance(self, elapsed, phase):
        self.remaining_seconds()
        with self._locked() as state:
            extensions = state.setdefault('extensions', [])
            allowance = state['limits']['investigation_seconds'] + sum(e['seconds'] for e in extensions)
            limits = state.get('stage_limits', {})
            count = sum(e['phase'] == phase for e in extensions)
            progress = state.get('progress', {'revision': 0})
            last = max((e['progress_revision'] for e in extensions), default=0)
            if (allowance - elapsed <= 30 and progress['revision'] > last
                    and count < limits.get('max_stage_extensions', 1)):
                grant = min(limits.get('extension_seconds', 300),
                            max(0, state['limits']['execution_seconds'] - (state['execution_ms'] + self._elapsed_ms()) / 1000))
                if grant > 0:
                    extensions.append({'phase': phase, 'seconds': grant,
                        'progress_revision': progress['revision'], 'basis': 'new_controller_grounded_facts'})
                    self._save(state)
                    allowance += grant
            return allowance

    def repeated_error(self, phase, kind, subjects):
        signature = hashlib.sha256(json.dumps([phase, kind, subjects], sort_keys=True).encode()).hexdigest()
        with self._locked() as state:
            revision = state.get('progress', {}).get('revision', 0)
            previous = state.setdefault('error_streaks', {}).get(phase, {})
            count = previous.get('count', 0) + 1 if (previous.get('signature') == signature
                      and previous.get('progress_revision') == revision) else 1
            state['error_streaks'][phase] = {'signature': signature, 'progress_revision': revision, 'count': count}
            self._save(state)
            return count >= 2

    def _elapsed_ms(self):
        return max(0, int((time.monotonic() - self._session_started) * 1000)) if self._session_started is not None else 0

    def remaining_seconds(self):
        batch_remaining = self.batch_budget.remaining_seconds() if self.batch_budget else math.inf
        with self._locked() as state:
            remaining = state['limits']['execution_seconds'] - (state['execution_ms'] + self._elapsed_ms()) / 1000
            if remaining <= 0:
                raise self._hard_limit(state, 'execution_seconds')
            return min(remaining, batch_remaining)

    def _hard_limit(self, state, kind):
        # Called only while _locked is held: never reenter its file lock.
        if 'audit_grace' not in state:
            now = time.time()
            state['audit_grace'] = {'trigger': kind, 'started_at': now,
                'deadline_at': now + AUDIT_GRACE_SECONDS, 'last_checked_at': now,
                'seconds_limit': AUDIT_GRACE_SECONDS, 'operations_limit': AUDIT_GRACE_OPERATIONS,
                'operations': 0, 'by_phase': {}}
            self._save(state)
        return exceeded(kind)

    def controller_git_timeout(self, timeout, argv):
        """Charge trusted Git once; only designated read audits can use grace."""
        from .retrieval import BudgetExceeded
        from .tool_io import ACTIVE_TOOL_IO
        if ACTIVE_TOOL_IO.get() is not None:
            raise exceeded('controller_git_unavailable_to_model_tools')
        phase = ACTIVE_CONTROLLER_AUDIT.get()
        try:
            self.charge('tool_operations', phase=phase or 'controller_git')
            return min(timeout, self.remaining_seconds())
        except BudgetExceeded as exc:
            if phase not in _AUDIT_PHASES or not _audit_read_command(argv):
                raise
            with self._locked() as state:
                self._hard_limit(state, getattr(exc, 'limit_kind', 'execution_limit'))
                grace = state['audit_grace']
                now = time.time()
                if (grace['seconds_limit'] != AUDIT_GRACE_SECONDS
                        or grace['operations_limit'] != AUDIT_GRACE_OPERATIONS
                        or grace['deadline_at'] != grace['started_at'] + AUDIT_GRACE_SECONDS
                        or now < grace['last_checked_at']):
                    raise RecoveryBlocked('audit grace identity or clock is inconsistent')
                left = grace['deadline_at'] - now
                if left <= 0 or grace['operations'] >= AUDIT_GRACE_OPERATIONS:
                    raise exceeded('audit_grace')
                grace['operations'] += 1
                grace['last_checked_at'] = now
                grace['by_phase'][phase] = grace['by_phase'].get(phase, 0) + 1
                self._save(state)
                return min(timeout, left)

    def charge(self, kind, amount=1, *, phase=None, repository=None):
        if kind not in DEFAULT_LIMITS or kind.endswith('_seconds') or kind == 'io_bytes':
            raise ValueError('unknown discrete budget: ' + kind)
        if type(amount) is not int or amount < 0:
            raise ValueError('budget charge must be a nonnegative integer')
        self.remaining_seconds()
        with self._locked() as state:
            used = state['consumed'].get(kind, 0)
            if used + amount > state['limits'][kind]:
                raise self._hard_limit(state, kind)
            state['consumed'][kind] = used + amount
            for field, name in (('by_stage', phase), ('by_repository', repository)):
                if name:
                    counters = state[field].setdefault(str(name), {})
                    counters[kind] = counters.get(kind, 0) + amount
            self._save(state)

    def admit_model(self, *, read_only=True, phase=None, repository=None):
        self.remaining_seconds()
        kinds = ['model_calls'] + ([] if read_only else ['candidate_turns'])
        with self._locked() as state:
            if state.get('audit_grace', {}).get('operations', 0):
                raise exceeded('audit_only_after_hard_limit')
            for kind in ['tool_operations', *kinds]:
                if state['consumed'].get(kind, 0) >= state['limits'][kind]:
                    raise self._hard_limit(state, kind)
            if self.batch_budget is not None:
                self.batch_budget.admit_model()
            for kind in kinds:
                state['consumed'][kind] = state['consumed'].get(kind, 0) + 1
                for field, name in (('by_stage', phase or ('analysis' if read_only else 'migration')),
                                    ('by_repository', repository)):
                    if name:
                        counters = state[field].setdefault(str(name), {})
                        counters[kind] = counters.get(kind, 0) + 1
            self._save(state)

    def reserve_io(self, size, category='tool_io'):
        if type(size) is not int or size < 0:
            raise ValueError('I/O reservation must be a nonnegative integer')
        self.remaining_seconds()
        with self._locked() as state:
            if state['io_consumed'] + state['io_reserved'] + size > state['limits']['io_bytes']:
                raise self._hard_limit(state, 'io_bytes')
            identity = uuid.uuid4().hex
            state['reservations'][identity] = {'size': size, 'category': category}
            state['io_reserved'] += size
            self._save(state)
            return identity

    def settle_io(self, identity, actual):
        with self._locked() as state:
            reserved = state['reservations'].get(identity)
            if reserved is None:
                raise ValueError('unknown or already settled I/O reservation')
            if type(actual) is not int or not 0 <= actual <= reserved['size']:
                raise ValueError('actual I/O exceeds reservation')
            del state['reservations'][identity]
            state['io_reserved'] -= reserved['size']
            state['io_consumed'] += actual
            category = reserved['category']
            state['io_by_boundary'][category] = state['io_by_boundary'].get(category, 0) + actual
            self._save(state)

    def remaining_io(self):
        with self._locked() as state:
            return state['limits']['io_bytes'] - state['io_consumed'] - state['io_reserved']

    def current_operation(self):
        current = ACTIVE_OPERATION.get()
        return deepcopy(current) if current else None

    @contextmanager
    def operation(self, kind, *, phase=None, repository=None, timeout=None):
        from .retrieval import ACTIVE_BUDGET
        investigation = ACTIVE_BUDGET.get()
        if investigation is not None and not investigation.tracks_investigation:
            investigation = None
        if investigation is not None:
            self.set_investigation_time(investigation.data()['elapsed_seconds'])
        timeout = min(timeout or self.remaining_seconds(), self.remaining_seconds())
        entry = {'id': uuid.uuid4().hex, 'kind': kind, 'phase': phase,
                 'repository': repository, 'started_at': time.time(), 'timeout_seconds': timeout,
                 'pid': os.getpid(), 'investigation': investigation is not None}
        with self._locked() as state:
            if state.get('audit_grace', {}).get('operations', 0):
                raise exceeded('audit_only_after_hard_limit')
            if state['consumed'].get('tool_operations', 0) >= state['limits']['tool_operations']:
                raise self._hard_limit(state, 'tool_operations')
            state['active_operations'][entry['id']] = entry
            self._save(state)
        token = ACTIVE_OPERATION.set(entry)
        try:
            yield entry
        finally:
            ACTIVE_OPERATION.reset(token)
            with self._locked() as state:
                state['active_operations'].pop(entry['id'], None)
                self._save(state)
            if investigation is not None:
                self.set_investigation_time(investigation.data()['elapsed_seconds'])

    def recover_stopped(self):
        """Caller must hold the stopped attempt chain/source leases first."""
        with self._locked() as state:
            unsettled = state['io_reserved']
            for reservation in state['reservations'].values():
                category = reservation['category']
                state['io_by_boundary'][category] = state['io_by_boundary'].get(category, 0) + reservation['size']
            state['io_consumed'] += unsettled
            state['io_reserved'] = 0
            state['reservations'] = {}
            # Operations can be nested. Count their union, bounded by each
            # original deadline; time spent waiting to resume is not execution.
            heartbeat = (state.get('active_session') or {}).get('heartbeat_at', 0)
            intervals = sorted((max(x['started_at'], heartbeat), min(time.time(), x['started_at'] + x['timeout_seconds']))
                               for x in state['active_operations'].values())
            if not intervals and state.get('active_session'):
                session = state['active_session']
                intervals = [(session['heartbeat_at'], min(time.time(), session['deadline_at']))]
            seconds, end = 0, 0
            for start, stop in intervals:
                seconds += max(0, stop - max(start, end))
                end = max(end, stop)
            if unsettled or intervals:
                state['recovery_settlements'].append({'at': time.time(), 'io_charged': unsettled,
                    'execution_ms_upper_bound': int(seconds * 1000), 'basis': 'unsettled_reservation_and_operation_deadlines'})
                state['recovery_settlements'] = state['recovery_settlements'][-32:]
                state['execution_ms'] += int(seconds * 1000)
                investigation = state.get('investigation_clock', {})
                if investigation.get('active'):
                    tail = max(0, min(time.time(), investigation['deadline_at']) - investigation['heartbeat_at'])
                    state['investigation_ms'] += int(tail * 1000)
            state['active_operations'] = {}
            state['active_session'] = None
            state['investigation_clock'] = {'active': False}
            self._save(state)

    def add_investigation_time(self, seconds):
        if seconds < 0:
            raise ValueError('negative investigation duration')
        with self._locked() as state:
            state['investigation_ms'] += int(seconds * 1000)
            self._save(state)

    def set_investigation_time(self, seconds, *, active=None):
        with self._locked() as state:
            state['investigation_ms'] = max(state['investigation_ms'], int(seconds * 1000))
            current = state.setdefault('investigation_clock', {'active': False})
            if active is not None:
                current['active'] = active
            allowance = state['limits']['investigation_seconds'] + sum(e['seconds'] for e in state['extensions'])
            current.update(heartbeat_at=time.time(), deadline_at=time.time() + max(0, allowance - seconds))
            self._save(state)

    def snapshot(self):
        with self._locked() as state:
            result = deepcopy(state)
        result.update(path=str(self.path), root=str(self.root), io_limit=result['limits']['io_bytes'],
                      execution_ms=result['execution_ms'] + self._elapsed_ms())
        return result

    @contextmanager
    def active(self):
        if self._session_started is not None:
            raise RecoveryBlocked('case execution budget already active')
        remaining = self.remaining_seconds()
        self._session_started = time.monotonic()
        with self._locked() as state:
            if state.get('active_session') or state['active_operations'] or state['reservations']:
                self._session_started = None
                raise RecoveryBlocked('previous execution accounting has not been settled')
            state['active_session'] = {'pid': os.getpid(), 'id': uuid.uuid4().hex,
                                      'heartbeat_at': time.time(), 'deadline_at': time.time() + remaining}
            self._save(state)
        token = ACTIVE_EXECUTION.set(self)
        try:
            yield self
        finally:
            ACTIVE_EXECUTION.reset(token)
            with self._locked() as state:
                state['active_session'] = None
                self._save(state)
            self._session_started = None


@contextmanager
def model_context(phase, repository=None):
    token = MODEL_CONTEXT.set({'phase': phase, 'repository': repository})
    try:
        yield
    finally:
        MODEL_CONTEXT.reset(token)
