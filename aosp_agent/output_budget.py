"""Persistent aggregate budgets for controller-emitted payloads.

Reservations count cumulative bytes, including replacements and failed writes:
this is deliberately stricter than live file size. Source/candidate checkouts,
external builder files, and restoration receipts have separate ownership.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import threading
import time
import uuid

from .lifecycle import RecoveryBlocked


DEFAULT_LIMIT = 256 * 1024 * 1024
UNSCOPED_FILE_LIMIT = 32 * 1024 * 1024
STATE = '.output-budget.json'
LOCK = '.output-budget.lock'
METADATA_RESERVE = 8192


class OutputBudgetUnavailable(RecoveryBlocked):
    kind = 'OUTPUT_BUDGET_UNAVAILABLE'


class OutputBudgetExceeded(OutputBudgetUnavailable):
    kind = 'OUTPUT_BUDGET_EXHAUSTED'


def _atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class OutputBudget:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.lock = threading.RLock()

    @contextmanager
    def _locked(self):
        with self.lock:
            fd = None
            try:
                fd = os.open(self.root / LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OutputBudgetUnavailable('invalid output budget lock')
                deadline = time.monotonic() + 2
                while True:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise OutputBudgetUnavailable('output budget lock deadline exceeded')
                        time.sleep(.01)
                state_fd = os.open(self.root / STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(state_fd, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
                        raise OutputBudgetUnavailable('invalid output budget state')
                    value = json.loads(stream.read(4097))
                if not isinstance(value, dict) or value.get('version') != 1:
                    raise OutputBudgetUnavailable('invalid output budget format')
                for key in ('limit', 'normal_limit', 'normal_reserved', 'control_reserved'):
                    if type(value.get(key)) is not int or value[key] < 0:
                        raise OutputBudgetUnavailable('invalid output budget counters')
                if type(value.get('exhausted')) is not bool:
                    raise OutputBudgetUnavailable('invalid output budget status')
                limit = value['limit']
                if (not 128 * 1024 <= limit <= 1024 ** 4 or
                    value['normal_limit'] != limit - min(4 * 1024 * 1024, limit // 8) - METADATA_RESERVE or
                    value['normal_reserved'] > value['normal_limit'] or
                    value['normal_reserved'] + value['control_reserved'] > limit - METADATA_RESERVE):
                    raise OutputBudgetUnavailable('inconsistent output budget counters')
                yield value
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise OutputBudgetUnavailable('output budget state or write is unavailable') from exc
            finally:
                if fd is not None:
                    os.close(fd)

    def data(self):
        with self._locked() as value:
            return dict(value, root=str(self.root), scope='cumulative_controller_payload_bytes')

    def check(self):
        with self._locked() as value:
            if value['exhausted']:
                raise OutputBudgetExceeded('managed output budget exhausted; no new work is permitted')

    def _save(self, value):
        # A fixed temporary name is safe under the cross-process lock and
        # prevents abandoned quota metadata from accumulating after crashes.
        data = (json.dumps(value, sort_keys=True) + '\n').encode()
        if len(data) > 4096:
            raise OutputBudgetUnavailable('output budget metadata exceeds its reserved size')
        temporary = self.root / (STATE + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        temporary.replace(self.root / STATE)

    def write(self, path, data, *, append=False, control=False):
        path = Path(path)
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise OutputBudgetUnavailable('managed output path escapes its task root')
        with self._locked() as value:
            used = value['normal_reserved'] + value['control_reserved']
            allowed = used + len(data) <= value['limit'] - METADATA_RESERVE
            if not control:
                allowed = allowed and not value['exhausted'] and value['normal_reserved'] + len(data) <= value['normal_limit']
            if not allowed:
                if not value['exhausted']:
                    value.update(exhausted=True, blocked_path=str(path.relative_to(self.root))[:512])
                    self._save(value)
                if control:
                    return False  # The persistent exhausted state remains authoritative.
                raise OutputBudgetExceeded('managed output budget exhausted before writing ' + path.name)
            key = 'control_reserved' if control else 'normal_reserved'
            value[key] += len(data)
            self._save(value)  # Reserve before the file, including interrupted/failed writes.
            if append:
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
            else:
                _atomic(path, data)
            return True


def find_budget(path):
    # Examine the lexical ancestors first so a symlink cannot escape an
    # already registered root and fall into the unscoped fallback.
    absolute = Path(os.path.abspath(path))
    for parent in (absolute.parent, *absolute.parent.parents):
        if os.path.lexists(parent / STATE):
            return OutputBudget(parent)
    return None


def create_budget(root, limit=DEFAULT_LIMIT):
    if type(limit) is not int or not 128 * 1024 <= limit <= 1024 ** 4:
        raise ValueError('max_output_bytes must be between 128 KiB and 1 TiB')
    root = Path(root).resolve()
    inherited = find_budget(root / 'placeholder')
    if inherited is not None:
        inherited.check()
        return inherited
    if any(root.iterdir()):
        raise ValueError('output budget must be initialized in a fresh empty task directory')
    reserve = min(4 * 1024 * 1024, limit // 8)
    value = dict(version=1, limit=limit, normal_limit=limit - reserve - METADATA_RESERVE,
                 normal_reserved=0, control_reserved=0, exhausted=False)
    _atomic(root / STATE, (json.dumps(value) + '\n').encode())
    return OutputBudget(root)


def write_bytes(path, data, *, append=False, budget=None):
    path = Path(path)
    budget = budget or find_budget(path)
    if budget is not None:
        return budget.write(path, data, append=append)
    # Standalone diagnostic helpers have a per-file bound, not a task budget.
    current = path.stat().st_size if append and path.exists() else 0
    if current + len(data) > UNSCOPED_FILE_LIMIT:
        raise OutputBudgetExceeded('unscoped output file limit exceeded')
    if append:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    else:
        _atomic(path, data)
    return True


def write_text(path, text, *, append=False, budget=None):
    return write_bytes(path, text.encode('utf-8'), append=append, budget=budget)


def _blocked_record(value, budget):
    # Do not truncate semantic evidence into a successful result. A compact
    # record is explicitly blocked and cannot be resumed as a complete record.
    keep = ('task_id', 'cve', 'execution', 'execution_path', 'input_sha256', 'input_patch_sha256',
            'resume_input_sha256', 'resumed_from', 'resumed_to', 'active_round_record', 'final_round_record',
            'row_count', 'counts', 'remaining_rows', 'source_guard', 'cancellation_source_guard')
    compact = {key: value[key] for key in keep if key in value}
    compact.update(status='BLOCKED', impact_decision='UNKNOWN', delivery_status='BLOCKED',
                   completion_blocked_by='OUTPUT_BUDGET_EXHAUSTED', record_compacted=True,
                   output_budget=budget.data())
    if 'verdict' in value:
        compact['verdict'] = 'ERROR'
    # The actual persistent quota record is sufficient to block status/resume
    # even if user-controlled metadata would exceed the control reservation.
    if len(json.dumps(compact).encode()) > 4096:
        compact = {key: compact[key] for key in ('status', 'impact_decision', 'delivery_status',
                   'completion_blocked_by', 'record_compacted', 'output_budget')}
        if 'verdict' in value:
            compact['verdict'] = 'ERROR'
    return compact


def write_json(path, value, *, control=False):
    budget = find_budget(path)
    if control and budget is not None and budget.data()['exhausted']:
        compact = _blocked_record(value, budget)
        if isinstance(value, dict):
            value.update({k: compact[k] for k in ('status', 'impact_decision', 'delivery_status',
                          'completion_blocked_by', 'record_compacted', 'output_budget')})
            if 'verdict' in compact:
                value['verdict'] = compact['verdict']
        return budget.write(path, (json.dumps(compact, ensure_ascii=False, indent=2) + '\n').encode(), control=True)
    try:
        return write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', budget=budget)
    except OutputBudgetExceeded:
        if control and budget is not None:
            write_json(path, value, control=True)
        raise


def require_output_record(record_path):
    budget = find_budget(record_path)
    if budget is not None:
        budget.check()
