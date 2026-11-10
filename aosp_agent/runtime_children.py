"""Persist app-server process identities for conservative stopped-run recovery.

The inspected openai-codex 0.154 transport owns a subprocess.Popen at
AsyncCodex._client._sync._proc. Unsupported transports are explicitly UNKNOWN.
No recovery operation signals a PID: a live or unverifiable identity blocks.
"""
import ctypes
import errno
import json
import os
from pathlib import Path
import sys
import time
import uuid

from .lifecycle import RecoveryBlocked
from .output_budget import find_budget, write_bytes, OutputBudgetExceeded


def process_identity(pid):
    """Return a kernel creation identity, None when absent, or raise on doubt."""
    if type(pid) is not int or pid <= 0:
        raise RecoveryBlocked('runtime child PID is invalid')
    if sys.platform.startswith('linux'):
        try:
            # comm may contain spaces and parentheses; starttime is field 22.
            stat = (Path('/proc') / str(pid) / 'stat').read_text()
        except FileNotFoundError:
            return None
        fields = stat.rsplit(')', 1)[1].split()
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return {'platform': 'linux', 'pid': pid, 'boot_id': boot, 'start_ticks': int(fields[19])}
    if sys.platform == 'darwin':
        # Layout and PROC_PIDTBSDINFO=3 are from the installed macOS SDK's
        # sys/proc_info.h; creation time has microsecond, not ps-second precision.
        class BsdInfo(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in (
                'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid',
                'rgid', 'svuid', 'svgid', 'reserved')] + [
                ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)] + [
                (name, ctypes.c_uint32) for name in ('nfiles', 'pgid', 'pjobc', 'tdev', 'tpgid')] + [
                ('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64), ('start_usec', ctypes.c_uint64)]
        library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        lookup = library.proc_pidinfo
        lookup.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        lookup.restype = ctypes.c_int
        info = BsdInfo()
        size = lookup(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        if not size and ctypes.get_errno() == errno.ESRCH:
            return None
        if size != ctypes.sizeof(info) or info.pid != pid or not info.start_sec:
            raise RecoveryBlocked('cannot verify macOS runtime process identity')
        return {'platform': 'darwin', 'pid': pid, 'start_sec': info.start_sec, 'start_usec': info.start_usec}
    raise RecoveryBlocked('runtime child creation identity is unsupported on this platform')


def identity_state(identity):
    if not isinstance(identity, dict) or identity.get('platform') not in ('linux', 'darwin'):
        return 'UNKNOWN'
    if (identity['platform'] == 'linux') != sys.platform.startswith('linux'):
        return 'UNKNOWN'
    try:
        current = process_identity(identity['pid'])
    except (OSError, ValueError, KeyError, IndexError, RecoveryBlocked):
        return 'UNKNOWN'
    if current is None:
        return 'EXITED'
    return 'ALIVE' if current == identity else 'EXITED_ID_REUSED'


def _save(path, value):
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    budget = find_budget(path)
    if budget is None:
        saved = write_bytes(path, data)
    else:
        try:
            saved = budget.write(path, data, control=budget.data()['exhausted'])
        except OutputBudgetExceeded:
            saved = budget.write(path, data, control=True)
    if saved is False or path.is_symlink() or path.read_bytes() != data:
        raise RecoveryBlocked('runtime child identity receipt was not durably saved')
    for durable in (path, path.parent):
        fd = os.open(durable, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class RuntimeChild:
    def __init__(self, events_path, process):
        self.process = process
        self.id = uuid.uuid4().hex
        self.path = Path(events_path).parent / 'runtime-children' / (self.id + '.json')
        identity = None
        if process is not None:
            try:
                identity = process_identity(process.pid)
            except (OSError, ValueError, AttributeError, IndexError, RecoveryBlocked):
                pass
        self.value = {'version': 1, 'runtime_id': self.id, 'identity': identity,
                      'identity_status': 'KNOWN' if identity else 'UNKNOWN',
                      'cleanup': 'NOT_CHECKED', 'started_at': time.time()}
        _save(self.path, self.value)

    def reference(self):
        return {'runtime_id': self.id, 'record': str(self.path), 'identity': self.value['identity']}

    def finish(self):
        state = identity_state(self.value['identity'])
        # A Popen wait result proves this exact process exited even if the OS
        # identity reader is unavailable later. Retain the identity for resume.
        returncode = self.process.poll() if self.process is not None else None
        if returncode is not None:
            state = 'EXITED'
        self.value.update(cleanup=state, closed_at=time.time(), returncode=returncode)
        _save(self.path, self.value)
        return state


def require_stopped(reference, owner_root):
    """Verify the exact persisted child. Never infer exit from PID alone."""
    if not isinstance(reference, dict) or not reference.get('record'):
        raise RecoveryBlocked('interrupted runtime child identity is UNKNOWN')
    path = Path(reference['record'])
    if path.is_symlink() or not path.resolve().is_relative_to(Path(owner_root).resolve()):
        raise RecoveryBlocked('runtime child receipt escapes the stopped run')
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise RecoveryBlocked('runtime child receipt is unavailable') from exc
    if (value.get('version') != 1 or value.get('runtime_id') != reference['runtime_id']
            or value.get('identity') != reference['identity']):
        raise RecoveryBlocked('runtime child identity receipt changed')
    if not reference.get('identity'):
        if value.get('cleanup') == 'EXITED' and type(value.get('returncode')) is int:
            return {'status': 'CLEANUP_RECEIPT_EXITED', 'runtime_id': reference['runtime_id']}
        raise RecoveryBlocked('interrupted runtime child identity is UNKNOWN')
    state = identity_state(reference['identity'])
    if state not in ('EXITED', 'EXITED_ID_REUSED'):
        raise RecoveryBlocked('interrupted runtime child is ' + state + '; recovery remains blocked')
    return {'status': state, 'runtime_id': reference['runtime_id']}


def verify_run_children(root):
    """Guard all sessions, including read-only routing/impact/review runtimes."""
    root = Path(root).resolve()
    verified = []
    for directory in sorted(root.rglob('runtime-children')):
        if directory.is_symlink() or not directory.resolve().is_relative_to(root) or not directory.is_dir():
            raise RecoveryBlocked('runtime child receipt directory is unsafe')
        for path in sorted(directory.glob('*.json')):
            try:
                value = json.loads(path.read_text())
                if path.name != value['runtime_id'] + '.json':
                    raise ValueError('runtime receipt filename does not match identity')
                reference = {'runtime_id': value['runtime_id'], 'identity': value['identity'], 'record': str(path)}
                verified.append(require_stopped(reference, root))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise RecoveryBlocked('cannot establish stopped runtime child: ' + str(path) + ': ' + str(exc)) from exc
    return {'status': 'VERIFIED', 'children': verified}
