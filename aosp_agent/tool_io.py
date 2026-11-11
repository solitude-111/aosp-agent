"""Cancellable, bounded subprocess output for controller-brokered read tools."""
from contextvars import ContextVar
import os
import selectors
import signal
import subprocess
import time

from .retrieval import BudgetExceeded, record_read_activity
from .lifecycle import RecoveryBlocked


ACTIVE_TOOL_IO = ContextVar('aosp_tool_io', default=None)


class QueryOutputLimit(RuntimeError):
    """One query exceeded its capture limit; the case can issue a smaller query."""
    kind = 'QUERY_OUTPUT_LIMIT'
    limit_scope = 'query'

    def __init__(self, limit, captured):
        super().__init__('single query output limit exhausted')
        self.limit, self.captured = limit, captured


def _cleanup_process_group(process):
    """Reap an exited leader without hiding failures to signal its group."""
    process.poll()
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        # Darwin may return EPERM for an exited, unreaped process group.
        # Reap within a small bound, then still signal the group: an exited
        # leader alone does not establish that all of its children are gone.
        try:
            process.wait(timeout=.1)
        except subprocess.TimeoutExpired:
            raise RecoveryBlocked('tool process group cannot be stopped: ' + str(process.pid)) from exc
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as retry:
            raise RecoveryBlocked('tool process group cleanup remains unverified: ' + str(process.pid)) from retry
    except OSError as exc:
        raise RecoveryBlocked('tool process group cleanup failed: ' + str(process.pid)) from exc
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise RecoveryBlocked('tool process did not exit after group cleanup: ' + str(process.pid)) from exc


class ToolIO:
    def __init__(self, budget, cancelled, deadline, max_output=4 * 1024 * 1024):
        self.budget, self.cancelled, self.deadline = budget, cancelled, deadline
        self.max_output = max_output

    def check(self):
        if self.cancelled.is_set():
            raise BudgetExceeded('model tool execution cancelled')
        if time.monotonic() >= self.deadline:
            raise BudgetExceeded('model tool turn deadline exhausted')
        self.budget.remaining()

    def run(self, argv, *, cwd=None, env=None, timeout=120, check=True, **ignored):
        """No shell, no file-backed capture, no output returned on truncation.

        Callers claim each Git operation before entering. Reserve one bounded
        capture window, settle its actual bytes, and reap the child on every exit.
        It is bounded Git process-group cleanup, not arbitrary daemon containment.
        """
        self.check()
        deadline = min(self.deadline, time.monotonic() + timeout)
        streams = [bytearray(), bytearray()]
        total = 0
        capacity = min(self.max_output + 1, self.budget.remaining_bytes())
        if capacity <= 0:
            raise BudgetExceeded('model tool I/O byte budget exhausted')
        receipt = self.budget.reserve_bytes(capacity, 'git_capture')
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            try:
                with selectors.DefaultSelector() as selector:
                    for index, stream in enumerate((process.stdout, process.stderr)):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, index)
                    while selector.get_map():
                        self.check()
                        if time.monotonic() >= deadline:
                            raise subprocess.TimeoutExpired(argv, timeout)
                        for key, _ in selector.select(.05):
                            self.check()
                            allowance = min(65536, capacity - total)
                            if allowance <= 0:
                                raise BudgetExceeded('model tool I/O byte budget exhausted')
                            data = os.read(key.fileobj.fileno(), allowance)
                            if not data:
                                selector.unregister(key.fileobj)
                            else:
                                streams[key.data].extend(data); total += len(data)
                                if total > self.max_output:
                                    raise QueryOutputLimit(self.max_output, total)
                    while process.poll() is None:
                        self.check()
                        if time.monotonic() >= deadline:
                            raise subprocess.TimeoutExpired(argv, timeout)
                        time.sleep(.01)
                    code = process.returncode
            finally:
                try:
                    _cleanup_process_group(process)
                finally:
                    process.stdout.close(); process.stderr.close()
        finally:
            record_read_activity(git_output_bytes=total)
            self.budget.settle_bytes(receipt, total)
        stdout, stderr = (bytes(v).decode('utf-8', errors='replace') for v in streams)
        if check and code:
            raise subprocess.CalledProcessError(code, argv, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, code, stdout, stderr)
