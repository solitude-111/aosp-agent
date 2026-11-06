"""Cancellable, bounded subprocess output for controller-brokered read tools."""
from contextvars import ContextVar
import os
import selectors
import signal
import subprocess
import time

from .retrieval import BudgetExceeded


ACTIVE_TOOL_IO = ContextVar('aosp_tool_io', default=None)


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

        Callers claim each Git operation before entering. This routine reserves
        chunks before reading pipe data and reaps the child on every exit.
        It is bounded Git process-group cleanup, not arbitrary daemon containment.
        """
        self.check()
        deadline = min(self.deadline, time.monotonic() + timeout)
        streams = [bytearray(), bytearray()]
        total = 0
        with subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True) as process:
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
                            allowance = min(4096, self.max_output - total, self.budget.remaining_bytes())
                            if allowance <= 0:
                                raise BudgetExceeded('model tool subprocess output limit exhausted')
                            self.budget.claim_bytes(allowance)
                            data = os.read(key.fileobj.fileno(), allowance)
                            if not data:
                                selector.unregister(key.fileobj)
                            else:
                                streams[key.data].extend(data); total += len(data)
                    while process.poll() is None:
                        self.check()
                        if time.monotonic() >= deadline:
                            raise subprocess.TimeoutExpired(argv, timeout)
                        time.sleep(.01)
                    code = process.returncode
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                process.stdout.close(); process.stderr.close()
        stdout, stderr = (bytes(v).decode('utf-8', errors='replace') for v in streams)
        if check and code:
            raise subprocess.CalledProcessError(code, argv, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, code, stdout, stderr)
