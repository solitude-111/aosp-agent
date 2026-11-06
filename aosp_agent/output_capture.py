"""Bounded diagnostics while continuing to drain restoration output."""
import os
import selectors
import threading
import time


class RetainedOutput:
    def __init__(self, limit):
        self.half = limit // 2
        self.first, self.last = bytearray(), bytearray()
        self.total = 0

    def append(self, data):
        self.total += len(data)
        count = min(len(data), self.half - len(self.first))
        self.first.extend(data[:count])
        self.last.extend(data[count:])
        if len(self.last) > self.half:
            del self.last[:-self.half]

    def text(self):
        marker = (f'\n[verifier output truncated: {self.total} bytes, first/last {self.half} retained]\n'
                  if self.total > self.half * 2 else '')
        return self.first.decode('utf-8', errors='replace') + marker + self.last.decode('utf-8', errors='replace')


class OutputCapture:
    """A reader independent of builder cleanup, with no temporary output files.

    Exceeding the combined byte limit asks the controller to stop the verifier.
    Draining continues during its TERM grace period so an EXIT trap can print
    while restoring source. Only bounded first/last diagnostics are retained.
    """
    def __init__(self, stdout, stderr, *, output_limit, retain_limit=1024 * 1024):
        if (type(output_limit) is not int or output_limit < 1 or
                type(retain_limit) is not int or retain_limit < 2):
            raise ValueError('output limits must be positive integers')
        self.streams = (stdout, stderr)
        self.outputs = [RetainedOutput(retain_limit), RetainedOutput(retain_limit)]
        self.limit = output_limit
        self.exceeded, self.stopping = threading.Event(), threading.Event()
        self.error = None
        self.deadline = None
        for stream in self.streams:
            os.set_blocking(stream.fileno(), False)
        self.thread = threading.Thread(target=self._read, name='aosp-verifier-output', daemon=True)

    def start(self):
        self.thread.start()

    def _read(self):
        try:
            with selectors.DefaultSelector() as selector:
                for number, stream in enumerate(self.streams):
                    selector.register(stream, selectors.EVENT_READ, number)
                while selector.get_map():
                    if self.deadline is not None and time.monotonic() >= self.deadline:
                        self.error = 'output reader did not drain after process-group cleanup'
                        break
                    ready = selector.select(0 if self.stopping.is_set() else .05)
                    if not ready and self.stopping.is_set():
                        break  # Do not wait for EOF held by an unrelated/detached writer.
                    for key, _ in ready:
                        try:
                            data = os.read(key.fileobj.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        self.outputs[key.data].append(data)
                        if sum(output.total for output in self.outputs) > self.limit:
                            self.exceeded.set()
        except Exception as exc:
            self.error = type(exc).__name__ + ': ' + str(exc)

    def finish(self):
        self.deadline = time.monotonic() + 1
        self.stopping.set()
        self.thread.join(2)
        if self.thread.is_alive():
            raise RuntimeError('verifier output reader did not stop')
        return tuple(output.text() for output in self.outputs)
