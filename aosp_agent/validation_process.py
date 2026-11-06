"""Bounded verifier process with a grace period for transactional restoration."""
import os
import signal
import subprocess
import time

from .lifecycle import RecoveryBlocked


class VerifierCleanupBlocked(RecoveryBlocked):
    kind = 'VERIFIER_CLEANUP_UNVERIFIED'


def stop_group(process, grace=10):
    """Stop builders even when their immediate parent already exited."""
    def live_members():
        # Darwin can return EPERM from killpg(..., 0) while a dead group is
        # being reaped. Check process state, excluding zombies (cannot write).
        listing = subprocess.run(['ps', '-axo', 'pgid=,stat='], check=True,
                                 capture_output=True, text=True, timeout=5)
        return any(int(fields[0]) == process.pid and not fields[1].startswith('Z')
                   for line in listing.stdout.splitlines()
                   if len(fields := line.split()) == 2 and fields[0].isdigit())

    def send(sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            if live_members():
                raise

    send(signal.SIGTERM)
    deadline = time.monotonic() + grace
    while True:
        process.poll()
        if not live_members():
            process.wait()
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    send(signal.SIGKILL)
    process.wait(timeout=5)
    deadline = time.monotonic() + 5
    while live_members():
        if time.monotonic() >= deadline:
            raise RuntimeError('build process group did not terminate; source preserved')
        time.sleep(0.05)


def run_check(argv, cwd, env, timeout=1800, grace=30, *, output_limit=64 * 1024 * 1024):
    """Return only after the verifier's process group has stopped.

    Capture retains bounded in-memory diagnostics, with a combined stdout/stderr
    byte limit. Group cleanup is mandatory on success, failure, output excess,
    timeout and cancellation, before auditing artifacts or releasing leases.
    This is process-group cleanup, not containment of arbitrary setsid daemons.
    """
    from .lifecycle import source_subprocess_contract
    from .output_capture import OutputCapture
    if type(output_limit) is not int or output_limit < 1:
        raise ValueError('verifier output limit must be a positive integer')
    env, descriptors = source_subprocess_contract(env)
    with subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True, pass_fds=descriptors) as process:
        capture, started, timed_out = None, False, False
        deadline = time.monotonic() + timeout
        try:
            capture = OutputCapture(process.stdout, process.stderr, output_limit=output_limit)
            capture.start()
            started = True
            while process.poll() is None:
                if capture.exceeded.is_set() or capture.error:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(.02)
        finally:
            try:
                stop_group(process, grace=grace)
            except Exception as exc:
                raise VerifierCleanupBlocked('cannot confirm verifier process-group cleanup') from exc
            finally:
                if started:
                    try:
                        stdout, stderr = capture.finish()
                    except Exception as exc:
                        raise VerifierCleanupBlocked('cannot confirm verifier output-reader cleanup') from exc
        code = 124 if timed_out else process.returncode
        if timed_out:
            stderr += f'\nvalidation timed out after {timeout} seconds'
        if capture.exceeded.is_set() or capture.error:
            code = 125
            stderr += ('\nverification output limit exceeded: ' + str(output_limit) + ' bytes'
                       if capture.exceeded.is_set() else '\nverification output capture failed: ' + capture.error)
        return stdout, stderr, code
