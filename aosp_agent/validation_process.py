"""Bounded verifier process with a grace period for transactional restoration."""
import os
import signal
import subprocess
import time


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


def run_check(argv, cwd, env, timeout=1800, grace=30):
    with subprocess.Popen(argv, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout, stderr, process.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=grace)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
                stderr += '\nverifier did not finish restoration within grace period'
            return stdout, stderr + f'\nvalidation timed out after {timeout} seconds', 124
