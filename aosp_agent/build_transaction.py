"""Apply/build/restore under a controller-owned contract and a shared lock.

Only patch paths are restored. Unexpected build/user changes are preserved and
reported as restoration failures. No reset/clean or recursive deletion is used.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

from .case import validate_relative_path
from .discovery import local_git
from .git_policy import offline_git_env
from .patches import split_hunks
from .validation_process import stop_group


class BuildInterrupted(Exception):
    pass


def state(repo):
    return {'head': local_git(repo, 'rev-parse', 'HEAD').stdout.strip(),
            'status': local_git(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout,
            'index': hashlib.sha256(local_git(repo, 'ls-files', '-s', '-z').stdout.encode()).hexdigest(),
            'diff': hashlib.sha256(local_git(repo, 'diff', '--binary', '--no-ext-diff', '--no-textconv', 'HEAD').stdout.encode()).hexdigest()}


def fingerprint(path):
    if path.is_symlink():
        return {'symlink': os.readlink(path)}
    if not path.exists():
        return None
    if not path.is_file():
        return {'type': 'not_file'}
    return {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': path.stat().st_mode}


def transaction(source_root, lock_path, command, env=None):
    env = dict(os.environ if env is None else env)
    required = ['PATCH_FILE', 'PATCH_SHA256', 'TARGET_REPO', 'TARGET_COMMIT', 'WORKTREE', 'RUN_DIR']
    values = {key: env.get('AOSP_AGENT_' + key) for key in required}
    if not all(values.values()) or not command:
        raise ValueError('missing controller build contract or build command')
    for key in ('PATCH_FILE', 'TARGET_REPO', 'WORKTREE', 'RUN_DIR'):
        if not Path(values[key]).is_absolute():
            raise ValueError('build contract paths must be absolute')
    source_root = Path(source_root).resolve()
    repo, worktree, run_dir = (Path(values[k]).resolve() for k in ('TARGET_REPO', 'WORKTREE', 'RUN_DIR'))
    patch_path = Path(values['PATCH_FILE']).resolve()
    if not repo.is_relative_to(source_root) or repo == worktree:
        raise ValueError('build repository is outside configured source root or equals candidate')
    if run_dir.is_relative_to(source_root) or not patch_path.is_relative_to(run_dir):
        raise ValueError('build evidence/patch must be outside source root and inside run directory')
    patch_bytes = patch_path.read_bytes()
    if hashlib.sha256(patch_bytes).hexdigest() != values['PATCH_SHA256']:
        raise ValueError('candidate patch hash mismatch')
    hunks = split_hunks(patch_bytes.decode('utf-8'))
    paths = sorted({validate_relative_path(h[k]) for h in hunks for k in ('old_path', 'new_path') if h.get(k)})
    if not paths:
        raise ValueError('empty build patch')
    snapshot = run_dir / 'module-build-restore'
    snapshot.mkdir(parents=True, exist_ok=True)
    report = {'patch_sha256': values['PATCH_SHA256'], 'target_commit': values['TARGET_COMMIT'],
              'paths': paths, 'restore': 'NOT_NEEDED', 'build_returncode': None}
    def save():
        (snapshot / 'transaction.json').write_text(json.dumps(report, indent=2) + '\n')
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = state(repo)
        report['before'] = before
        save()
        if before['status']:
            raise ValueError('source baseline is dirty; no apply or restoration performed')
        if before['head'] != values['TARGET_COMMIT']:
            raise ValueError('source HEAD differs from pinned target commit')
        if local_git(worktree, 'rev-parse', 'HEAD').stdout.strip() != before['head']:
            raise ValueError('candidate HEAD differs from pinned target commit')
        tracked, new_paths, new_dirs = [], [], set()
        for path in paths:
            absolute = repo / path
            if any(p.is_symlink() for p in [absolute, *list(absolute.parents)[:len(Path(path).parts) - 1]]):
                raise ValueError('symlink in patch path: ' + path)
            entry = local_git(repo, 'ls-tree', before['head'], '--', path).stdout
            if entry:
                if not entry.startswith(('100644 ', '100755 ')):
                    raise ValueError('unsupported baseline file type: ' + path)
                tracked.append(path)
            else:
                if absolute.exists():
                    raise ValueError('new patch path already exists (possibly ignored): ' + path)
                new_paths.append(path)
                parent = absolute.parent
                while parent != repo and not parent.exists():
                    new_dirs.add(parent)
                    parent = parent.parent
        # Validate before mutating. Git apply without --reject is atomic on errors.
        local_git(repo, 'apply', '--check', '--binary', str(patch_path))
        process = None
        applied = False
        expected = {}
        old_handlers = {}
        def interrupted(signum, _frame):
            raise BuildInterrupted(f'build interrupted by signal {signum}')
        try:
            for sig in (signal.SIGTERM, signal.SIGINT):
                old_handlers[sig] = signal.signal(sig, interrupted)
            blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                local_git(repo, 'apply', '--binary', str(patch_path))
                applied = True
                expected = {path: fingerprint(repo / path) for path in paths}
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            report['applied_files'] = expected
            report['restore'] = 'PENDING'
            save()
            child_env = offline_git_env(env)
            child_env['AOSP_AGENT_TRANSACTION_ACTIVE'] = '1'
            process = subprocess.Popen(command, cwd=worktree, env=child_env, start_new_session=True)
            report['build_returncode'] = process.wait()
        except BuildInterrupted as exc:
            report.update(build_returncode=130, error=str(exc))
        finally:
            # Finish stopping builders before restoring their source inputs.
            for sig in old_handlers:
                signal.signal(sig, signal.SIG_IGN)
            try:
                if process is not None:
                    stop_group(process)
                if applied:
                    changed = [p for p in paths if fingerprint(repo / p) != expected.get(p)]
                    if changed:
                        report.update(restore='FAIL', unexpected_patch_changes=changed)
                    else:
                        if tracked:
                            local_git(repo, 'restore', '--source=' + before['head'], '--worktree', '--', *tracked)
                        for path in new_paths:
                            (repo / path).unlink(missing_ok=True)
                        for directory in sorted(new_dirs, key=lambda p: len(p.parts), reverse=True):
                            try:
                                directory.rmdir()
                            except OSError:
                                pass  # preserve unrelated files created by a build/user
                        report['after'] = state(repo)
                        report['restore'] = 'PASS' if report['after'] == before else 'FAIL'
            except Exception as exc:
                report.update(restore='FAIL', restore_error=str(exc))
            finally:
                save()
                for sig, handler in old_handlers.items():
                    signal.signal(sig, handler)
        if report['restore'] != 'PASS':
            print('RESTORE_VERIFICATION_FAILED', flush=True)
            return 119
        print('RESTORE_VERIFIED_OK', flush=True)
        return report['build_returncode'] or 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    try:
        return transaction(args.source_root, args.lock, command)
    except Exception as exc:
        print('BUILD_CONTRACT_FAILED: ' + str(exc), flush=True)
        return 120


if __name__ == '__main__':
    raise SystemExit(main())
