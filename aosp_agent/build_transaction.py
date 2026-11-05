"""Apply/build/restore under a controller-owned contract and a shared lock.

Only patch paths are restored. Unexpected build/user changes are preserved and
reported as restoration failures. No reset/clean or recursive deletion is used.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
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
    if env.get('AOSP_AGENT_PATCH_BUNDLE'):
        return bundle_transaction(source_root, lock_path, command, env)
    return _single_transaction(source_root, lock_path, command, env)


def _single_transaction(source_root, lock_path, command, env=None, *,
                        _lock_held=False, _check_only=False, _command_cwd=None):
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
    with (nullcontext() if _lock_held else lock_path.open('a')) as lock:
        if not _lock_held:
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
        if _check_only:
            return 0
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
            if _command_cwd is not None:
                child_env['AOSP_AGENT_WORKTREE'] = str(_command_cwd)
            if callable(command):
                report['build_returncode'] = command()
            else:
                process = subprocess.Popen(command, cwd=_command_cwd or worktree,
                                           env=child_env, start_new_session=True)
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


def bundle_transaction(source_root, lock_path, command, env):
    """Validate every member before applying any; unwind nested exact restores.

    All entries share the outer lock. The actual builder runs only at the leaf,
    while every patched repository is still applied. A failure unwinds every
    already-applied entry, including failures applying a later repository.
    """
    root = Path(source_root).resolve()
    required = ('PATCH_BUNDLE', 'BUNDLE_SHA256', 'WORKTREE', 'RUN_DIR')
    if not command or not all(env.get('AOSP_AGENT_' + k) for k in required):
        raise ValueError('missing controller bundle contract or command')
    for key in ('PATCH_BUNDLE', 'WORKTREE', 'RUN_DIR'):
        if not Path(env['AOSP_AGENT_' + key]).is_absolute():
            raise ValueError('bundle contract paths must be absolute')
    manifest = Path(env['AOSP_AGENT_PATCH_BUNDLE']).resolve()
    run_dir = Path(env['AOSP_AGENT_RUN_DIR']).resolve()
    workspace = Path(env['AOSP_AGENT_WORKTREE']).resolve()
    if (run_dir.is_relative_to(root) or workspace.is_relative_to(root)
            or not manifest.is_relative_to(run_dir) or not workspace.is_dir()):
        raise ValueError('bundle evidence and workspace must be outside source root')
    data = manifest.read_bytes()
    if hashlib.sha256(data).hexdigest() != env['AOSP_AGENT_BUNDLE_SHA256']:
        raise ValueError('bundle hash mismatch')
    bundle = json.loads(data)
    if (bundle.get('version') != 1 or not isinstance(bundle.get('repositories'), list)
            or not 1 <= len(bundle['repositories']) <= 256
            or not isinstance(bundle.get('dependencies', []), list)):
        raise ValueError('invalid patch bundle')
    contracts, seen, dependency_heads = [], {}, {}
    for writable, entry in ([(True, entry) for entry in bundle['repositories']]
                            + [(False, entry) for entry in bundle.get('dependencies', [])]):
        key = validate_relative_path(entry['key'])
        path = Path(entry['target_repo'])
        if not path.is_absolute() or not path.resolve().is_relative_to(root) or key in seen:
            raise ValueError('invalid or duplicate bundle repository')
        path = path.resolve()
        if any(path.is_relative_to(p) or p.is_relative_to(path) for p in seen.values()):
            raise ValueError('overlapping bundle repositories')
        seen[key] = path
        if writable:
            patch_path = Path(entry['patch_file'])
            candidate = Path(entry['worktree'])
            if (not patch_path.is_absolute() or not patch_path.resolve().is_relative_to(run_dir)
                    or not candidate.is_absolute() or not candidate.resolve().is_relative_to(workspace)):
                raise ValueError('bundle patch/candidate is outside the task receipt/workspace')
            contract = dict(env)
            contract.update({
                'AOSP_AGENT_PATCH_FILE': str(patch_path.resolve()),
                'AOSP_AGENT_PATCH_SHA256': entry['sha256'],
                'AOSP_AGENT_TARGET_REPO': str(path),
                'AOSP_AGENT_TARGET_COMMIT': entry['target_commit'],
                'AOSP_AGENT_WORKTREE': str(candidate.resolve()),
                'AOSP_AGENT_RUN_DIR': str(patch_path.resolve().parent),
                'AOSP_AGENT_WORKSPACE': str(workspace),
                'AOSP_AGENT_ARTIFACT_DIR': str(run_dir / 'joint-artifacts'),
            })
            contracts.append(contract)
        else:
            dependency_heads[key] = entry['target_commit']
    snapshot = run_dir / 'module-build-restore'
    snapshot.mkdir(parents=True, exist_ok=True)
    report = {'bundle_sha256': env['AOSP_AGENT_BUNDLE_SHA256'],
              'validation_id': env.get('AOSP_AGENT_VALIDATION_ID'), 'restore': 'NOT_NEEDED',
              'before': {}, 'after': {}, 'build_returncode': None}
    def save():
        temporary = snapshot / 'bundle.json.tmp'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(snapshot / 'bundle.json')
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        report['before'] = {key: state(path) for key, path in seen.items()}
        save()
        for key, head in dependency_heads.items():
            if report['before'][key]['status'] or report['before'][key]['head'] != head:
                raise ValueError('read-only dependency baseline is dirty or differs from pinned HEAD: ' + key)
        for contract in contracts:
            _single_transaction(root, lock_path, command, contract, _lock_held=True, _check_only=True)
        def enter(number):
            nested = (lambda: enter(number + 1)) if number + 1 < len(contracts) else command
            return _single_transaction(root, lock_path, nested, contracts[number],
                                       _lock_held=True, _command_cwd=workspace)
        report['restore'] = 'PENDING'
        save()
        try:
            report['build_returncode'] = enter(0)
        except Exception as exc:
            report.update(build_returncode=120, error=str(exc))
        finally:
            report['after'] = {key: state(path) for key, path in seen.items()}
            report['restore'] = 'PASS' if report['after'] == report['before'] else 'FAIL'
            save()
        return report['build_returncode'] if report['restore'] == 'PASS' else 119


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
