"""One-file launcher for the existing serial batch in a private Linux namespace."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import uuid
import re

from .preparation import PreparationManager, PreparationBlocked, LinuxOverlays, write_receipt
from .lifecycle import RecoveryBlocked, cancellation_signals
from .server_config import AGENT_KEYS, REQUIRED_PATHS, load_config, validate_config, config_digest


# SDK cancellation/close (15s), verifier restoration (30s), integrity audit
# grace (120s), and 15s scheduling/receipt margin. A stuck worker is still killed.
CANCELLATION_CLEANUP_SECONDS = 180


def parser():
    result = argparse.ArgumentParser(description='Run four-field patch JSONL using one server configuration')
    result.add_argument('input', nargs='?', type=Path)
    result.add_argument('--config', type=Path, default=os.environ.get('AOSP_AGENT_SERVER_CONFIG'))
    result.add_argument('--resume', type=Path, help='resume an existing unattended batch-status.json')
    result.add_argument('--inspect-only', action='store_true', help='prepare and discover without model calls')
    result.add_argument('--print-config', action='store_true', help='validate and print non-secret effective configuration')
    result.add_argument('--worker-request', type=Path, help=argparse.SUPPRESS)
    for key in sorted(REQUIRED_PATHS): result.add_argument('--' + key.replace('_', '-'))
    for key in sorted(AGENT_KEYS):
        option = '--' + key.replace('_', '-')
        if key in ('locate_first', 'auto_validation'):
            result.add_argument(option, action=argparse.BooleanOptionalAction, default=None)
        elif key in ('model', 'model_provider', 'mapping_model'):
            result.add_argument(option)
        else:
            result.add_argument(option, type=float if key in ('turn_timeout', 'investigation_seconds', 'case_timeout', 'extension_seconds') else int)
    return result


def _code_identity():
    root = Path(__file__).resolve().parent.parent
    def git(*args):
        return subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=10)
    revision = git('rev-parse', 'HEAD')
    dirty = git('status', '--porcelain', '--untracked-files=normal')
    from .checkpoint import code_identity
    code_sha256 = code_identity()
    identity = {'root': str(root), 'commit': revision.stdout.strip() if revision.returncode == 0 else None,
            'dirty': bool(dirty.stdout) if dirty.returncode == 0 else None,
            'code_sha256': code_sha256, 'commit_source': 'git' if revision.returncode == 0 else 'unverified',
            'python': str(Path(sys.executable).resolve()), 'module': str(Path(__file__).resolve())}
    if revision.returncode != 0:
        manifest = root / 'deployment.json'
        if manifest.is_file() and manifest.stat().st_size <= 4096:
            try:
                saved = json.loads(manifest.read_text())
                if (saved.get('code_sha256') == code_sha256
                        and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', saved.get('commit', ''))):
                    identity.update(commit=saved['commit'], dirty=False, commit_source='verified_deployment_manifest')
            except (ValueError, TypeError): pass
    return identity


@cancellation_signals()
def _worker(path):
    request = json.loads(Path(path).read_text())
    config = validate_config(request['config'])
    if config_digest(config) != request['config_sha256']:
        raise PreparationBlocked('CONFIG_RECEIPT_INVALID', 'launch configuration identity changed')
    launcher = Path(path).parent
    status = {'state': 'PREPARING', 'started_at': time.time(), 'code': _code_identity(),
              'config_sha256': request['config_sha256'], 'process_id': os.getpid()}
    def save(**updates):
        status.update(updates, updated_at=time.time())
        write_receipt(launcher / 'launcher-status.json', status)
    save()
    try:
        overlays = LinuxOverlays(request['parent_namespace'])
        overlays.check_namespace()
        overlays.command(['mount', '--make-rprivate', '/'])
        preparer = PreparationManager(config, overlays=overlays)
        if request.get('resume'):
            from .resume import resume_batch
            save(state='RUNNING')
            outcome = resume_batch(Path(request['resume']), preparer=preparer)
            record = outcome.get('record')
        else:
            from .runtime_batch import RuntimeBatch
            options = {**config['agent'], 'cache_root': Path(config['cache_root']) / 'objects'}
            if config['build'].get('enabled'):
                options['build_runner'] = Path(config['build']['runner'])
            runner = RuntimeBatch(Path(request['input']), config['source_root'], launcher,
                config['donor_root'], donor_map=config['donor_map'], agent_options=options,
                preparer=preparer, case_output_bytes=options.get('max_output_bytes', 256 * 1024 * 1024),
                batch_output_bytes=config['batch_limits'].get('max_output_bytes'))
            record = str(runner.run_dir / 'batch-status.json')
            save(state='RUNNING', batch_record=record)
            outcome = runner.run(inspect_only=request.get('inspect_only', False),
                                 verify=config['build'].get('enabled', False))
        save(state=outcome.get('status', 'FAILED'), batch_record=record,
             counts=outcome.get('counts'), completion_blocked_by=outcome.get('completion_blocked_by'))
        print(json.dumps({'status': outcome.get('status'), 'record': record,
                          'launcher': str(launcher / 'launcher-status.json'), 'counts': outcome.get('counts')}, ensure_ascii=False))
        from .__main__ import exit_status
        return 0 if outcome.get('status') == 'COMPLETED' else exit_status(outcome.get('status'))
    except KeyboardInterrupt as exc:
        save(state='CANCELLED', completion_blocked_by='CANCELLED_BY_USER',
             error={'type': type(exc).__name__, 'message': str(exc)[:1000]})
        return 130
    except BaseException as exc:
        save(state='BLOCKED' if isinstance(exc, RecoveryBlocked) else 'FAILED',
             error={'type': type(exc).__name__, 'kind': getattr(exc, 'kind', None), 'message': str(exc)[:1000]})
        raise


def main(argv=None):
    args = parser().parse_args(argv)
    if args.worker_request:
        return _worker(args.worker_request)
    if not args.config:
        raise ValueError('set AOSP_AGENT_SERVER_CONFIG or pass --config server.json')
    overrides = {key: getattr(args, key) for key in REQUIRED_PATHS | AGENT_KEYS}
    config = load_config(args.config, overrides)
    if args.print_config:
        print(json.dumps(config, indent=2, ensure_ascii=False)); return 0
    if bool(args.input) == bool(args.resume):
        raise ValueError('supply exactly one input JSONL or --resume batch-status.json')
    if sys.platform != 'linux' or not shutil.which('unshare'):
        raise PreparationBlocked('ISOLATION_UNAVAILABLE', 'unattended execution requires Linux user/mount namespaces and unshare')
    if args.input and not args.input.is_file(): raise ValueError('input JSONL does not exist')
    if args.resume and not args.resume.is_file(): raise ValueError('resume record does not exist')
    launcher = Path(config['run_root']) / ('unattended-' + uuid.uuid4().hex[:12])
    launcher.mkdir(parents=True, exist_ok=False)
    write_receipt(launcher / 'effective-config.json', config)
    request = {'version': 1, 'config': config, 'config_sha256': config_digest(config),
        'input': str(args.input.resolve()) if args.input else None,
        'resume': str(args.resume.resolve()) if args.resume else None,
        'inspect_only': args.inspect_only, 'parent_namespace': os.readlink('/proc/self/ns/mnt'),
        'code': _code_identity()}
    path = launcher / 'launch-request.json'; write_receipt(path, request)
    # Keep host PIDs: durable child identities must remain verifiable from a
    # later mount namespace. Source isolation only requires a mount namespace.
    command = ['unshare', '--user', '--map-root-user', '--mount', '--fork',
        '--kill-child=SIGTERM', sys.executable, '-m', 'aosp_agent.unattended',
        '--worker-request', str(path)]
    env = dict(os.environ)
    code = str(Path(__file__).resolve().parent.parent)
    env['PYTHONPATH'] = code + (os.pathsep + env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
    process = subprocess.Popen(command, env=env, start_new_session=True)
    cancellation_deadline = None
    try:
        code = process.wait()
    except KeyboardInterrupt:
        cancellation_deadline = time.monotonic() + CANCELLATION_CLEANUP_SECONDS
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: code = process.wait(timeout=max(0, cancellation_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            # Only a still-owned live wrapper establishes this process group.
            # A completed wrapper's PID/PGID may already have been reused.
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            code = process.wait(timeout=5)
    status_path = launcher / 'launcher-status.json'
    if not status_path.exists():
        write_receipt(status_path, {'state': 'INTERRUPTED' if cancellation_deadline is not None else 'BLOCKED',
            'returncode': code, 'completion_blocked_by': ('CANCELLATION_CLEANUP_UNVERIFIED'
                if cancellation_deadline is not None else 'ISOLATION_LAUNCH_FAILED'), 'code': request['code']})
    else:
        status = json.loads(status_path.read_text())
        if cancellation_deadline is not None:
            # unshare can exit before its signal-aware worker. Wait for that
            # worker's receipt under the original deadline, without signalling
            # an exited wrapper's former process group again.
            while status.get('state') in ('PREPARING', 'RUNNING'):
                remaining = cancellation_deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(.2, remaining))
                status = json.loads(status_path.read_text())
            if (status.get('state') in ('COMPLETED', 'CANCELLED', 'FAILED', 'BLOCKED')
                    and status.get('config_sha256') == request['config_sha256']
                    and type(status.get('process_id')) is int and status['process_id'] > 0):
                from .__main__ import exit_status
                return 0 if status['state'] == 'COMPLETED' else exit_status(status['state'])
            status.update(state='INTERRUPTED', returncode=code, cleanup='UNVERIFIED',
                completion_blocked_by='CANCELLATION_CLEANUP_UNVERIFIED', updated_at=time.time())
            write_receipt(status_path, status)
            return code or 4
        if status.get('state') in ('PREPARING', 'RUNNING'):
            status.update(state='INTERRUPTED', returncode=code,
                          completion_blocked_by='PROCESS_EXIT_WITHOUT_TERMINAL_RECEIPT', updated_at=time.time())
            write_receipt(status_path, status)
    return (code or 4) if cancellation_deadline is not None else code


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, PreparationBlocked) as exc:
        print(json.dumps({'status': 'BLOCKED', 'error': str(exc), 'kind': getattr(exc, 'kind', None)}), file=sys.stderr)
        raise SystemExit(4)
