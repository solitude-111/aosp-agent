"""Identity and fresh evidence for individual controller-owned checks."""
import hashlib
import json
from pathlib import Path
import shutil


def validation_policy(commands, required_repositories, *, expected_checks):
    """Require fresh declared production builds, not arbitrary command success.

    Build receipts attest the configured builder's invocation and restoration;
    they are not semantic security proofs or independent compiler attestation.
    Configuration ownership stays with the controller/operator, never the model.
    """
    required = set(required_repositories)
    covered = {key for c in commands if c.get('returncode') == 0
               and c.get('stage') == 'android_module_build'
               and c.get('build_receipt_verified') is True for key in c.get('covers', [])}
    all_checks_passed = (bool(commands) and len(commands) == expected_checks
                         and all(c.get('returncode') == 0 for c in commands))
    return {'id': 'production_build_v1', 'required_stages': ['android_module_build'],
            'required_repositories': sorted(required), 'build_covered_repositories': sorted(covered & required),
            'missing_build_repositories': sorted(required - covered),
            'all_configured_checks_passed': all_checks_passed,
            'satisfied': bool(required) and all_checks_passed and required <= covered,
            'scope': 'declared_production_build_and_configured_checks', 'runtime_security_proven': False}


def check_identity(check, number, *, cwd, env, patch_sha256, target_commit, context, dependencies):
    """Record check identity, but never infer a closed input set from argv.

    Scripts may import helpers, read configuration or invoke other programs.
    Hashing command arguments cannot prove that those inputs are unchanged.
    Until checks run against a declared, hermetic input snapshot every check
    executes afresh. Immutable Git object reads have a separate safe cache.
    """
    argv = check['argv']
    executable = shutil.which(argv[0], path=env.get('PATH'))
    if '/' in argv[0]:
        executable = str(Path(argv[0]) if Path(argv[0]).is_absolute() else cwd / argv[0])
    files = {}
    for name in ([executable] if executable else []) + list(argv[1:]):
        path = Path(name)
        path = path if path.is_absolute() else cwd / path
        if path.is_file():
            files[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
    identity = dict(check=check, position=number, files=files, patch=patch_sha256,
                    target=target_commit, context=context, dependencies=dependencies,
                    environment_sha256=hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest())
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    return digest, False


def archive_artifacts(check, worktree, run_dir, invocation, number):
    """Preserve prior outputs outside the candidate; they cannot satisfy a retry."""
    for name in check.get('artifacts', []):
        path = worktree / name
        if path.is_symlink() or not path.parent.resolve().is_relative_to(worktree.resolve()):
            raise RuntimeError('unsafe validation artifact: ' + name)
        if path.exists():
            if not path.is_file():
                raise RuntimeError('validation artifact is not a regular file: ' + name)
            archive = run_dir / 'previous-artifacts' / f'{invocation}-{number}' / name
            archive.parent.mkdir(parents=True, exist_ok=True)
            if archive.exists() or archive.is_symlink():
                raise RuntimeError('validation artifact archive already exists')
            path.rename(archive)


def successful_build_receipt(run_dir, *, nonce, patch_sha256, target_commit, target_repo):
    try:
        receipt = json.loads((run_dir / 'module-build-restore/transaction.json').read_text())
    except (OSError, ValueError):
        return False
    return (receipt.get('validation_id') == nonce and receipt.get('patch_sha256') == patch_sha256
            and receipt.get('target_commit') == target_commit and receipt.get('target_repo') == str(target_repo)
            and receipt.get('restore') == 'PASS' and receipt.get('build_returncode') == 0)
