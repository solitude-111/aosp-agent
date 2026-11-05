"""Controller-owned validation of the exact final multi-repository candidate."""
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from .engine import _safe_env
from .validation_plan import normalize_checks
from .validation_process import run_check


def prepare_joint(controller, deferred):
    from .diff_engine import _write
    keys = sorted(k for k, child in controller.children.items() if child.case.files)
    explicit = controller.joint_validation
    overrides = normalize_checks(explicit) if explicit is not None else []
    replaced = {check['stage'] for check in overrides}
    generated = []
    for key, check in deferred:
        if check['stage'] in replaced or (explicit is not None and not overrides):
            continue
        artifacts = []
        for artifact in check.get('artifacts', []):
            if not artifact.startswith('out-artifacts/'):
                raise ValueError('deferred build artifacts must use out-artifacts/; configure an explicit joint override')
            artifacts.append('joint-artifacts/' + artifact[len('out-artifacts/'):])
        generated.append({**check, 'artifacts': artifacts, 'covers': [key]})
    # Coalesce only the explicit module-runner interface with literal module
    # names. Arbitrary configured commands are never concatenated heuristically.
    merged = []
    for check in generated:
        mergeable = (controller.build_runner and check['argv'][0] == str(controller.build_runner)
                     and all(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*', arg) for arg in check['argv'][1:]))
        existing = next((c for c in merged if mergeable and c['argv'][0] == check['argv'][0]
                         and all(re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*', arg) for arg in c['argv'][1:])), None)
        if existing:
            existing['argv'] = [existing['argv'][0], *sorted(set(existing['argv'][1:] + check['argv'][1:]))]
            existing['covers'] = sorted(set(existing['covers'] + check['covers']))
            existing['artifacts'] = sorted(set(existing['artifacts'] + check['artifacts']))
        else:
            merged.append(check)
    checks = merged + [{**check, 'covers': keys} for check in overrides]
    for check in checks:
        if any(not path.startswith('joint-artifacts/') for path in check.get('artifacts', [])):
            raise ValueError('joint check artifacts must be under joint-artifacts/')
        controller._freeze_check(check, controller.workspace)
    controller.joint_plan = {'version': 1, 'required_repositories': keys,
        'mapping_plan_sha256': controller.mapping_plan.sha256, 'checks': checks,
        'scope': 'configured_commands_on_exact_candidate_bundle', 'runtime_security_proven': False}
    _write(controller.run_dir / 'joint-validation-plan.json', controller.joint_plan)
    controller._protect(controller.run_dir / 'joint-validation-plan.json')


def candidate_bundle(controller):
    entries, dependencies = [], []
    for key, child in sorted(controller.children.items()):
        if not child.case.files:
            dependencies.append({'key': key, 'target_repo': str(child.repo),
                                 'target_commit': child.case.target_commit})
            continue
        patch_file = child.run_dir / 'backport.patch'
        digest = child.record.get('patch_sha256')
        if (not patch_file.is_file() or not digest or not patch_file.read_bytes().strip()
                or hashlib.sha256(patch_file.read_bytes()).hexdigest() != digest
                or hashlib.sha256(child._render_patch().encode()).hexdigest() != digest):
            raise ValueError('final candidate is missing or changed after export: ' + key)
        entries.append({'key': key, 'target_repo': str(child.repo), 'target_commit': child.case.target_commit,
                        'worktree': str(child.worktree), 'patch_file': str(patch_file), 'sha256': digest})
    if not entries:
        raise ValueError('joint verification requires at least one exported patch')
    return {'version': 1, 'repositories': entries, 'dependencies': dependencies}


def verify_joint(controller):
    from .diff_engine import _write
    checks = controller.joint_plan['checks']
    if not checks:
        return {'status': 'NOT_CONFIGURED', 'sufficient_for_validated': False, 'commands': []}
    controller._audit()
    bundle = candidate_bundle(controller)
    path = controller.run_dir / 'joint-patch-bundle.json'
    _write(path, bundle)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    controller._protect(path)
    attempt = controller.record.get('joint_attempt', 0) + 1
    controller.record['joint_attempt'] = attempt
    results, covered = [], set()
    # Local checks may depend on another candidate. Recheck against the final
    # vector, and include that vector in the cache key so no earlier PASS leaks.
    for key, child in controller.children.items():
        if not child.case.files:
            continue
        child.record['verification_context'] = digest
        local = child.verify()
        child.record['final_verification'] = local
        child._write_record()
        controller.record.setdefault('verification', {})[key] = local
        controller._audit()
        if candidate_bundle(controller) != bundle:
            raise RuntimeError('local validation mutated another candidate in the bundle')
        if local['status'] == 'FAIL':
            result = {'status': 'FAIL', 'blocked_by': 'FINAL_LOCAL_CHECK', 'repository': key,
                      'bundle_sha256': digest, 'sufficient_for_validated': False, 'commands': []}
            _write(controller.run_dir / 'joint-verification.json', result)
            return result
    for number, check in enumerate(checks, 1):
        controller._audit()
        if candidate_bundle(controller) != bundle:
            raise RuntimeError('candidate changed before joint verification')
        artifact_root = controller.run_dir / 'joint-artifacts'
        if artifact_root.is_symlink() or artifact_root.resolve() != artifact_root:
            raise RuntimeError('unsafe joint artifact directory')
        artifact_root.mkdir(exist_ok=True)
        env = _safe_env()
        nonce = f'{digest}:{attempt}:{number}'
        env.update(AOSP_AGENT_PATCH_BUNDLE=str(path), AOSP_AGENT_BUNDLE_SHA256=digest,
                   AOSP_AGENT_WORKTREE=str(controller.workspace), AOSP_AGENT_RUN_DIR=str(controller.run_dir),
                   AOSP_AGENT_ARTIFACT_DIR=str(controller.run_dir / 'joint-artifacts'),
                   AOSP_AGENT_VALIDATION_ID=nonce, AOSP_AGENT_PYTHON=sys.executable)
        # Require outputs from this invocation; a prior successful artifact must
        # not make an incomplete retry look successful. Preserve it as evidence.
        for name in check.get('artifacts', []):
            artifact = controller.run_dir / name
            if not artifact.parent.resolve().is_relative_to(artifact_root):
                raise RuntimeError('unsafe joint artifact parent: ' + name)
            if artifact.exists() or artifact.is_symlink():
                if (artifact.is_symlink() or not artifact.is_file()
                        or not artifact.resolve().is_relative_to(controller.run_dir)):
                    raise RuntimeError('unsafe existing joint artifact: ' + name)
                archive = controller.run_dir / 'previous-joint-artifacts' / f'{attempt}-{number}' / name
                archive.parent.mkdir(parents=True, exist_ok=True)
                artifact.rename(archive)
        started = time.monotonic()
        try:
            stdout, stderr, code = run_check(check['argv'], controller.workspace, env)
        except OSError as exc:
            stdout, stderr, code = '', str(exc), 127
        if check['stage'] == 'android_module_build' and code == 0:
            receipt = controller.run_dir / 'module-build-restore/bundle.json'
            try:
                evidence = json.loads(receipt.read_text())
            except (OSError, ValueError):
                evidence = {}
            if (evidence.get('bundle_sha256') != digest or evidence.get('validation_id') != nonce
                    or evidence.get('restore') != 'PASS' or evidence.get('build_returncode') != 0):
                code = 125
                stderr += '\nmissing fresh successful build/apply/restore receipt for this exact bundle'
        artifacts = []
        for name in check.get('artifacts', []):
            artifact = controller.run_dir / name
            exists = artifact.is_file() and not artifact.is_symlink() and artifact.resolve().is_relative_to(controller.run_dir)
            artifacts.append({'path': name, 'exists': exists,
                              'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest() if exists else None})
            if not exists:
                code = code or 125
                stderr += '\nmissing joint artifact: ' + name
        stem = f'joint-validation-{attempt}-{number}'
        (controller.run_dir / (stem + '.stdout')).write_text(stdout)
        (controller.run_dir / (stem + '.stderr')).write_text(stderr)
        results.append({'stage': check['stage'], 'argv': check['argv'], 'covers': check['covers'],
                        'returncode': code, 'stdout': stdout[-10000:], 'stderr': stderr[-10000:],
                        'stdout_log': stem + '.stdout', 'stderr_log': stem + '.stderr',
                        'elapsed_seconds': round(time.monotonic() - started, 3), 'artifacts': artifacts})
        controller._audit()
        if candidate_bundle(controller) != bundle:
            raise RuntimeError('joint validation mutated the candidate bundle')
        if code:
            break
        if check['stage'] != 'source_contract':
            covered.update(check['covers'])
    passed = all(r['returncode'] == 0 for r in results)
    result = {'status': 'PASS' if passed else 'FAIL', 'commands': results, 'bundle_sha256': digest,
              'sufficient_for_validated': passed and covered == set(controller.joint_plan['required_repositories']),
              'uncovered_repositories': sorted(set(controller.joint_plan['required_repositories']) - covered),
              'scope': controller.joint_plan['scope'], 'runtime_security_proven': False}
    _write(controller.run_dir / 'joint-verification.json', result)
    return result


def finish_joint(controller, *, verify, assessment=None, max_attempts=1):
    # This does not turn a partial migration or a failed independent gate green.
    if controller.record['status'] not in ('VALIDATED', 'PATCH_UNVERIFIED'):
        return
    count = len(controller.joint_plan['required_repositories'])
    if count > 1:
        controller.record['status'] = 'PATCH_UNVERIFIED'
    result = verify_joint(controller) if verify else {'status': 'NOT_REQUESTED', 'commands': []}
    while result['status'] == 'FAIL' and assessment is not None:
        controller.record.setdefault('joint_attempt_results', []).append(result)
        # Coverage is declared by the fixed check, not guessed from compiler
        # output. A local check may depend on any other mapped candidate.
        affected = (set(controller.joint_plan['required_repositories']) if result.get('blocked_by') else
                    {key for c in result['commands'] if c['returncode'] for key in c['covers']})
        repairable = [key for key in sorted(affected)
                      if controller.children[key].record.get('attempt', 0) < max_attempts]
        if not repairable:
            break
        from .text_backend import migrate_repository, collect_results
        for key in repairable:
            migrate_repository(controller, assessment, key, verify=verify,
                max_attempts=max_attempts, feedback={'joint_verification': result,
                    'scope': 'failure belongs to this declared group; repository blame is not established'})
        collect_results(controller, assessment)
        if controller.record['status'] not in ('VALIDATED', 'PATCH_UNVERIFIED'):
            result = {**result, 'repair_status': controller.record['status']}
            break
        result = verify_joint(controller)
    controller.record['joint_verification'] = result
    controller.record['combined_verification'] = result['status']
    required = set(controller.joint_plan['required_repositories'])
    for layer in ('source_contract', 'source_extracted_jvm', 'android_module_build', 'android_runtime'):
        checks = [c for c in result.get('commands', []) if c['stage'] == layer]
        if checks:
            covered = {key for c in checks if not c['returncode'] for key in c['covers']}
            controller.record[layer] = ('FAIL' if any(c['returncode'] for c in checks) else
                                         'PASS' if covered == required else 'PARTIAL')
    if result['status'] == 'FAIL':
        if controller.record['status'] in ('VALIDATED', 'PATCH_UNVERIFIED'):
            controller.record['status'] = 'VALIDATION_FAILED'
    elif result.get('sufficient_for_validated'):
        controller.record['status'] = 'VALIDATED'
        if controller.donor['status'] == 'VERIFIED':
            assess_joint_impact(controller)


def assess_joint_impact(controller):
    """Retain the donor backend's optional business-impact review after joint success."""
    from .git_policy import OFFLINE_GIT_ENV
    from .prompts import SYSTEM
    bundle = candidate_bundle(controller)
    for key, child in controller.children.items():
        if not child.case.files or child.record.get('post_fix_patch_sha256') == child.record.get('patch_sha256'):
            continue
        factory = child.runtime_factory
        if factory is None:
            from .sdk_runtime import CodexRuntime
            factory = CodexRuntime
        try:
            with factory(events_path=child.run_dir / 'sdk-post-fix.jsonl', model=child.model,
                         model_provider=child.model_provider, turn_timeout=child.turn_timeout,
                         env=OFFLINE_GIT_ENV) as runtime:
                runtime.start(child.worktree, SYSTEM + '\nRead-only review of the exact validated candidate bundle.')
                child.assess_post_fix(runtime, child._render_patch(),
                    '\nJoint verification scope: configured checks only; Android runtime security is not proven.\n'
                    + json.dumps(bundle, ensure_ascii=False))
        except Exception as exc:
            child.record['post_fix_impact'] = {'error': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))[:200]}
        finally:
            controller._audit()
            if candidate_bundle(controller) != bundle:
                raise RuntimeError('post-fix review mutated the validated candidate bundle')
        child._write_record()
    controller.record['post_fix_impact'] = {key: c.record.get('post_fix_impact') for key, c in controller.children.items()
                                          if c.case.files}
