"""Repository-scoped text migration and bounded repairs of mapped candidates."""
import copy
import json
import re
from urllib.parse import quote

from .diff_prompts import MIGRATION_SCHEMA, migration_prompt
from .engine import AssessmentError, CandidateRejected
from .prompts import SYSTEM


def repository_assessment(controller, assessment, key):
    """Project edit obligations, never discard a split region in this repo."""
    local = copy.deepcopy(assessment)
    local['units'] = []
    for unit in assessment['units']:
        targets = [t for t in unit['targets'] if controller._owner(t['path'])[0].key == key]
        if unit['status'] == 'AFFECTED' and any(t['action'] == 'edit' for t in targets):
            local['units'].append({**copy.deepcopy(unit), 'targets': targets})
    local['writable_paths'] = [p for p in assessment['writable_paths'] if controller._owner(p)[0].key == key]
    local['new_files'] = [n for n in assessment['new_files'] if n['path'] in local['writable_paths']]
    return local


def migrate_repository(controller, assessment, key, *, verify, max_attempts, feedback=None):
    from .diff_engine import _write
    child = controller.children[key]
    local = repository_assessment(controller, assessment, key)
    required = {u['id'] for u in local['units']}
    child._current_hunks = [u for u in controller.units if u['id'] in required]
    from .hunk_groups import review_groups, review_prompt
    review = review_groups(child._current_hunks)
    _write(child.run_dir / 'hunk-review-groups.json', review)
    controller._protect(child.run_dir / 'hunk-review-groups.json')
    peers = controller._candidate_hashes(except_key=key)
    try:
        with controller._runtime('migration-' + quote(key, safe='')) as runtime:
            runtime.start(controller.workspace, SYSTEM)
            base = (migration_prompt(controller.diff, local, local['writable_paths'], controller.workspace)
                    + controller._donor_tools_context()
                    + review_prompt(review)
                    + '\nThis session owns ONLY repository ' + key + '. Other candidate repositories are READ ONLY.'
                    + '\nCoverage is required for every unit in the repository assessment above, including all its local split regions.'
                    + '\nComplete fixed mapping (context only; it does not expand your write scope):\n'
                    + json.dumps(assessment, ensure_ascii=False))
            for attempt in range(child.record.get('attempt', 0) + 1, max_attempts + 1):
                child.record['attempt'] = attempt
                prompt = base
                if feedback:
                    prompt += ('\nRepair the current candidate without changing mapping or checks. Controller feedback:\n'
                               + json.dumps(feedback, ensure_ascii=False))
                try:
                    raw = controller._turn(runtime, prompt, MIGRATION_SCHEMA, read_only=False)
                finally:
                    controller._audit_peers(key, peers)
                _write(child.run_dir / f'coverage-{attempt}.json', raw)
                error, blocked = None, 'HUNK_LEDGER'
                try:
                    controller._coverage(raw, local)
                except AssessmentError as exc:
                    error = str(exc)
                try:
                    patch = child.export_patch(attempt)
                except CandidateRejected as exc:
                    patch, error, blocked = '', str(exc), 'NEW_FILE_INTEGRATION'
                if not patch.strip():
                    error = error or 'affected repository produced no patch'
                if not error:
                    declarations = '\n'.join(f"HUNK-RESULT {c['id']} implemented {c['explanation']}"
                                             for c in raw['coverage'] if c['id'] in required)
                    ledger = child._check_hunk_results(declarations, child._last_audit['changed_files'], patch)
                    child.record['hunk_results'] = ledger['claims']
                    if not ledger['ok']:
                        error = ledger['feedback']
                verification = ({'status': 'NOT_RUN', 'blocked_by': blocked} if error else
                                child.verify() if verify else {'status': 'NOT_REQUESTED'})
                controller._audit_peers(key, peers)
                status = ('MIGRATION_INCOMPLETE' if error else 'VALIDATION_FAILED' if verification['status'] == 'FAIL'
                          else 'VALIDATED' if verification.get('sufficient_for_validated') else 'PATCH_UNVERIFIED')
                child.record.update(status=status, final_verification=verification, coverage=raw)
                if error:
                    child.record['coverage_error'] = error
                else:
                    child.record.pop('coverage_error', None)
                child.record.setdefault('attempt_verifications', {})[str(attempt)] = verification
                child._write_record()
                if status in ('VALIDATED', 'PATCH_UNVERIFIED'):
                    return
                feedback = {'coverage_error': error, 'verification': verification, 'previous_feedback': feedback}
    except Exception as exc:
        # Source/plan/scope violations remain fatal. Ordinary runtime exhaustion
        # is local and must not prevent later independent repositories running.
        controller._audit_peers(key, peers)
        child.record.update(status='FAILED', error={'type': type(exc).__name__,
            'message': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))})
        child._write_record()


def collect_results(controller, assessment):
    from .diff_engine import _write
    patches, verification, statuses, errors = {}, {}, {}, {}
    for key, child in controller.children.items():
        if not child.case.files:
            continue
        statuses[key] = child.record['status']
        verification[key] = child.record.get('final_verification', {'status': 'NOT_RUN'})
        if child.record.get('coverage_error'):
            errors[key] = child.record['coverage_error']
        if child.record.get('patch_file'):
            patches[key] = {'file': child.record['patch_file'], 'sha256': child.record['patch_sha256'],
                            'target': child.case.target_commit, 'replay': child.record['patch_replay']}
    outcomes = set(statuses.values())
    status = next((s for s in ('FAILED', 'MIGRATION_INCOMPLETE', 'VALIDATION_FAILED', 'INCONCLUSIVE')
                   if s in outcomes), 'VALIDATED' if outcomes == {'VALIDATED'} and len(statuses) == 1 else 'PATCH_UNVERIFIED')
    controller.record.update(patches=patches, verification=verification, repository_statuses=statuses, status=status)
    if errors:
        controller.record['coverage_error'] = '; '.join(key + ': ' + error for key, error in sorted(errors.items()))
    else:
        controller.record.pop('coverage_error', None)
    controller.record['patch_replay'] = 'pass' if patches and all(p['replay'] == 'pass' for p in patches.values()) and not errors else 'not_run'
    for layer in ('source_contract', 'source_extracted_jvm', 'android_module_build', 'android_runtime'):
        values = [v.get('stages', {}).get(layer) for v in verification.values()]
        controller.record[layer] = ('FAIL' if 'FAIL' in values else 'PASS' if values and all(v == 'PASS' for v in values)
                                    else 'PARTIAL' if 'PASS' in values else 'NOT_CONFIGURED')
    ledger = []
    for unit in assessment['units']:
        keys = {controller._owner(t['path'])[0].key for t in unit['targets']
                if unit['status'] == 'AFFECTED' and t['action'] == 'edit'}
        ledger.append({'id': unit['id'], 'mapping_status': unit['status'], 'expected_repositories': sorted(keys),
                       'backend_claims': {key: next((c for c in controller.children[key].record.get('hunk_results', [])
                                                    if c['id'] == unit['id']), None) for key in keys},
                       'assessment_evidence': unit['evidence']})
    controller.record['hunk_ledger'] = ledger
    _write(controller.run_dir / 'patch-bundle.json', patches)
    _write(controller.run_dir / 'hunk-ledger.json', ledger)


def run_text_backends(controller, assessment, *, verify, max_attempts):
    for key, child in controller.children.items():
        if child.case.files:
            migrate_repository(controller, assessment, key, verify=verify, max_attempts=max_attempts)
    collect_results(controller, assessment)
    controller.record['execution_path'] = 'mapping_then_text_backends'
    from .joint_validation import finish_joint
    finish_joint(controller, verify=verify, assessment=assessment, max_attempts=max_attempts)
    controller._save()
    return controller.record
