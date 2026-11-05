"""Run's existing causal assessment, hunk ledger and verifier behind a mapping plan."""
from pathlib import Path
import re

from .agent_tools import _write_wrappers


def run_backends(controller, assessment, *, verify, max_attempts, impact_only, mechanical):
    patches, verification, statuses = {}, {}, {}
    for key, child in controller.children.items():
        if not child.case.files:
            continue
        targets = controller.mapping_plan.targets(key)
        child.selected_hunk_ids = {t['unit_id'] for t in targets
                                   if t['status'] == 'AFFECTED' and t['action'] == 'edit'}
        # Donor identity was checked against the complete input patch before any
        # model call. Keep the original engine's blob grounding and history tools.
        child.input_diff = None
        child.donor_repo = Path(controller.donor['donor_git'])
        child.donor_root = child.donor_repo.parent
        child.commit_message = controller.donor.get('commit_message', '')
        child.runtime_factory = controller.factory
        child.model_provider, child.turn_timeout = controller.provider, controller.timeout
        child.record.update(donor_git=str(child.donor_repo),
                            commit_message=child.commit_message,
                            mapping_plan_sha256=controller.mapping_plan.sha256)
        child._write_record()
        _write_wrappers(child.run_dir)
        # Audit the immutable plan and other repositories after every backend
        # model turn, not just after the complete per-repository run.
        original_turn = child._turn
        def audited_turn(*args, _original=original_turn, _key=key, **kwargs):
            before = controller._candidate_hashes(except_key=_key)
            try:
                return _original(*args, **kwargs)
            finally:
                controller._audit_peers(_key, before)
        child._turn = audited_turn
        peers = controller._candidate_hashes(except_key=key)
        try:
            result = child.run(verify=verify, max_attempts=max_attempts,
                               mechanical=mechanical, impact_only=impact_only)
        except Exception as exc:
            # Ordinary exhausted backend failures are local to this repository.
            # Unsafe source/plan/workspace mutations still stop the whole task.
            controller._audit_peers(key, peers)
            statuses[key] = 'FAILED'
            controller.record.setdefault('repository_errors', {})[key] = {
                'type': type(exc).__name__, 'message': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))}
            continue
        controller._audit_peers(key, peers)
        statuses[key] = result['status']
        if result.get('patch_file'):
            patches[key] = {'file': result['patch_file'], 'sha256': result['patch_sha256'],
                            'target': child.case.target_commit, 'replay': result['patch_replay']}
        verification[key] = result.get('final_verification', {'status': 'NOT_RUN'})
    controller.record.update(patches=patches, verification=verification,
                             repository_statuses=statuses, execution_path='mapping_then_run_backend')
    ledger = []
    for unit in assessment['units']:
        expected = {controller._owner(t['path'])[0].key for t in unit['targets']
                    if unit['status'] == 'AFFECTED' and t['action'] == 'edit'}
        claims = {key: next((c for c in controller.children[key].record.get('hunk_results', [])
                            if c['id'] == unit['id']), None) for key in expected}
        ledger.append({'id': unit['id'], 'mapping_status': unit['status'],
                       'expected_repositories': sorted(expected), 'backend_claims': claims,
                       'assessment_evidence': unit['evidence']})
    controller.record['hunk_ledger'] = ledger
    outcomes = set(statuses.values())
    if 'FAILED' in outcomes:
        status = 'FAILED'
    elif 'VALIDATION_FAILED' in outcomes:
        status = 'VALIDATION_FAILED'
    elif 'INCONCLUSIVE' in outcomes:
        status = 'INCONCLUSIVE'
    elif impact_only:
        status = 'AFFECTED' if 'AFFECTED' in outcomes else 'INCONCLUSIVE'
    elif len(statuses) > 1:
        # Per-repository checks do not establish that the combined patch builds.
        # Preserve all independent results until a joint verifier is configured.
        status = 'PATCH_UNVERIFIED'
        controller.record['combined_verification'] = 'NOT_CONFIGURED'
    elif outcomes == {'VALIDATED'}:
        status = 'VALIDATED'
    elif outcomes <= {'NOT_AFFECTED', 'ALREADY_FIXED'}:
        status = 'ALREADY_FIXED' if 'ALREADY_FIXED' in outcomes else 'NOT_AFFECTED'
    else:
        status = 'PATCH_UNVERIFIED'
    controller.record['status'] = status
    for layer in ('source_contract', 'source_extracted_jvm', 'android_module_build', 'android_runtime'):
        values = [v.get('stages', {}).get(layer) for v in verification.values()]
        controller.record[layer] = ('FAIL' if 'FAIL' in values else
            'PASS' if values and all(v == 'PASS' for v in values) else
            'PARTIAL' if 'PASS' in values else 'NOT_CONFIGURED')
    controller.record['patch_replay'] = ('pass' if patches and all(p['replay'] == 'pass' for p in patches.values())
                                         else 'not_run')
    from .diff_engine import _write
    _write(controller.run_dir / 'patch-bundle.json', patches)
    _write(controller.run_dir / 'hunk-ledger.json', ledger)
    if not impact_only:
        from .joint_validation import finish_joint
        finish_joint(controller, verify=verify, assessment=assessment, max_attempts=max_attempts)
    controller._save()
    return controller.record
