"""Delivery eligibility is separate from build receipts and model review.

This policy summarizes controller-owned evidence; it never executes a check or
turns model prose into proof of runtime security. Missing/stale evidence fails
closed. A low-risk review permits handoff, not deployment or a security claim.
"""
from jsonschema import ValidationError, validate

from .prompts import POST_FIX_SCHEMA


CANDIDATE_STATUSES = ('VALIDATED', 'NEEDS_REVIEW', 'PATCH_UNVERIFIED')


def _build(record):
    patches = record.get('patches')
    if patches:
        joint = record.get('joint_verification') or {}
        if (len(patches) > 1 or joint.get('sufficient_for_validated') is True
                or joint.get('status') not in (None, 'NOT_CONFIGURED', 'PASS')):
            evidence = joint
            current = record.get('candidate_bundle_sha256')
            bound = bool(current) and evidence.get('candidate_bundle_sha256') == current
        else:
            key, patch = next(iter(patches.items()))
            evidence = (record.get('verification') or {}).get(key) or {}
            current = patch.get('sha256')
            bound = bool(current) and evidence.get('patch_sha256') == current
            # A single repository's production build can cover its candidate;
            # additional ordinary joint checks must also pass, but cannot erase
            # that build coverage merely because they are not build commands.
            if joint.get('status') == 'PASS':
                bound = (bound and joint.get('policy', {}).get('all_configured_checks_passed') is True
                         and bool(record.get('candidate_bundle_sha256'))
                         and joint.get('candidate_bundle_sha256') == record['candidate_bundle_sha256'])
    else:
        evidence = record.get('final_verification') or {}
        current = record.get('patch_sha256')
        bound = bool(current) and evidence.get('patch_sha256') == current
    sufficient = (bound and evidence.get('status') == 'PASS'
                  and evidence.get('sufficient_for_validated') is True
                  and evidence.get('policy', {}).get('satisfied') is True)
    return {'status': ('PASS' if sufficient else 'FAIL' if evidence.get('status') == 'FAIL'
                       else 'NOT_REQUESTED' if evidence.get('status') == 'NOT_REQUESTED' else 'INCOMPLETE'),
            'evidence_status': evidence.get('status', 'NOT_RUN'), 'candidate_bound': bound,
            'scope': 'declared_production_build_and_configured_checks', 'runtime_security_proven': False}


def _review(record):
    review = record.get('post_fix_review') or {}
    result = {'status': 'INCOMPLETE', 'risks': {}, 'runtime_security_proven': False}
    if review.get('status') != 'COMPLETED':
        result['status'] = 'NOT_REQUESTED' if review.get('status') == 'NOT_REQUESTED' else 'INCOMPLETE'
        return result
    patches = record.get('patches')
    if patches:
        expected = {key: patch.get('sha256') for key, patch in patches.items()}
        bound = (all(expected.values()) and review.get('patches') == expected
                 and bool(record.get('candidate_bundle_sha256'))
                 and review.get('bundle_sha256') == record['candidate_bundle_sha256'])
        outputs = record.get('post_fix_impact') or {}
        complete = (set(outputs) == set(expected) == set(review.get('repositories', {}))
                    and all(v == 'COMPLETED' for v in review['repositories'].values()))
    else:
        current = record.get('patch_sha256')
        bound = bool(current) and review.get('patch_sha256') == current
        outputs = {'patch': record.get('post_fix_impact') or {}}
        complete = True
    if not bound:
        result['status'] = 'STALE'
        return result
    if not complete:
        return result
    try:
        for key, output in outputs.items():
            validate(output, POST_FIX_SCHEMA)
            result['risks'][key] = output['overall_risk']
    except ValidationError:
        return result
    result['status'] = ('PASSED' if result['risks'] and all(v == 'low' for v in result['risks'].values())
                        else 'NEEDS_REVIEW')
    return result


def update_delivery(record):
    """Refresh saved/returned conclusions without discarding build evidence.

    Only completed candidates can become VALIDATED. Failures, recovery barriers,
    incomplete source scope and analysis-only states cannot be promoted by a saved
    review. Repeated calls are safe and re-evaluate changed candidate identities.
    """
    build, review = _build(record), _review(record)
    status = record.get('status')
    reasons = []
    if status in CANDIDATE_STATUSES:
        if build['status'] != 'PASS' or record.get('completion_blocked_by'):
            record['status'] = 'PATCH_UNVERIFIED'
            delivery = 'UNVERIFIED'
            reasons.append(record.get('completion_blocked_by') or 'BUILD_EVIDENCE_INCOMPLETE')
        elif review['status'] != 'PASSED':
            record['status'] = 'NEEDS_REVIEW'
            delivery = 'NEEDS_REVIEW'
        else:
            record['status'] = 'VALIDATED'
            delivery = 'READY_FOR_HANDOFF'
        if review['status'] != 'PASSED':
            reasons.append('POST_FIX_REVIEW_' + review['status'])
    elif status in ('NOT_AFFECTED', 'ALREADY_FIXED', 'AFFECTED', 'DISCOVERED'):
        delivery = 'NOT_APPLICABLE'
    elif status in ('FAILED', 'BLOCKED', 'CANCELLED', 'INCONCLUSIVE', 'INPUT_UNRESOLVED',
                    'VALIDATION_FAILED', 'MIGRATION_INCOMPLETE'):
        delivery = 'BLOCKED'
        reasons.append(status)
    else:
        delivery = 'PENDING'
    record.update(build_validation=build, review_status=review, delivery_status=delivery,
                  delivery={'policy': 'build_and_review_v1', 'status': delivery, 'reasons': reasons,
                            'scope': 'candidate_handoff_only', 'runtime_security_proven': False})
    return record
