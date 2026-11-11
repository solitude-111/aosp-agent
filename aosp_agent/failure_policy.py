"""Controller-owned failure scope; model prose never authorizes resumption."""
import errno


SHARED_KINDS = {
    'AUTH_REQUIRED', 'QUOTA_EXHAUSTED', 'MODEL_UNAVAILABLE',
    'OUTPUT_BUDGET_UNAVAILABLE', 'OUTPUT_BUDGET_EXHAUSTED',
    'VERIFIER_CLEANUP_UNVERIFIED', 'BACKGROUND_CLEANUP_FAILED',
    'SOURCE_AUDIT_UNVERIFIED', 'EXECUTION_OR_RECOVERY_BARRIER',
    'RESUMPTION_PRECONDITION_FAILED', 'ACTIVE_SOURCE_LEASE',
    'BATCH_TIME_BUDGET_EXHAUSTED', 'BATCH_MODEL_BUDGET_EXHAUSTED',
    'BATCH_OUTPUT_BUDGET_EXHAUSTED', 'DISK_SPACE_LOW', 'STORAGE_UNAVAILABLE',
    'HOST_RESOURCE_BLOCKED', 'RECOVERY_BLOCKED', 'ISOLATION_RESTORE_UNVERIFIED',
    'SOURCE_BASE_INVALID', 'SOURCE_BASE_UNAVAILABLE', 'SOURCE_BASE_PATH_OVERLAP',
    'SOURCE_VIEW_UNVERIFIED',
}


def terminal_retry_allowed(record, limit=1):
    """Only an observed model timeout is transient; never reset hard quotas."""
    if (record.get('status') not in ('FAILED', 'INCONCLUSIVE')
            or record.get('terminal_retry_count', 0) >= limit
            or classify_failure(record)['scope'] == 'shared'):
        return False
    if record.get('completion_blocked_by') == 'MODEL_TIMEOUT':
        return True
    return record.get('error', {}).get('kind') == 'TIMEOUT'


def classify_failure(value):
    """Classify existing structured errors, with narrow provider/OS fallbacks."""
    from .lifecycle import LeaseBusy, RecoveryBlocked
    if getattr(value, 'kind', None) == 'CASE_OUTPUT_BUDGET_EXHAUSTED':
        return {'scope': 'case', 'action': 'CONTINUE_BATCH', 'kind': value.kind}
    if isinstance(value, (LeaseBusy, RecoveryBlocked)):
        return {'scope': 'shared', 'action': 'PAUSE_BATCH',
                'kind': getattr(value, 'kind', 'EXECUTION_OR_RECOVERY_BARRIER')}
    if isinstance(value, OSError) and value.errno in (errno.ENOSPC, errno.EDQUOT):
        return {'scope': 'shared', 'action': 'PAUSE_BATCH', 'kind': 'STORAGE_UNAVAILABLE'}
    if isinstance(value, BaseException):
        value = {'kind': getattr(value, 'kind', None), 'message': str(value)}
    if not isinstance(value, dict):
        return {'scope': 'case', 'action': 'CONTINUE_BATCH', 'kind': 'CASE_FAILURE'}
    if value.get('completion_blocked_by') == 'CASE_OUTPUT_BUDGET_EXHAUSTED' or value.get('kind') == 'CASE_OUTPUT_BUDGET_EXHAUSTED':
        return {'scope': 'case', 'action': 'CONTINUE_BATCH', 'kind': 'CASE_OUTPUT_BUDGET_EXHAUSTED'}
    for key in ('kind', 'completion_blocked_by'):
        if value.get(key) in SHARED_KINDS:
            return {'scope': 'shared', 'action': 'PAUSE_BATCH', 'kind': value[key]}
    message = str(value.get('message', '')).lower()
    if 'insufficient balance' in message or 'payment required' in message:
        return {'scope': 'shared', 'action': 'PAUSE_BATCH', 'kind': 'QUOTA_EXHAUSTED'}
    if 'no space left on device' in message or 'disk quota exceeded' in message:
        return {'scope': 'shared', 'action': 'PAUSE_BATCH', 'kind': 'STORAGE_UNAVAILABLE'}
    # Only inspect actual error fields. A model's assessment or source quote
    # mentioning authentication, money or disk space is not a service failure.
    children = [value.get('error')]
    children.extend((value.get('repository_errors') or {}).values())
    for child in children:
        if isinstance(child, dict):
            classification = classify_failure(child)
            if classification['scope'] == 'shared':
                return classification
    return {'scope': 'case', 'action': 'CONTINUE_BATCH',
            'kind': value.get('kind') or value.get('completion_blocked_by') or 'CASE_FAILURE'}
