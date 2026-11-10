"""Explicit resume starts a fresh attempt from pinned inputs, never a stale candidate."""
from dataclasses import replace
from contextlib import ExitStack, nullcontext
import hashlib
import json
from pathlib import Path
import uuid

from .discovery import Repository
from .lifecycle import run_lease, source_lease, RecoveryBlocked
from .project_catalog import Project, ProjectCatalog
from .project_first import ProjectFirstAgent
from .diff_engine import _write


def locked_attempt_chain(record_path, leases, inherited=None):
    """Follow durable forward links while reserving every observed attempt.

    Nonblocking leases avoid deadlock with a caller resuming a descendant
    directly. Missing/cyclic/mismatched links are a recovery barrier, never a
    reason to fall back to a stale ancestor and execute it again.
    """
    path, chain, previous = Path(record_path).resolve(), [], None
    seen = set()
    identity = None
    while True:
        from .output_budget import require_output_record
        require_output_record(path)
        if path in seen:
            raise RecoveryBlocked('resumption chain contains a cycle')
        seen.add(path)
        if not path.is_file():
            raise RecoveryBlocked('linked resumption record is missing: ' + str(path))
        lease = leases.enter_context(run_lease(path.parent, inherited if not chain else None))
        try:
            record = json.loads(path.read_text())
            if not isinstance(record, dict):
                raise ValueError('attempt record must be an object')
            current = (record.get('execution_path'), record.get('execution'),
                       record.get('input_patch_sha256'), record.get('input_sha256'))
            if previous is not None and (record.get('resumed_from') != str(previous) or current != identity):
                raise ValueError('linked resumption identity or backlink mismatches')
            link = record.get('resumed_to')
            if link is not None and (not isinstance(link, str) or not Path(link).is_absolute()):
                raise ValueError('resumption link must be an absolute record path')
        except (ValueError, OSError) as exc:
            raise RecoveryBlocked('cannot verify resumption chain: ' + str(exc)) from exc
        identity = current
        chain.append((path, record, lease))
        if link is None:
            return chain
        previous, path = path, Path(link).resolve()


def link_attempt(path, record, successor):
    # Caller holds the predecessor lease. The successor is fully prepared and
    # durable before publishing its path, and must not execute before this edge.
    record['resumed_to'] = str(successor)
    _write(path, record)


def checked_json(path, digest):
    data = path.read_bytes()
    if not digest or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('resume input checksum mismatch: ' + path.name)
    return json.loads(data)


def _accepted_assessment(root, record):
    from .checkpoint import validate_checkpoint
    validate_checkpoint(record)
    if record.get('frontend_workflow', {}).get('mode') == 'location_handoff':
        return _accepted_location(root, record)
    impact = record.get('impact_analysis', {})
    confirmed = impact.get('status') == 'CONFIRMED' and impact.get('decision') == 'AFFECTED'
    pending = not confirmed and impact.get('status') not in ('CONFIRMED', 'CONFLICT')
    field = 'grounded_mapping' if pending else 'impact_analysis'
    checkpoint = record.get(field, {})
    if not checkpoint or not (confirmed or pending):
        return None
    targets = checkpoint.get('targets', {})
    pins = record.get('pinned_targets', {})
    if not targets or set(targets) != set(record.get('selected_projects', [])):
        return None
    if any(pins.get(key, {}).get('head') != head for key, head in targets.items()):
        return None
    round_path = Path(checkpoint['round_record']).resolve()
    if not round_path.is_relative_to(root / 'rounds') or round_path.name != 'run.json':
        raise RecoveryBlocked('accepted assessment round is outside the stopped task')
    row = json.loads(round_path.read_text())
    if (row.get('input_patch_sha256') != record['input_patch_sha256']
            or row.get(field) != {k: v for k, v in checkpoint.items() if k != 'round_record'}):
        raise RecoveryBlocked('accepted assessment identity does not match the stopped task')
    filename = checkpoint['file'] if pending else 'assessment.json'
    if Path(filename).name != filename or not filename.startswith('assessment') or not filename.endswith('.json'):
        raise RecoveryBlocked('invalid saved assessment filename')
    path = round_path.parent / filename
    if path.is_symlink():
        raise RecoveryBlocked('accepted assessment is a symlink')
    from .assessment_repair import MAX_REUSABLE_ASSESSMENT_BYTES
    if path.stat().st_size > MAX_REUSABLE_ASSESSMENT_BYTES:
        return None
    saved = checked_json(path, checkpoint['sha256' if pending else 'assessment_sha256'])
    from .diff_prompts import ASSESSMENT_RESPONSE_SCHEMA
    assessment = {k: v for k, v in saved.items() if k in ASSESSMENT_RESPONSE_SCHEMA['properties']}
    feedback = {k: record.get(k, row.get(k)) for k in
                ('scope_evidence', 'coverage_blockers', 'migration_scope_error',
                 'budget_interruption', 'completion_blocked_by')
                if k in record or k in row}
    if pending:
        feedback['causal_evidence'] = {'status': 'UNRESOLVED', 'reason': checkpoint['proof_error']}
    revalidate = (confirmed and row.get('causal_evidence', {}).get('status') == 'GROUNDED_CAUSAL_PROOFS'
                  and not (feedback.get('coverage_blockers') or feedback.get('migration_scope_error')
                           or feedback.get('scope_evidence', {}).get('status') == 'OPEN_QUESTIONS'))
    return {'targets': targets, 'assessment': assessment, 'feedback': feedback,
            'revalidate': revalidate, 'pending_proof': pending}


def _accepted_location(root, record):
    from .checkpoint import validate_checkpoint
    validate_checkpoint(record)
    from .assessment_repair import MAX_REUSABLE_ASSESSMENT_BYTES
    location = record.get('location_handoff', {})
    targets = location.get('targets', {})
    pins = record.get('pinned_targets', {})
    if (location.get('status') != 'READY' or not targets
            or set(targets) != set(record.get('selected_projects', []))
            or any(pins.get(key, {}).get('head') != head for key, head in targets.items())):
        return None

    def artifact(field, checkpoint, name, digest):
        round_path = Path(checkpoint['round_record']).resolve()
        if not round_path.is_relative_to(root / 'rounds') or round_path.name != 'run.json':
            raise RecoveryBlocked('handoff receipt round is outside the stopped task')
        row = json.loads(round_path.read_text())
        if (row.get('input_patch_sha256') != record['input_patch_sha256']
                or row.get(field) != {k: v for k, v in checkpoint.items() if k != 'round_record'}):
            raise RecoveryBlocked('handoff receipt does not match the stopped task')
        path = round_path.parent / name
        if path.is_symlink() or not path.resolve().is_relative_to(round_path.parent):
            raise RecoveryBlocked('handoff artifact escapes its round')
        return checked_json(path, digest) if path.stat().st_size <= MAX_REUSABLE_ASSESSMENT_BYTES else None

    raw = artifact('location_handoff', location, 'grounded-location.json', location['sha256'])
    if raw is None:
        return None
    impact = record.get('impact_analysis', {})
    backend = None
    if (impact.get('origin') == 'backend' and impact.get('status') == 'CONFIRMED'
            and impact.get('decision') == 'AFFECTED' and impact.get('targets') == targets):
        saved = artifact('impact_analysis', impact, impact['assessment_file'], impact['assessment_sha256'])
        if saved is not None:
            backend = {'targets': targets, 'assessment': saved}
    feedback = {key: record[key] for key in ('coverage_blockers', 'migration_scope_error',
        'migration_scope_diagnostic', 'backend_scope_retry', 'location_gaps', 'scope_requests',
        'backend_conflicts') if record.get(key)}
    if feedback.get('backend_scope_retry'):
        feedback['location_handoff'] = location
    return {'targets': targets, 'location': raw, 'backend_impact': backend, 'feedback': feedback,
            'revalidate': False}


def verify_stopped_sources(root):
    try:
        return _verify_stopped_sources(Path(root))
    except RecoveryBlocked:
        raise
    except Exception as exc:
        raise RecoveryBlocked('cannot verify prior source restoration: ' + str(exc)) from exc


def _verify_stopped_sources(root):
    # Never attempt restoration on behalf of an interrupted transaction here.
    from .runtime_children import verify_run_children
    verify_run_children(root)
    for path in (root / 'rounds').rglob('transaction.json'):
        receipt = json.loads(path.read_text())
        if receipt.get('restore') not in ('PASS', 'NOT_NEEDED'):
            raise RecoveryBlocked('prior build restoration is not verified: ' + str(path))
    baselines = {}
    for path in (root / 'rounds').glob('*/source-baselines.json'):
        for entry in json.loads(path.read_text()).values():
            old = baselines.setdefault(entry['root'], entry['state'])
            if old != entry['state']:
                raise RecoveryBlocked('prior rounds used inconsistent original source baselines')
    for directory, expected in baselines.items():
        actual = Repository('resume-check', Path(directory), expected['head'], {}).state()
        if actual != expected:
            raise RecoveryBlocked('original checkout changed since prior attempt: ' + directory)


def resume_project(record_path, *, runtime_factory=None, run_root=None, task_id=None,
                   _source_lease=None, _previous_lease=None, _on_prepared=None,
                   prepared_case=None, batch_budget=None):
    """Hold the old lease until the fresh attempt ends to prevent two resumes."""
    with ExitStack() as leases:
        chain = locked_attempt_chain(record_path, leases, _previous_lease)
        path, record, _ = chain[-1]
        root = path.parent
        if record.get('execution_path') != 'project_first':
            raise ValueError('resume supports project-first task records only')
        from .checkpoint import validate_checkpoint
        validate_checkpoint(record)
        if record.get('status') in ('VALIDATED', 'NEEDS_REVIEW', 'NOT_AFFECTED', 'ALREADY_FIXED', 'DISCOVERED', 'AFFECTED'):
            raise RecoveryBlocked('latest task attempt is already terminal; resume does not rerun completed tasks: ' + str(path))
        if 'run_options' not in record:
            raise ValueError('task invocation was not recorded; start a new task with explicit options')
        spec = checked_json(root / 'resume-input.json', record.get('resume_input_sha256'))
        if record.get('preparation_receipt') and prepared_case is None:
            raise RecoveryBlocked('isolated task requires run-patches --resume with its batch-status.json')
        lease = leases.enter_context(source_lease(spec['target_root'], _source_lease))
        data = (root / 'input.patch').read_bytes()
        if hashlib.sha256(data).hexdigest() != record['input_patch_sha256']:
            raise ValueError('input patch changed since prior attempt')
        for old_path, _, _ in chain:
            verify_stopped_sources(old_path.parent)
        from .execution_budget import ExecutionBudget
        accounting = record.get('execution_budget')
        execution_budget = None
        if not accounting:
            raise RecoveryBlocked('legacy task has no persistent case accounting; use a separately identified new task')
        if accounting:
            allowed_roots = {p.parent.resolve() for p, _, _ in chain}
            budget_root = Path(accounting['root']).resolve()
            current_path, current_record = chain[0][0], chain[0][1]
            seen = set()
            while budget_root not in allowed_roots and current_record.get('resumed_from'):
                previous_path = Path(current_record['resumed_from']).resolve()
                if previous_path in seen or len(seen) >= 128:
                    raise RecoveryBlocked('invalid accounting ancestry')
                seen.add(previous_path)
                previous_record = json.loads(previous_path.read_text())
                if (previous_record.get('resumed_to') != str(current_path)
                        or previous_record.get('input_patch_sha256') != record['input_patch_sha256']
                        or previous_record.get('execution_budget', {}).get('lineage_id') != accounting['lineage_id']):
                    raise RecoveryBlocked('accounting ancestry identity mismatch')
                allowed_roots.add(previous_path.parent)
                current_path, current_record = previous_path, previous_record
            if budget_root not in allowed_roots:
                raise RecoveryBlocked('case accounting root is outside the locked attempt chain')
            execution_budget = ExecutionBudget(budget_root, record['input_patch_sha256'], existing=True)
            if execution_budget.lineage_id != accounting['lineage_id']:
                raise RecoveryBlocked('case accounting lineage changed')
            for old_path, old_record, _ in chain:
                old_accounting = old_record.get('execution_budget', {})
                if (old_accounting.get('lineage_id') != accounting['lineage_id']
                        or Path(old_accounting.get('root', '')).resolve() != budget_root):
                    raise RecoveryBlocked('linked attempt changed its candidate accounting root')
                from .candidate_store import recover_stopped_candidates
                recover_stopped_candidates(old_path)
            execution_budget.recover_stopped()
            execution_budget.batch_budget = batch_budget
        options = dict(spec['options'])
        if record.get('catalog_sha256'):
            catalog_data = checked_json(root / 'project-catalog.json', record['catalog_sha256'])
            pins = record.get('pinned_targets', {})
            projects = [Project(**p) for p in catalog_data['projects']]
            projects = [replace(p, revision=pins[p.key]['head']) if p.key in pins else p for p in projects]
            options['catalog'] = ProjectCatalog(spec['target_root'], projects, catalog_data['provenance'])
        if prepared_case is not None:
            options['catalog'] = prepared_case.catalog
            options['prepared_case'] = prepared_case
        accepted = _accepted_assessment(root, record)
        if accepted:
            options['resumed_assessment'] = accepted
            candidate_index = execution_budget.root / 'candidate-store/index.json'
            if candidate_index.is_file():
                from .candidate_store import CandidateStore
                store = CandidateStore(candidate_index.parent)
                candidates = store.snapshot()['candidates'].values()
                execution_budget.resume_candidates = {}
                for candidate in sorted(candidates, key=lambda item: item['created_sequence']):
                    identity = candidate['identity']
                    if (identity['targets'] == accepted['targets']
                            and identity['source'] == {'input_sha256': record['input_patch_sha256']}
                            and any(e['kind'] == 'replay' and e['status'] == 'pass' for e in candidate['evidence'])):
                        execution_budget.resume_candidates[identity['repository']] = candidate['id']
        task_id = task_id or 'resume-' + uuid.uuid4().hex[:12]
        agent = ProjectFirstAgent(data, spec['target_root'], run_root or root / 'resumptions', task_id=task_id,
                                  runtime_factory=runtime_factory, execution_budget=execution_budget, **options)
        agent.record.update(resumed_from=str(path), resumption_policy=(
            'checked_assessment_repair_and_fresh_candidates' if accepted else
            'fresh_mapping_and_candidates; immutable_object_cache_only'))
        agent.record['run_options'] = dict(record['run_options'])
        if prepared_case is not None:
            # Every generation must retain its isolation requirement. A raw
            # resume of a later child must not fall back to the shared tree.
            agent.record['preparation_receipt'] = str(prepared_case.receipt_path)
        # A crash before run() must still preserve the pinned catalogue needed
        # to resume this prepared child instead of rediscovering current HEADs.
        if options.get('catalog') is not None:
            _write(agent.run_dir / 'project-catalog.json', options['catalog'].data())
            agent.record['catalog_sha256'] = hashlib.sha256((agent.run_dir / 'project-catalog.json').read_bytes()).hexdigest()
            agent.record['pinned_targets'] = record.get('pinned_targets', {})
        agent._save()
        link_attempt(path, record, agent.run_dir / 'run.json')
        if _on_prepared:
            _on_prepared(agent.run_dir / 'run.json')
        result = agent.run(_source_lease=lease, **record.get('run_options', {}))
        return {**result, 'record': str(agent.run_dir / 'run.json')}


def resume_batch(record_path, *, runtime_factory=None, preparer=None):
    from .runtime_batch import RuntimeBatch
    with ExitStack() as leases:
        chain = locked_attempt_chain(record_path, leases)
        path, record, _ = chain[-1]
        root = path.parent
        if record.get('execution') != 'serial_project_first':
            raise ValueError('unsupported batch record')
        from .checkpoint import validate_checkpoint
        validate_checkpoint(record)
        spec = checked_json(root / 'resume-input.json', record.get('resume_input_sha256'))
        from .failure_policy import terminal_retry_allowed
        retry_limit = spec.get('preparation_config', {}).get('retry_policy', {}).get('max_terminal_retries', 1)
        if record.get('status') == 'COMPLETED' and not any(
                terminal_retry_allowed(row, retry_limit) for row in record.get('rows', [])):
            raise RecoveryBlocked('latest batch has no interrupted or policy-retryable rows: ' + str(path))
        if spec.get('preparation_config'):
            if preparer is None:
                raise RecoveryBlocked('isolated batch requires run-patches --resume with its original server config')
            if preparer.serialized_config() != spec['preparation_config']:
                raise RecoveryBlocked('batch preparation configuration changed across resumption')
        lease = leases.enter_context(source_lease(spec['target_root']))
        data = (root / 'input.jsonl').read_bytes()
        if hashlib.sha256(data).hexdigest() != record['input_sha256']:
            raise ValueError('batch input changed since prior attempt')
        accounting_root = record.get('batch_budget_root')
        if not accounting_root:
            raise RecoveryBlocked('legacy batch has no persistent shared accounting; start a separately identified batch')
        allowed_roots = {p.parent for p, _, _ in chain}
        ancestor_path, ancestor = chain[0][0], chain[0][1]
        seen = set()
        while Path(accounting_root).resolve() not in allowed_roots and ancestor.get('resumed_from'):
            previous_path = Path(ancestor['resumed_from']).resolve()
            if previous_path in seen or len(seen) >= 128:
                raise RecoveryBlocked('invalid shared accounting ancestry')
            seen.add(previous_path)
            previous = json.loads(previous_path.read_text())
            if (previous.get('resumed_to') != str(ancestor_path)
                    or previous.get('input_sha256') != record['input_sha256']
                    or previous.get('batch_budget_root') != accounting_root):
                raise RecoveryBlocked('shared accounting ancestry identity mismatch')
            allowed_roots.add(previous_path.parent)
            ancestor_path, ancestor = previous_path, previous
        if Path(accounting_root).resolve() not in allowed_roots:
            raise RecoveryBlocked('shared accounting root is outside the original batch lineage')
        if record.get('preparation_frozen_receipt'):
            frozen = Path(record['preparation_frozen_receipt'])
            if frozen.is_symlink() or frozen.resolve().parent not in allowed_roots:
                raise RecoveryBlocked('frozen target vector is outside the original batch lineage')
            checked_json(frozen, record.get('preparation_frozen_sha256'))
        # Incomplete transaction recovery is a separate operation. Do not
        # silently run another row against a possibly patched original tree.
        recovered, child_leases = {}, {}
        terminal = {'VALIDATED', 'NEEDS_REVIEW', 'NOT_AFFECTED', 'ALREADY_FIXED', 'DISCOVERED', 'AFFECTED', 'FAILED',
                    'INCONCLUSIVE', 'VALIDATION_FAILED', 'MIGRATION_INCOMPLETE', 'PATCH_UNVERIFIED'}
        for row in record['rows']:
            row = dict(row)
            execution = Path(row.get('execution_record') or Path(row['record']).parent / 'execution/run.json')
            if row.get('execution_record') and not execution.is_file():
                raise RecoveryBlocked('prior row execution record is missing: ' + str(execution))
            if execution.is_file():
                # Keep every old child reserved until the new batch ends. A
                # liveness snapshot alone has a race with standalone resume.
                child_chain = locked_attempt_chain(execution, leases)
                execution, actual, child_leases[row['line']] = child_chain[-1]
                receipt = row.get('preparation_receipt') or actual.get('preparation_receipt')
                if spec.get('preparation_config') and not receipt:
                    raise RecoveryBlocked('isolated row is missing its saved preparation receipt')
                with preparer.activate_receipt(receipt) if receipt and preparer else nullcontext():
                    for old_path, _, _ in child_chain:
                        verify_stopped_sources(old_path.parent)
                if receipt:
                    row['preparation_receipt'] = receipt
                row['execution_record'] = str(execution)
                if row['status'] in ('PREPARING', 'BLOCKED', 'CANCELLED') and actual.get('status') in terminal:
                    row.update({k: v for k, v in actual.items() if k not in ('task_id', 'record')})
            row.pop('retry_terminal', None)
            if terminal_retry_allowed(row, retry_limit):
                row['retry_terminal'] = True
                row['terminal_retry_count'] = row.get('terminal_retry_count', 0) + 1
            recovered[row['line']] = row
        runner = RuntimeBatch(root / 'input.jsonl', spec['target_root'], root / 'resumptions', spec['donor_root'],
            donor_map=spec['donor_map'], agent_options=spec['agent_options'], runtime_factory=runtime_factory,
            _resume_rows=recovered, _resume_leases=child_leases,
            case_output_bytes=spec.get('case_output_bytes'), batch_output_bytes=spec.get('batch_output_bytes'),
            preparer=preparer, frozen_receipt=record.get('preparation_frozen_receipt'),
            batch_budget_root=record.get('batch_budget_root'))
        runner.record.update(resumed_from=str(path), run_options=dict(record.get('run_options', {})))
        runner._save()
        link_attempt(path, record, runner.run_dir / 'batch-status.json')
        result = runner.run(_source_lease=lease, **record.get('run_options', {}))
        return {**result, 'record': str(runner.run_dir / 'batch-status.json')}
