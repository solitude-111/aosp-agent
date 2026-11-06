"""Explicit resume starts a fresh attempt from pinned inputs, never a stale candidate."""
from dataclasses import replace
from contextlib import ExitStack
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


def verify_stopped_sources(root):
    try:
        return _verify_stopped_sources(Path(root))
    except RecoveryBlocked:
        raise
    except Exception as exc:
        raise RecoveryBlocked('cannot verify prior source restoration: ' + str(exc)) from exc


def _verify_stopped_sources(root):
    # Never attempt restoration on behalf of an interrupted transaction here.
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
                   _source_lease=None, _previous_lease=None, _on_prepared=None):
    """Hold the old lease until the fresh attempt ends to prevent two resumes."""
    with ExitStack() as leases:
        chain = locked_attempt_chain(record_path, leases, _previous_lease)
        path, record, _ = chain[-1]
        root = path.parent
        if record.get('execution_path') != 'project_first':
            raise ValueError('resume supports project-first task records only')
        if record.get('status') in ('VALIDATED', 'NEEDS_REVIEW', 'NOT_AFFECTED', 'ALREADY_FIXED', 'DISCOVERED', 'AFFECTED'):
            raise RecoveryBlocked('latest task attempt is already terminal; resume does not rerun completed tasks: ' + str(path))
        if 'run_options' not in record:
            raise ValueError('task invocation was not recorded; start a new task with explicit options')
        spec = checked_json(root / 'resume-input.json', record.get('resume_input_sha256'))
        lease = leases.enter_context(source_lease(spec['target_root'], _source_lease))
        data = (root / 'input.patch').read_bytes()
        if hashlib.sha256(data).hexdigest() != record['input_patch_sha256']:
            raise ValueError('input patch changed since prior attempt')
        for old_path, _, _ in chain:
            verify_stopped_sources(old_path.parent)
        options = dict(spec['options'])
        if record.get('catalog_sha256'):
            catalog_data = checked_json(root / 'project-catalog.json', record['catalog_sha256'])
            pins = record.get('pinned_targets', {})
            projects = [Project(**p) for p in catalog_data['projects']]
            projects = [replace(p, revision=pins[p.key]['head']) if p.key in pins else p for p in projects]
            options['catalog'] = ProjectCatalog(spec['target_root'], projects, catalog_data['provenance'])
        task_id = task_id or 'resume-' + uuid.uuid4().hex[:12]
        agent = ProjectFirstAgent(data, spec['target_root'], run_root or root / 'resumptions', task_id=task_id,
                                  runtime_factory=runtime_factory, **options)
        agent.record.update(resumed_from=str(path), resumption_policy='fresh_mapping_and_candidates; immutable_object_cache_only')
        agent.record['run_options'] = dict(record['run_options'])
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


def resume_batch(record_path, *, runtime_factory=None):
    from .runtime_batch import RuntimeBatch
    with ExitStack() as leases:
        chain = locked_attempt_chain(record_path, leases)
        path, record, _ = chain[-1]
        root = path.parent
        if record.get('execution') != 'serial_project_first':
            raise ValueError('unsupported batch record')
        if record.get('status') == 'COMPLETED':
            raise RecoveryBlocked('latest batch attempt is already completed; resume does not rerun terminal rows: ' + str(path))
        spec = checked_json(root / 'resume-input.json', record.get('resume_input_sha256'))
        lease = leases.enter_context(source_lease(spec['target_root']))
        data = (root / 'input.jsonl').read_bytes()
        if hashlib.sha256(data).hexdigest() != record['input_sha256']:
            raise ValueError('batch input changed since prior attempt')
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
                for old_path, _, _ in child_chain:
                    verify_stopped_sources(old_path.parent)
                row['execution_record'] = str(execution)
                if row['status'] in ('PREPARING', 'BLOCKED', 'CANCELLED') and actual.get('status') in terminal:
                    row.update({k: v for k, v in actual.items() if k not in ('task_id', 'record')})
            recovered[row['line']] = row
        runner = RuntimeBatch(root / 'input.jsonl', spec['target_root'], root / 'resumptions', spec['donor_root'],
            donor_map=spec['donor_map'], agent_options=spec['agent_options'], runtime_factory=runtime_factory,
            _resume_rows=recovered, _resume_leases=child_leases)
        runner.record.update(resumed_from=str(path), run_options=dict(record.get('run_options', {})))
        runner._save()
        link_attempt(path, record, runner.run_dir / 'batch-status.json')
        result = runner.run(_source_lease=lease, **record.get('run_options', {}))
        return {**result, 'record': str(runner.run_dir / 'batch-status.json')}
