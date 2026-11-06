"""Serial four-field JSONL execution with per-row, answer-free provenance."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import uuid

from .diff_engine import _write
from .project_first import ProjectFirstAgent
from .retrieval import ReadBudget, BudgetExceeded
from .runtime_input import RuntimeInput, resolve_sources
from .lifecycle import run_lease, source_lease, LeaseBusy, RecoveryBlocked
from .delivery import update_delivery


class RuntimeBatch:
    def __init__(self, input_file, target_root, run_root, donor_root, *, donor_map=None,
                 task_id=None, agent_options=None, runtime_factory=None, _resume_rows=None, _resume_leases=None):
        self.input_file, self.target_root = Path(input_file).resolve(), Path(target_root).resolve()
        self.input_bytes = self.input_file.read_bytes()
        # Every nonblank line keeps its original number, including invalid rows.
        self.lines = [(n, line) for n, line in enumerate(self.input_bytes.decode().splitlines(), 1) if line.strip()]
        if not self.lines:
            raise ValueError('runtime input is empty')
        digest = hashlib.sha256(self.input_bytes).hexdigest()
        from .case import validate_relative_path
        self.task_id = validate_relative_path(task_id or 'batch-' + digest[:12] + '-' + uuid.uuid4().hex[:8])
        self.run_dir = Path(run_root).resolve() / self.task_id
        if self.run_dir.is_relative_to(self.target_root):
            raise ValueError('batch output must be outside target source root')
        self.donor_root, self.donor_map = Path(donor_root).resolve(), donor_map or {}
        if not isinstance(self.donor_map, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.donor_map.items()):
            raise ValueError('donor map must map origin strings to local path strings')
        self.options = dict(agent_options or {})
        forbidden = {'task_id', 'target_revision', 'source_sequence', 'donor_repo', 'source_commit', 'source_parent',
                     'read_budget', 'catalog', 'pinned_heads', 'project_hints'} & set(self.options)
        if forbidden:
            raise ValueError('runtime input identities cannot be overridden: ' + ', '.join(sorted(forbidden)))
        self.runtime_factory = runtime_factory
        self.resume_rows = _resume_rows or {}
        self.resume_leases = _resume_leases or {}
        self.run_dir.mkdir(parents=True, exist_ok=False)
        from .output_budget import create_budget, write_bytes
        self.output_budget = create_budget(self.run_dir, self.options.get('max_output_bytes', 256 * 1024 * 1024))
        write_bytes(self.run_dir / 'input.jsonl', self.input_bytes)
        self.record = {'task_id': self.task_id, 'status': 'PREPARED', 'input_sha256': digest,
                       'execution': 'serial_project_first', 'row_count': len(self.lines), 'rows': [],
                       'runtime_security_proven': False}
        spec = {'target_root': str(self.target_root), 'donor_root': str(self.donor_root),
                'donor_map': self.donor_map, 'agent_options': self.options}
        _write(self.run_dir / 'resume-input.json', json.loads(json.dumps(spec, default=str)))
        self.record['resume_input_sha256'] = hashlib.sha256((self.run_dir / 'resume-input.json').read_bytes()).hexdigest()
        self._save()

    def _save(self):
        self.record['counts'] = dict(Counter(row['status'] for row in self.record['rows']))
        self.record['delivery_counts'] = dict(Counter(row.get('delivery_status', 'PENDING') for row in self.record['rows']))
        self.record['remaining_rows'] = self.record['row_count'] - len(self.record['rows'])
        self.record['output_budget'] = self.output_budget.data()
        _write(self.run_dir / 'batch-status.json', self.record, control=True)

    def run(self, *, _source_lease=None, **run_options):
        with run_lease(self.run_dir):
            self.record['run_options'] = run_options; self._save()
            try:
                with source_lease(self.target_root, _source_lease) as lease:
                    return self._run(lease, **run_options)
            except (LeaseBusy, RecoveryBlocked) as exc:
                self.record.update(status='BLOCKED', completion_blocked_by='EXECUTION_OR_RECOVERY_BARRIER',
                                   error={'type': type(exc).__name__, 'message': str(exc)})
                self._save()
                return self.record
            except KeyboardInterrupt as exc:
                self.record.update(status='CANCELLED', error={'type': type(exc).__name__, 'message': str(exc)})
                self._save()
                return self.record

    def _run(self, lease, **run_options):
        self.record['status'] = 'RUNNING'; self._save()
        for number, line in self.lines:
            self.output_budget.check()
            row_dir = self.run_dir / f'row-{number:04}'
            row_dir.mkdir()
            from .output_budget import write_text
            write_text(row_dir / 'input.json', line + '\n')
            result = {'line': number, 'status': 'PREPARING', 'impact_decision': 'UNKNOWN',
                      'record': str(row_dir / 'run.json')}
            self.record['rows'].append(result)
            _write(row_dir / 'run.json', update_delivery(result), control=True); self._save()
            previous = self.resume_rows.get(number)
            if previous and previous['status'] not in ('PREPARING', 'CANCELLED', 'BLOCKED'):
                previous_record = previous['record']
                result.update({k: v for k, v in previous.items() if k != 'record'})
                result['reused_terminal_record'] = previous_record
                _write(row_dir / 'run.json', update_delivery(result), control=True); self._save()
                continue
            budget = ReadBudget(self.options.get('investigation_seconds', 900), self.options.get('max_git_operations', 2000))
            try:
                if previous and previous.get('execution_record'):
                    from .resume import resume_project
                    outcome = resume_project(previous['execution_record'], runtime_factory=self.runtime_factory,
                        run_root=row_dir, task_id='execution', _source_lease=lease,
                        _previous_lease=self.resume_leases.get(number),
                        _on_prepared=lambda path: self._prepared_execution(row_dir, result, path))
                    result.update({k: v for k, v in outcome.items() if k not in ('task_id', 'record')})
                    result['execution_record'] = outcome['record']
                    _write(row_dir / 'run.json', update_delivery(result), control=True); self._save()
                    if result['status'] in ('CANCELLED', 'BLOCKED'):
                        self.record['status'] = result['status']; self._save()
                        return self.record
                    continue
                with budget.active():
                    task = RuntimeInput.parse(json.loads(line))
                    result['input_task_id'] = task.task_id
                    resolution = resolve_sources(task, self.donor_root, donor_map=self.donor_map)
                    _write(row_dir / 'source-resolution.json', resolution)
                    if resolution['status'] != 'READY':
                        result.update(status='INPUT_UNRESOLVED', problems=resolution['problems'])
                    else:
                        data = ''.join(s['patch'].rstrip('\n') + '\n' for s in resolution['sources']).encode()
                        options = {**self.options}
                        options['cache_root'] = options.get('cache_root') or self.run_dir / '.object-cache'
                        sources = resolution['sources']
                        if len(sources) == 1:
                            source = sources[0]
                            identity = {'donor_repo': source['provenance']['donor_git'],
                                        'source_commit': source['source_commit'], 'source_parent': source['source_parent'],
                                        'project_hints': [c['origin'] for c in source['source_candidates']]}
                        else:
                            identity = {'source_sequence': sources}
                        agent = ProjectFirstAgent(data, self.target_root, row_dir, task_id='execution',
                            target_revision=task.target_revision, read_budget=budget,
                            runtime_factory=self.runtime_factory, **identity, **options)
                        result['execution_record'] = str(agent.run_dir / 'run.json')
                        _write(row_dir / 'run.json', update_delivery(result), control=True); self._save()
                        outcome = agent.run(_source_lease=lease, **run_options)
                        result.update({k: v for k, v in outcome.items() if k not in ('task_id', 'record')})
                        result['execution_record'] = str(agent.run_dir / 'run.json')
            except (LeaseBusy, RecoveryBlocked) as exc:
                result.update(status='BLOCKED', completion_blocked_by='EXECUTION_OR_RECOVERY_BARRIER',
                              error={'type': type(exc).__name__, 'message': str(exc)})
            except BudgetExceeded as exc:
                result.update(status='INCONCLUSIVE', completion_blocked_by='BUDGET_EXHAUSTED',
                              error={'type': type(exc).__name__, 'message': str(exc)})
            except KeyboardInterrupt as exc:
                result.update(status='CANCELLED', completion_blocked_by='CANCELLED_BY_USER',
                              error={'type': type(exc).__name__, 'message': str(exc)})
            except Exception as exc:
                # A failed resume preflight/creation is not an independent case
                # failure: stopped-source and checkpoint safety are unresolved.
                blocked = bool(previous and previous.get('execution_record'))
                result.update(status='BLOCKED' if blocked else 'FAILED',
                              error={'type': type(exc).__name__, 'message': str(exc)[:2000]})
                if blocked:
                    result['completion_blocked_by'] = 'RESUMPTION_PRECONDITION_FAILED'
            result['investigation_budget'] = budget.data()
            _write(row_dir / 'run.json', update_delivery(result), control=True); self._save()
            if result['status'] in ('CANCELLED', 'BLOCKED'):
                self.record['status'] = result['status']; self._save()
                return self.record
        self.record['status'] = 'COMPLETED'; self._save()
        return self.record

    def _prepared_execution(self, row_dir, result, path):
        # Save a resumption's new child before starting it, just like a new row.
        result['execution_record'] = str(path)
        _write(row_dir / 'run.json', update_delivery(result), control=True)
        self._save()
