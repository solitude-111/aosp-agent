"""Project-first front end: plan, inspect selected projects, expand, remap.

Each remapping round owns a new immutable plan and fresh candidate worktrees.
Only immutable object reads are shared across rounds; verification results are
never copied between candidate generations.
"""
import hashlib
import json
from pathlib import Path

from .case import validate_relative_path
from .diff_engine import DiffBackportAgent, _write
from .diff_prompts import STRING, array, obj
from .discovery import diff_units, repository_roots
from .donor import verify_donor, verify_source_sequence
from .git_policy import OFFLINE_GIT_ENV
from .mapping_plan import _shape
from .project_catalog import Project, ProjectCatalog, catalog_at_revision, catalog_from_checkout
from .retrieval import ACTIVE_BUDGET, ACTIVE_MODEL_BUDGET, BudgetExceeded, ObjectCache, ReadBudget
from .lifecycle import run_lease, source_lease, LeaseBusy, RecoveryBlocked


PREANALYSIS_SCHEMA = obj({'summary': STRING, 'projects': array(obj({'key': STRING, 'reason': STRING})),
    'obligations': array(obj({'unit_id': STRING, 'security_operation': STRING,
                              'questions': array(STRING)})), 'unresolved_questions': array(STRING)})


class RoutingUnresolved(ValueError):
    pass


def checkout_catalog(root, pinned_heads=None):
    """Current-checkout mode still uses metadata only before admission.

    A named release must use catalog_at_revision instead. In current mode each
    admitted HEAD is pinned once and retained through every remapping round.
    """
    root = Path(root).resolve()
    pins = pinned_heads or {}
    original = catalog_from_checkout(root, pins)
    if original:
        projects = list(original.projects.values())
        provenance = original.provenance
    else:
        roots = repository_roots(root)  # Directory metadata only; no Git commands.
        projects = [Project(p.relative_to(root).as_posix() if p != root else 'repo',
                            p.relative_to(root).as_posix() if p != root else 'repo',
                            pins.get(p.relative_to(root).as_posix() if p != root else 'repo', 'HEAD')) for p in roots]
        provenance = {'scope': 'checkout_directory_metadata', 'target_policy': 'current_heads_pinned_on_admission'}
    if set(pins) - {p.key for p in projects}:
        raise ValueError('required pinned project is absent from target catalogue')
    return ProjectCatalog(root, projects, provenance)


class ModelTurnLimit:
    def __init__(self, factory=None, limit=48):
        self.factory, self.limit, self.used = factory, limit, 0
        self.exhausted = False

    def claim(self):
        if self.used >= self.limit:
            self.exhausted = True
            raise BudgetExceeded('total model turn budget exhausted')
        self.used += 1

    def __call__(self, **options):
        if self.factory is None:
            from .sdk_runtime import CodexRuntime
            factory = CodexRuntime
        else:
            factory = self.factory
        owner = self
        class LimitedRuntime:
            def __enter__(self):
                self.manager = factory(**options)
                self.runtime = self.manager.__enter__()
                return self
            def __exit__(self, *args):
                return self.manager.__exit__(*args)
            def __getattr__(self, key):
                return getattr(self.runtime, key)
            def run(self, *args, **kwargs):
                budget = ACTIVE_BUDGET.get()
                if budget:
                    budget.remaining()
                # The SDK counts actual turns, including JSON correction turns.
                # Runtime doubles/other adapters count one call unless they opt
                # into the same accounting contract.
                if not getattr(self.runtime, 'accounts_model_calls', False):
                    owner.claim()
                token = ACTIVE_MODEL_BUDGET.set(owner)
                try:
                    return self.runtime.run(*args, **kwargs)
                finally:
                    ACTIVE_MODEL_BUDGET.reset(token)
        return LimitedRuntime()


class ProjectFirstAgent:
    def __init__(self, patch, target_root, run_root, *, task_id=None, catalog=None,
                 target_revision=None, pinned_heads=None, repository_keys=None,
                 donor_repo=None, source_commit=None, source_parent=None, source_sequence=None,
                 model=None, mapping_model=None, model_provider=None, turn_timeout=900,
                 runtime_factory=None, validation=None, joint_validation=None, auto_validation=True,
                 build_runner=None, cache_root=None, max_projects=12, max_rounds=3,
                 investigation_seconds=900, max_git_operations=2000, max_model_turns=48,
                 project_hints=None, read_budget=None, max_output_bytes=256 * 1024 * 1024):
        self.patch = patch if isinstance(patch, bytes) else Path(patch).read_bytes()
        self.units = diff_units(self.patch.decode())
        self.target_root = Path(target_root).resolve()
        self.task_id = validate_relative_path(task_id) if task_id else 'patch-' + hashlib.sha256(self.patch).hexdigest()[:16]
        self.run_dir = Path(run_root).resolve() / self.task_id
        if self.run_dir.is_relative_to(self.target_root):
            raise ValueError('run directory must be outside target source root')
        if max_projects < 1 or max_rounds < 1 or max_model_turns < 1:
            raise ValueError('scope and model budgets must be positive')
        self.run_dir.mkdir(parents=True, exist_ok=False)
        from .output_budget import create_budget
        self.output_budget = create_budget(self.run_dir, max_output_bytes)
        self.record = {'task_id': self.task_id, 'status': 'PREPARING', 'impact_decision': 'UNKNOWN',
                       'execution_path': 'project_first', 'input_patch_sha256': hashlib.sha256(self.patch).hexdigest(),
                       'rounds': [], 'runtime_security_proven': False, 'model_execution': 'not_run'}
        self.budget = read_budget or ReadBudget(investigation_seconds, max_git_operations)
        self.factory = ModelTurnLimit(runtime_factory, max_model_turns)
        self.model, self.mapping_model, self.provider = model, mapping_model or model, model_provider
        self.timeout, self.max_projects, self.max_rounds = turn_timeout, max_projects, max_rounds
        self.catalog, self.target_revision, self.pinned_heads = catalog, target_revision, pinned_heads
        self.explicit_keys = repository_keys
        self.project_hints = list(project_hints or [])
        self.donor_options = dict(donor_repo=donor_repo, source_commit=source_commit, source_parent=source_parent)
        self.source_sequence = source_sequence
        self.options = dict(model=model, mapping_model=mapping_model, model_provider=model_provider,
                            turn_timeout=turn_timeout, runtime_factory=self.factory, validation=validation,
                            joint_validation=joint_validation, auto_validation=auto_validation, build_runner=build_runner)
        cache_path = Path(cache_root).resolve() if cache_root else self.run_dir.parent / '.object-cache'
        if cache_path.is_relative_to(self.target_root) or cache_path.is_relative_to(self.run_dir):
            raise ValueError('shared object cache must be outside source and task workspaces')
        self.cache = ObjectCache(cache_path)
        from .output_budget import write_bytes
        write_bytes(self.run_dir / 'input.patch', self.patch)
        def serial(value):
            if isinstance(value, Path):
                return str(value)
            if isinstance(value, dict):
                return {k: serial(v) for k, v in value.items()}
            if isinstance(value, (list, tuple)):
                return [serial(v) for v in value]
            return value
        self.resume_spec = serial({'target_root': self.target_root,
            'options': {**{k: v for k, v in self.options.items() if k != 'runtime_factory'},
                **self.donor_options, 'source_sequence': self.source_sequence, 'target_revision': self.target_revision,
                'pinned_heads': self.pinned_heads, 'repository_keys': self.explicit_keys, 'project_hints': self.project_hints,
                'cache_root': self.cache.directory, 'max_projects': max_projects, 'max_rounds': max_rounds,
                'investigation_seconds': investigation_seconds, 'max_git_operations': max_git_operations,
                'max_model_turns': max_model_turns, 'max_output_bytes': max_output_bytes}})
        _write(self.run_dir / 'resume-input.json', self.resume_spec)
        self.record['resume_input_sha256'] = hashlib.sha256((self.run_dir / 'resume-input.json').read_bytes()).hexdigest()
        self._save()

    def _save(self):
        from .delivery import update_delivery
        update_delivery(self.record)
        self.record['investigation_budget'] = self.budget.data()
        self.record['model_turns'] = {'used': self.factory.used, 'limit': self.factory.limit}
        self.record['object_cache'] = self.cache.data()
        self.record['output_budget'] = self.output_budget.data()
        _write(self.run_dir / 'run.json', self.record, control=True)

    def _prepare(self):
        from .output_budget import write_bytes
        write_bytes(self.run_dir / 'input.patch', self.patch)
        if self.source_sequence is not None:
            if any(v is not None for v in self.donor_options.values()):
                raise ValueError('use either source sequence or single donor')
            self.units, self.provenance = verify_source_sequence(self.source_sequence, self.patch.decode())
        else:
            self.provenance = verify_donor(self.donor_options['donor_repo'], self.donor_options['source_commit'],
                                           self.donor_options['source_parent'], self.patch.decode())
        if self.catalog is None:
            self.catalog = (catalog_at_revision(self.target_root, self.target_revision) if self.target_revision else
                            checkout_catalog(self.target_root, self.pinned_heads))
        _write(self.run_dir / 'project-catalog.json', self.catalog.data())
        self.record['catalog_sha256'] = hashlib.sha256((self.run_dir / 'project-catalog.json').read_bytes()).hexdigest()
        self.record['catalog_provenance'] = self.catalog.provenance
        self.record['source_provenance'] = self.provenance
        self._save()

    def _plan(self, number, feedback=None, max_attempts=3):
        inventory = [{'key': p.key, 'name': p.name} for p in self.catalog.projects.values()]
        # A catalogue is metadata, not source evidence. The model may inspect
        # the complete saved catalogue; only the first shortlist is inlined.
        hints = list(self.project_hints)
        if self.source_sequence:
            hints.extend(c['origin'] for s in self.source_sequence for c in s.get('source_candidates', []))
        matching = set(self.catalog.candidates(hints))
        units = [{'id': u['id'], 'old_path': u['old_path'], 'new_path': u['new_path'],
                  'header': u.get('header', ''), 'before': u['before'], 'after': u['after']} for u in self.units]
        paths = ' '.join(str(u.get('new_path') or u.get('old_path') or '') for u in self.units)
        ordered = sorted(inventory, key=lambda p: (p['key'] not in matching,
                         not any(part in paths for part in p['key'].split('/') if len(part) > 3), p['key']))
        prompt = ('Analyze the complete repair input BEFORE target source reads. Work READ ONLY. '
                  'Select a small initial project set from the supplied catalogue, identifying the security operation '
                  'and investigation questions for every source unit. Do not decide affectedness. Do not run Git, '
                  'read target source files, scan target directories or start builds in this planning phase. '
                  'Donor project names and paths are hints; old releases may move or split implementations. '
                  'Never select every project merely because an earlier search failed. Missing objects are not absence. '
                  'The later investigator can request additional projects with grounded evidence. '
                  f'At most {self.max_projects} projects may be admitted. Complete metadata is in project-catalog.json.\n'
                  + json.dumps({'catalog_shortlist': ordered[:80], 'catalog_count': len(inventory),
                                'source_units': units, 'source_provenance': self.provenance,
                                'previous_round_feedback': feedback}, ensure_ascii=False))
        self.record['status'] = 'PREANALYZING'; self._save()
        from .sandbox_scope import ModelScope
        with self.factory(events_path=self.run_dir / f'sdk-routing-{number}.jsonl', model=self.mapping_model,
                          model_provider=self.provider, turn_timeout=min(self.timeout, self.budget.remaining()),
                          env=OFFLINE_GIT_ENV, read_scope=ModelScope((str(self.run_dir),))) as runtime:
            runtime.start(self.run_dir, 'Read-only patch preanalysis and project routing. No target source reads yet.')
            correction = ''
            for attempt in range(1, max_attempts + 1):
                result = runtime.run(prompt + correction, read_only=True, output_schema=PREANALYSIS_SCHEMA)
                if result.get('status') != 'completed':
                    raise RuntimeError('routing model did not complete')
                try:
                    plan = result.get('output') or json.loads(result.get('final_response', '{}'))
                    _write(self.run_dir / f'routing-response-{number}-{attempt}.json', plan)
                    _shape(plan, PREANALYSIS_SCHEMA)
                    expected = {u['id'] for u in self.units}
                    if len(plan['obligations']) != len(expected) or {o['unit_id'] for o in plan['obligations']} != expected:
                        raise ValueError('preanalysis must account for every source step and unit')
                    keys = [p['key'] for p in plan['projects']]
                    self._check_keys(keys)
                    if number > 1:
                        self._check_keys(list(dict.fromkeys(self.record.get('selected_projects', []) + keys)))
                except ValueError as exc:
                    self.record.setdefault('routing_rejections', []).append({
                        'round': number, 'attempt': attempt, 'reason': str(exc)})
                    self._save()
                    if attempt == max_attempts:
                        raise RoutingUnresolved('routing correction attempts exhausted') from exc
                    correction = ('\nCorrect the entire plan under the same scope and source obligations. '
                                  'Rejected previous selection: ' + str(exc))
                    continue
                _write(self.run_dir / f'routing-plan-{number}.json', plan)
                return keys, plan

    def _check_keys(self, keys):
        if not keys or len(set(keys)) > self.max_projects or len(set(keys)) != len(keys):
            raise ValueError('empty, duplicate or over-budget project selection')
        if set(keys) - set(self.catalog.projects):
            raise ValueError('selected project is not in the target catalogue')

    def run(self, *, inspect_only=False, max_attempts=3, verify=False, impact_only=False, mechanical=True,
            _source_lease=None):
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValueError('max_attempts must be a positive integer')
        with run_lease(self.run_dir):
            self.record['run_options'] = dict(inspect_only=inspect_only, max_attempts=max_attempts, verify=verify,
                                               impact_only=impact_only, mechanical=mechanical)
            self._save()
            try:
                with source_lease(self.target_root, _source_lease) as lease:
                    return self._run(inspect_only=inspect_only, max_attempts=max_attempts, verify=verify,
                                     impact_only=impact_only, mechanical=mechanical, _source_lease=lease)
            except LeaseBusy as exc:
                self.record.update(status='BLOCKED', impact_decision='UNKNOWN', completion_blocked_by='ACTIVE_SOURCE_LEASE',
                                   error={'type': type(exc).__name__, 'message': str(exc)})
                self._save()
                return self.record

    def _run(self, *, inspect_only=False, max_attempts=3, verify=False, impact_only=False, mechanical=True,
             _source_lease=None):
        controller = None
        try:
            with self.budget.active():
                self._prepare()
                if self.explicit_keys is not None:
                    keys = list(dict.fromkeys(self.explicit_keys)); self._check_keys(keys)
                    plan = {'summary': 'Explicit user-supplied project scope', 'projects': keys}
                elif inspect_only:
                    hints = list(self.project_hints)
                    if self.source_sequence:
                        hints.extend(c['origin'] for s in self.source_sequence for c in s.get('source_candidates', []))
                    keys = (list(self.catalog.projects) if len(self.catalog.projects) == 1 else
                            list(dict.fromkeys(list(self.pinned_heads or {}) + self.catalog.candidates(hints))))
                    if not keys or len(keys) > self.max_projects:
                        self.record.update(status='INCONCLUSIVE', completion_blocked_by='INSPECTION_REQUIRES_PROJECT_SCOPE',
                            message='No unambiguous metadata scope; supply --repository or enable model routing.')
                        self._save()
                        return self.record
                    self._check_keys(keys)
                    plan = {'summary': 'Metadata-only inspection hints; no model or semantic conclusion', 'projects': keys}
                else:
                    keys, plan = self._plan(1, max_attempts=max_attempts)
                feedback = None
                for number in range(1, self.max_rounds + 1):
                    self.budget.remaining()
                    pins = {k: self.catalog.pin(k)['head'] for k in keys}
                    self.record.update(status='INVESTIGATING', selected_projects=keys, pinned_targets=dict(self.catalog.pins))
                    self._save()
                    context = ('\nProject-first investigation. Do not read unloaded projects directly. '
                               'Request needed projects using repository_requests [{repository, unit_id, reason, evidence}]. '
                               'Each request must cite exact loaded target or supplied patch evidence. '
                               'No requests means you must provide scope_closure.units covering every unit: '
                               'unit_id, security_operation, entrypoint_and_flow, dependencies_checked (loaded project keys), '
                               'unresolved_questions, evidence, proof_steps. proof_steps must cover entrypoint, state_flow, '
                               'security_condition and dependency exactly once, each with reasoning and 1-based evidence indices. '
                               'Every step needs target evidence inside the mapped region; dependencies_checked must name '
                               'exactly the evidenced mapped projects. Cite both available donor diff sides and every mapped '
                               'target region, including read dependencies. Open necessary questions block a final conclusion. '
                               'Do not treat a missing modern interface as an absent older operation. '
                               'Use the saved project catalogue for project names, not arbitrary filesystem scans.\n'
                               + json.dumps({'preanalysis': plan, 'catalog_file': str(self.run_dir / 'project-catalog.json'),
                                             'previous_feedback': feedback}, ensure_ascii=False))
                    controller = DiffBackportAgent(self.patch, self.target_root, self.run_dir / 'rounds',
                        task_id=f'r{number:02}', repository_keys=keys, pinned_heads=pins, lazy_reads=True,
                        object_cache=self.cache, assessment_context=context, require_scope_closure=True,
                        read_denied_roots=[self.target_root / p.key for p in self.catalog.projects.values()
                                           if p.key not in keys and any(p.key.startswith(k + '/') for k in keys)],
                        source_sequence=self.source_sequence, _source_lease=_source_lease,
                        **self.donor_options, **self.options)
                    self.record['active_round_record'] = str(controller.run_dir / 'run.json'); self._save()
                    result = controller.run(inspect_only=inspect_only, max_attempts=max_attempts, verify=verify,
                                            impact_only=impact_only, mechanical=mechanical, _source_lease=_source_lease)
                    if self.factory.exhausted:
                        raise BudgetExceeded('total model turn budget exhausted in a backend')
                    self.record['rounds'].append({'round': number, 'record': str(controller.run_dir / 'run.json'),
                                                  'status': result['status'], 'projects': list(keys),
                                                  'mapping_plan_sha256': result.get('mapping_plan_sha256')})
                    self.record['model_execution'] = result.get('model_execution', 'not_run')
                    if inspect_only:
                        return self._finish(result)
                    requests = result.get('scope_requests') or []
                    feedback = {k: result[k] for k in ('status', 'replan_required', 'scope_evidence', 'backend_conflicts',
                                'causal_evidence', 'coverage_error', 'repository_errors', 'verification', 'joint_verification') if k in result}
                    if requests:
                        expanded = list(dict.fromkeys(keys + [r['repository'] for r in requests]))
                        self._check_keys(expanded)
                        if expanded == keys:
                            return self._finish(result, blocked='EXPANSION_MADE_NO_PROGRESS')
                        plan = {'summary': 'Expansion justified by grounded source evidence', 'requests': requests}
                        keys = expanded
                    elif result.get('replan_required') or result['status'] in ('MIGRATION_INCOMPLETE', 'VALIDATION_FAILED'):
                        if number < self.max_rounds:
                            selected, plan = self._plan(number + 1, feedback, max_attempts=max_attempts)
                            keys = list(dict.fromkeys(keys + selected)); self._check_keys(keys)
                    else:
                        return self._finish(result)
                    self.record['status'] = 'REPLANNING'; self._save()
                return self._finish(result, blocked='REPLANNING_BUDGET_EXHAUSTED')
        except RecoveryBlocked as exc:
            self.record.update(status='BLOCKED', impact_decision='UNKNOWN',
                               completion_blocked_by=getattr(exc, 'kind', 'EXECUTION_OR_RECOVERY_BARRIER'),
                               error={'type': type(exc).__name__, 'message': str(exc)})
        except RoutingUnresolved as exc:
            self.record.update(status='INCONCLUSIVE', impact_decision='UNKNOWN', completion_blocked_by='ROUTING_UNRESOLVED',
                               error={'type': type(exc).__name__, 'message': str(exc)})
        except BudgetExceeded as exc:
            self.record.update(status='INCONCLUSIVE', impact_decision='UNKNOWN', completion_blocked_by='BUDGET_EXHAUSTED',
                               error={'type': type(exc).__name__, 'message': str(exc)})
        except KeyboardInterrupt as exc:
            self.record.update(status='CANCELLED', impact_decision='UNKNOWN',
                               completion_blocked_by='CANCELLED_BY_USER', error={'type': type(exc).__name__, 'message': str(exc)})
            if controller is not None:
                try:
                    controller._originals_unchanged()
                    self.record['cancellation_source_guard'] = 'PASS'
                except Exception as audit:
                    self.record['cancellation_source_guard'] = 'UNVERIFIED'
                    self.record['cancellation_guard_error'] = str(audit)
                controller.record.update(status='CANCELLED', impact_decision='UNKNOWN', completion_blocked_by='CANCELLED_BY_USER')
                controller._save()
        except Exception as exc:
            self.record.update(status='FAILED', error={'type': type(exc).__name__, 'message': str(exc)[:2000]})
        self._save()
        return self.record

    def _finish(self, result, blocked=None):
        for key in ('status', 'impact_decision', 'patches', 'verification', 'joint_verification',
                    'repository_statuses', 'android_module_build', 'patch_replay', 'source_guard', 'error',
                    'analysis_scope', 'inventory_status', 'completion_blocked_by', 'causal_evidence', 'model_read_boundary',
                    'retrieval_summary', 'discovery_status',
                    'post_fix_review', 'post_fix_impact', 'candidate_bundle_sha256'):
            if key in result:
                self.record[key] = result[key]
        self.record['final_round_record'] = self.record['rounds'][-1]['record']
        self.record['selected_projects'] = self.record['rounds'][-1]['projects']
        if blocked:
            self.record.update(status='INCONCLUSIVE', impact_decision='UNKNOWN', completion_blocked_by=blocked)
        self._save()
        return self.record
