"""Diff + target repositories -> discovery -> grounded assessment -> isolated backport.

The controller derives write paths from a reviewed per-change plan. Repository
paths and target HEADs are inferred, source evidence is grounded directly in the
input diff, and no source commit identity or reference answer is manufactured.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

from .case import Case, validate_relative_path
from .git_policy import OFFLINE_GIT_ENV
from .discovery import Locator, diff_units, local_git, repositories, repository_roots, repository_issue, READ_BUDGETS
from .donor import verify_donor, verify_source_sequence
from .diff_prompts import ASSESSMENT_SCHEMA, MIGRATION_SCHEMA, assessment_prompt
from .engine import AospBackportAgent, AssessmentError
from .prompts import SYSTEM
from .validation_plan import make_plan, normalize_checks
from .mapping_plan import MappingPlanner, MappingPlan, _shape, _excerpt
from .lifecycle import source_guard, operation_lease


def _write(path, value, *, control=False):
    from .output_budget import write_json
    return write_json(path, value, control=control)
class DiffBackportAgent:
    @source_guard('target_root')
    def __init__(self, patch: Path, target_root: Path, run_root: Path, *, model=None,
                 model_provider=None, turn_timeout=900, runtime_factory=None, validation=None,
                 donor_repo=None, source_commit=None, source_parent=None,
                 auto_validation=True, build_runner=None, mapping_model=None,
                 task_id=None, pinned_heads=None, joint_validation=None, repository_keys=None,
                 lazy_reads=False, object_cache=None, assessment_context='', source_sequence=None,
                 require_scope_closure=False, read_denied_roots=(), max_output_bytes=256 * 1024 * 1024):
        self.patch_bytes = patch if isinstance(patch, bytes) else patch.read_bytes()
        self.diff = self.patch_bytes.decode('utf-8')
        self.units = diff_units(self.diff)
        if source_sequence is not None:
            if any(x is not None for x in (donor_repo, source_commit, source_parent)):
                raise ValueError('use either a verified source sequence or a single donor')
            self.units, self.donor = verify_source_sequence(source_sequence, self.diff)
        else:
            self.donor = verify_donor(donor_repo, source_commit, source_parent, self.diff)
        self.digest = hashlib.sha256(self.patch_bytes).hexdigest()
        self.task_id = validate_relative_path(task_id) if task_id else 'patch-' + self.digest[:16]
        self.target_root = target_root.resolve()
        self.run_dir = run_root.resolve() / self.task_id
        # Persist inventory progress before the first object read. Keep these
        # diagnostics outside the source tree, including unavailable checkouts.
        if self.run_dir.resolve().is_relative_to(self.target_root):
            raise ValueError('run directory must be outside original target root')
        self.run_dir.mkdir(parents=True, exist_ok=False)
        from .output_budget import create_budget
        self.output_budget = create_budget(self.run_dir, max_output_bytes)
        self._started = False
        self.inventory_issues = []
        self.lazy_reads, self.object_cache = lazy_reads, object_cache
        self.assessment_context, self.source_sequence = assessment_context, source_sequence
        self.require_scope_closure = require_scope_closure
        self.read_denied_roots = tuple(read_denied_roots)
        self._model_read_roots = None
        self.record = {'task_id': self.task_id, 'input_patch_sha256': self.digest, 'status': 'INITIALIZING',
                       'backend': 'codex_sdk', 'model': model or 'codex_config_default', 'model_execution': 'not_run',
                       'impact_decision': 'UNKNOWN', 'patch_replay': 'not_run',
                       'verification_scope': 'configured_commands_only', 'runtime_security_proven': False,
                       'android_module_build': 'NOT_CONFIGURED', 'android_runtime': 'NOT_CONFIGURED',
                       'poc_execution': 'NOT_RUN', 'inventory_issues': self.inventory_issues}
        self._save()
        try:
            self._inventory(pinned_heads, repository_keys)
            self.by_key = {r.key: r for r in self.repos}
            self.mapper = MappingPlanner(self.repos, self.units)
            self.mapping_plan = None
            self.workspace = self.run_dir / 'workspace'
            self.model, self.provider, self.timeout = model, model_provider or os.environ.get('AOSP_AGENT_MODEL_PROVIDER'), turn_timeout
            self.mapping_model = mapping_model or model
            self.factory, self.validation = runtime_factory, {} if validation is None else validation
            if not isinstance(self.validation, dict):
                raise ValueError('validation must be an object keyed by repository')
            self.auto_validation = auto_validation
            self.build_runner = Path(build_runner).resolve(strict=True) if build_runner else None
            if self.build_runner and (not self.build_runner.is_file() or not os.access(self.build_runner, os.X_OK)
                                      or any(self.build_runner.is_relative_to(root) for root in self.repo_roots)):
                raise ValueError('build runner must be executable and outside supplied target repositories')
            unknown = set(self.validation) - set(self.repo_keys)
            if unknown:
                raise ValueError(f'validation names unknown repositories: {sorted(unknown)}')
            for spec in self.validation.values():
                normalize_checks(spec)
            self.joint_validation, self.joint_plan = joint_validation, None
            if joint_validation is not None:
                normalize_checks(joint_validation)
            self.children = {}
            self.protected = {}
            if self.build_runner:
                self._protect(self.build_runner)
            self.record['status'] = 'INITIALIZED'
            self._save()
        except Exception as exc:
            self.record.update(status='FAILED', error={
                'type': type(exc).__name__, 'kind': 'REPOSITORY_INITIALIZATION_ERROR',
                'message': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))})
            self._save()
            exc.record_path = str(self.run_dir / 'run.json')
            raise

    def _inventory(self, pinned_heads, repository_keys=None):
        self.record.update(git_read_budgets_seconds={k: list(v) for k, v in READ_BUDGETS.items()},
                           git_read_attempts='git-read-attempts.jsonl', git_read_retry_on='TimeoutExpired_only')
        self._save()
        if repository_keys is None:
            self.repo_roots = repository_roots(self.target_root)
            self.record['analysis_scope'] = {'mode': 'all_supplied_checkouts'}
        else:
            keys = list(dict.fromkeys(repository_keys))
            if not keys:
                raise ValueError('explicit repository scope cannot be empty')
            self.repo_roots = []
            standalone = os.path.lexists(self.target_root / '.git')
            for key in keys:
                validate_relative_path(key)
                if standalone and key != 'repo':
                    raise ValueError('standalone target scope must use repository key repo')
                path = self.target_root if standalone else self.target_root / key
                if (not path.resolve().is_relative_to(self.target_root) or path.resolve() != path
                        or not os.path.lexists(path / '.git')):
                    raise ValueError('selected repository is unavailable or unsafe: ' + key)
                self.repo_roots.append(path)
            if set(pinned_heads or {}) - set(keys):
                raise ValueError('pinned repository is outside the selected scope')
            # Explicit selections are required inputs, not optional inventory
            # noise. Missing objects must not silently remove a selected project.
            pinned_heads = {key: (pinned_heads or {}).get(key, 'HEAD') for key in keys}
            self.record['analysis_scope'] = {'mode': 'explicit_projects', 'projects': keys,
                'whole_tree_discovery_evaluated': False,
                'limitation': 'Conclusions apply to the supplied project scope; undeclared dependencies are not proven absent.'}
        self.repo_keys = {p.relative_to(self.target_root).as_posix() if p != self.target_root else 'repo': p
                          for p in self.repo_roots}
        def progress(state):
            _write(self.run_dir / 'inventory-progress.json', {**state, 'issues': self.inventory_issues})
        last_read_snapshot = float('-inf')
        def read_event(event):
            nonlocal last_read_snapshot
            from .output_budget import write_text
            write_text(self.run_dir / 'git-read-attempts.jsonl', json.dumps(event, ensure_ascii=False) + '\n', append=True)
            now = time.monotonic()
            # Keep every attempt in the append-only log, without atomically
            # replacing a snapshot twice for every fast grep/blob read.
            if now - last_read_snapshot >= 1 or event['status'] in ('TIMED_OUT', 'ERROR') or event['attempt'] > 1:
                _write(self.run_dir / 'git-read-progress.json', event)
                last_read_snapshot = now
        repos = repositories(self.target_root, pinned_heads=pinned_heads, roots=self.repo_roots,
                             issues=self.inventory_issues, progress=progress, read_events=read_event,
                             lazy=self.lazy_reads, cache=self.object_cache)
        self.before, self.repos = {}, []
        for number, repo in enumerate(repos, 1):
            progress({'repository': repo.key, 'stage': 'source_guard',
                      'completed_repositories': number - 1, 'total_repositories': len(repos)})
            try:
                self.before[repo.key] = repo.state(timeout=None)
            except (OSError, subprocess.SubprocessError) as exc:
                self.inventory_issues.append(repository_issue(repo.key, 'source_guard', exc, repo.root))
                if repo.key in (pinned_heads or {}):
                    raise ValueError(f'pinned target repository cannot be guarded: {repo.key}') from exc
                continue
            self.repos.append(repo)
        self.record['inventory_status'] = 'INCOMPLETE' if self.inventory_issues else 'COMPLETE'
        self.record['source_guard'] = {
            'scope': 'available_repositories_only' if self.inventory_issues else 'all_discovered_repositories',
            'guarded': sorted(self.before),
            'unavailable': sorted(set(self.repo_keys) - set(self.before)),
            'unavailable_integrity': 'NOT_VERIFIED' if self.inventory_issues else 'NOT_APPLICABLE'}
        _write(self.run_dir / 'source-baselines.json', {
            r.key: {'root': str(r.root), 'state': self.before[r.key]} for r in self.repos})
        progress({'stage': 'complete', 'completed_repositories': len(self.repo_roots),
                  'total_repositories': len(self.repo_roots), 'status': self.record['inventory_status']})

    def _save(self):
        if self.inventory_issues or self.record.get('discovery_status') == 'INCOMPLETE':
            if self.inventory_issues:
                self.record['inventory_status'] = 'INCOMPLETE'
            status = self.record['status']
            if status in ('VALIDATED', 'NEEDS_REVIEW', 'PATCH_UNVERIFIED', 'NOT_AFFECTED', 'ALREADY_FIXED'):
                if status != 'PATCH_UNVERIFIED' or 'available_scope_status' not in self.record:
                    self.record['available_scope_status'] = status
                self.record['status'] = 'PATCH_UNVERIFIED' if status in ('VALIDATED', 'NEEDS_REVIEW', 'PATCH_UNVERIFIED') else 'INCONCLUSIVE'
                self.record['completion_blocked_by'] = ('INCOMPLETE_REPOSITORY_INVENTORY'
                    if self.inventory_issues else 'INCOMPLETE_OBJECT_RETRIEVAL')
                if status in ('NOT_AFFECTED', 'ALREADY_FIXED'):
                    self.record['available_scope_impact'] = self.record['impact_decision']
                    self.record['impact_decision'] = 'UNKNOWN'
        from .delivery import update_delivery
        update_delivery(self.record)
        self.record['output_budget'] = self.output_budget.data()
        _write(self.run_dir / 'run.json', self.record, control=True)

    def _protect(self, path):
        self.protected[path] = hashlib.sha256(path.read_bytes()).hexdigest()

    def _freeze_check(self, check, cwd):
        argv = check['argv']
        scripts = [argv[0]]
        if re.fullmatch(r'(?:python[\d.]*|pypy[\d.]*|node|ruby|perl)', Path(argv[0]).name):
            if '-m' not in argv:
                scripts.extend(next(([a] for a in argv[1:] if not a.startswith('-')), []))
        for script in scripts:
            path = Path(script) if Path(script).is_absolute() else cwd / script
            if path.is_file():
                self._protect(path.resolve())

    def _donor_tools_context(self):
        if self.donor['status'] == 'VERIFIED_SEQUENCE':
            tools = str(self.run_dir / 'bin')
            return ('\nVerified source steps (all changes remain required, input order is not by itself ancestry proof):\n'
                    + json.dumps(self.donor) + '\nControlled tools: ' + tools
                    + '/view-code --repo donor:<source-id> --ref SHA --path P --start N --end M; '
                    + tools + '/view-code --repo target:<repository-key> --ref SHA --path P --start N --end M. '
                    'History: hunk-history --hunk-id <namespaced-unit-id> --target-repo <key>; '
                    'show-commit --source-step <source-id> --target-repo <key> --sha SHA. '
                    'Do not drop superseded or dependent steps; explain how the final candidate covers their obligations.\n')
        if self.donor['status'] != 'VERIFIED':
            return '\nDonor history: NOT_AVAILABLE; evidence is limited to supplied diff lines.\n'
        tools = self.run_dir / 'bin'
        return ('\nVerified donor history (read only):\n' + json.dumps(self.donor) +
                '\nControlled tools: ' + str(tools) +
                '/view-code --repo donor --ref SHA --path P --start N --end M; ' +
                str(tools) + '/hunk-history --hunk-id ID; ' + str(tools) +
                '/show-commit --sha SHA [--hunk-id ID]. Use only recorded revisions.\n'
                'For target reads use --repo target:<repository-key> with that project\'s pinned SHA. '
                'For multi-project hunk-history/show-commit, also pass --target-repo <repository-key>; '
                'there is no default target project. READ_FAILED is not absence evidence.\n')

    def _owner(self, path):
        return self.mapper._owner(path)

    def _originals_unchanged(self):
        for repo in self.repos:
            if repo.state() != self.before[repo.key]:
                raise RuntimeError(f'original repository changed: {repo.key}')

    def _candidate_hashes(self, except_key=None):
        return {key: hashlib.sha256(child._render_patch().encode()).hexdigest()
                for key, child in self.children.items() if key != except_key}

    def _audit_peers(self, key, before):
        self._audit()
        if self._candidate_hashes(except_key=key) != before:
            raise RuntimeError('repository turn modified another candidate: ' + key)

    def _audit(self):
        for path, digest in self.protected.items():
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError('controller-owned plan was modified: ' + str(path))
        self._originals_unchanged()
        for child in self.children.values():
            child.audit_diff()
            # Include ignored files in the raw-mode guard; never export a partial
            # result that silently omitted an ignored model-created file.
            ignored = local_git(child.worktree, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').stdout
            if ignored:
                raise RuntimeError('unexpected ignored files in isolated worktree')
        if self.workspace.exists():
            roots = {c.worktree for c in self.children.values()}
            for folder, dirs, files in os.walk(self.workspace, followlinks=False):
                current = Path(folder)
                if current in roots:
                    dirs[:] = []
                    continue
                if files or any((current / d).is_symlink() for d in dirs):
                    raise RuntimeError('unexpected files outside repository worktrees')

    def ground(self, raw):
        return self.mapper.ground(raw)

    def _runtime(self, name):
        from .retrieval import ACTIVE_BUDGET
        budget = ACTIVE_BUDGET.get()
        if self.factory is None:
            from .sdk_runtime import CodexRuntime
            factory = CodexRuntime
        else:
            factory = self.factory
        writable = []
        if name.startswith('migration-'):
            from urllib.parse import unquote
            child = self.children[unquote(name[len('migration-'):])]
            writable = [child.worktree / p for p in child.case.files]
        return factory(events_path=self.run_dir / f'sdk-{name}.jsonl',
                       model=self.mapping_model if name == 'assessment' or name.startswith('exclusion-review-') else self.model,
                       model_provider=self.provider, turn_timeout=min(self.timeout, budget.remaining()) if budget else self.timeout,
                       env=OFFLINE_GIT_ENV, read_scope=self.model_scope(writable))

    def model_scope(self, writable=()):
        from .sandbox_scope import git_read_roots, source_scope
        if self._model_read_roots is None:
            repositories = [r.root for r in self.repos]
            if self.donor['status'] == 'VERIFIED':
                repositories.append(Path(self.donor['donor_git']))
            elif self.donor['status'] == 'VERIFIED_SEQUENCE':
                repositories.extend(Path(s['donor_git']) for s in self.donor['steps'])
            self._model_read_roots = git_read_roots(repositories)
        denied = self.read_denied_roots
        if all(r.root != self.target_root for r in self.repos):
            denied += (self.target_root,)
        scope = source_scope(self.run_dir, writable=writable, extra_readable=self._model_read_roots, denied=denied)
        self.record['model_read_boundary'] = {'status': 'REQUIRED_PERMISSION_PROFILE',
            'scope': scope.data(), 'tool_budget_enforcement': 'controller_broker_before_execution'}
        self._save()
        return scope

    def _turn(self, runtime, prompt, schema, *, read_only):
        result = runtime.run(prompt, read_only=read_only, output_schema=schema)
        self._audit()
        if result.get('status') != 'completed':
            raise RuntimeError(f'SDK turn did not complete: {result.get("status")}')
        self.record.setdefault('turns', []).append({k: result.get(k) for k in ('thread_id', 'turn_id', 'usage', 'events_path')})
        # Prefer the runtime's parsed (possibly tail-repaired) structured output;
        # fall back to parsing the raw text for runtimes that omit it.
        output = result.get('output')
        if output is None:
            output = json.loads(result['final_response'])
        return output

    def _prepare_children(self, assessment, *, build_requested=True):
        self.mapping_plan = MappingPlan.create(assessment, self.repos, self.units, self.donor)
        _write(self.run_dir / 'mapping-plan.json', self.mapping_plan.data())
        self._protect(self.run_dir / 'mapping-plan.json')
        self.record['mapping_plan_sha256'] = self.mapping_plan.sha256
        # Read dependencies in the same workspace; only AFFECTED mappings/new files become writable.
        selected = {self._owner(t['path'])[0].key for u in assessment['units'] for t in u['targets']}
        multi = sum(bool(self.mapping_plan.files(key)) for key in selected) > 1
        deferred = []
        source_root = (self.target_root.parent if any(r.root == self.target_root for r in self.repos)
                       else self.target_root)
        for key in sorted(selected):
            repo = self.by_key[key]
            files = self.mapping_plan.files(key)
            mappings = {}
            for unit in assessment['units']:
                if unit['status'] != 'AFFECTED':
                    continue
                edited = {t['path'] for t in unit['targets'] if t['action'] == 'edit'}
                edited.update(a['path'] for a in assessment['new_files'] if a['anchor_path'] in edited)
                mappings[unit['id']] = [self._owner(p)[1] for p in edited if self._owner(p)[0].key == key]
            plan = make_plan(repo, self.units, mappings, files, self.diff,
                             explicit=self.validation.get(key), auto=self.auto_validation,
                             build_runner=self.build_runner, build_requested=build_requested)
            local_checks = []
            for check in plan['checks']:
                if multi and files and check['stage'] == 'android_module_build':
                    deferred.append((key, check))
                else:
                    local_checks.append(check)
            plan['deferred_to_joint'] = ['android_module_build'] if len(local_checks) != len(plan['checks']) else []
            _write(self.run_dir / 'validation-plans' / key / 'plan.json', plan)
            self._protect(self.run_dir / 'validation-plans' / key / 'plan.json')
            validation_case = Case.from_dict({'cve': 'CVE-2099-0000', 'project': 'validation contract',
                'repository': 'repo', 'source_commit': '0', 'source_parent': '0', 'target_commit': repo.head,
                'files': ['placeholder'], 'validation': local_checks})
            dependencies = tuple({'path': self.by_key[k].root.relative_to(source_root).as_posix(),
                                  'role': 'read_only_dependency', 'files': [],
                                  'target_commit': self.by_key[k].head}
                                 for k in sorted(selected - {key}))
            case = Case(cve=self.task_id, project='AOSP mapped backport',
                        repository=repo.root.relative_to(source_root).as_posix(),
                        source_commit=self.donor.get('source_commit', ''),
                        source_parent=self.donor.get('source_parent', ''), target_commit=repo.head, files=files,
                        validation=validation_case.validation, validation_checks=validation_case.validation_checks,
                        repositories=dependencies)
            child = AospBackportAgent(source_root, self.run_dir / 'exports', case,
                                      model=self.model, source_diff=self.diff,
                                      model_provider=self.provider, turn_timeout=self.timeout,
                                      runtime_factory=self.factory)
            child.run_dir = self.run_dir / 'repositories' / key
            child.worktree = self.workspace / key
            child.mapping_plan, child.mapping_repository = self.mapping_plan, key
            # A standalone repo uses its parent merely as a path namespace.
            # Protect the actual controller source scope, not that container.
            child._source_scope = self.target_root
            child._scope_provider = self.model_scope
            # Review once against the final vector, including source sequences
            # and single-project text backends. Per-child review misses peers.
            child.defer_post_fix = True
            self.children[key] = child
            child.prepare(_source_lease=operation_lease(self))
            from dataclasses import asdict
            _write(child.run_dir / 'runtime-case.json', asdict(case))
            self._protect(child.run_dir / 'runtime-case.json')
            for check in case.validation_checks:
                self._freeze_check(check, child.worktree)
            child.record['validation_plan'] = str(self.run_dir / 'validation-plans' / key / 'plan.json')
            child._write_record()
        from .joint_validation import prepare_joint
        prepare_joint(self, deferred)
        self._audit()

    def _coverage(self, raw, assessment):
        _shape(raw, MIGRATION_SCHEMA)
        units = {u['id']: u for u in assessment['units']}
        if len(raw['coverage']) != len(units) or {c['id'] for c in raw['coverage']} != set(units):
            raise AssessmentError('migration coverage must include every diff unit exactly once')
        for coverage in raw['coverage']:
            unit = units[coverage['id']]
            if coverage['status'] == 'unresolved':
                raise AssessmentError(f'unresolved migration unit: {unit["id"]}: {coverage["explanation"]}')
            if unit['status'] != 'AFFECTED':
                if coverage['status'] != 'not_required':
                    raise AssessmentError('unaffected/fixed unit must be marked not_required')
                continue
            if coverage['status'] != 'implemented' or not coverage['evidence']:
                raise AssessmentError('affected unit requires implemented coverage with candidate evidence')
            related = {t['path'] for t in unit['targets']}
            related.update(a['path'] for a in assessment['new_files'] if a['anchor_path'] in related)
            required = [t for t in unit['targets'] if t['action'] == 'edit']
            covered = set()
            for e in coverage['evidence']:
                if e['path'] not in related or e['path'] not in assessment['writable_paths']:
                    raise AssessmentError('coverage evidence is outside the unit writable mapping')
                repo, path = self._owner(e['path'])
                candidate = self.children[repo.key].worktree / path
                if candidate.is_symlink() or not candidate.is_file():
                    raise AssessmentError('coverage must cite a regular candidate source file')
                lines = candidate.read_text().splitlines()
                _excerpt(lines, e)
                patch = local_git(self.children[repo.key].worktree, 'diff', '--no-ext-diff', '--unified=0',
                                  repo.head, '--', path).stdout
                for match in re.finditer(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', patch, re.M):
                    old_start, old_count, new_start, new_count = (int(x) if x is not None else 1 for x in match.groups())
                    old_end = old_start + max(1, old_count) - 1
                    new_end = new_start + max(1, new_count) - 1
                    if e['line_start'] <= new_end and e['line_end'] >= max(1, new_start):
                        # Independently compare each mapped old function/region. One changed
                        # sibling cannot cover a split function left untouched elsewhere.
                        for number, target in enumerate(required):
                            if (target['path'] == e['path'] and target['line_start'] <= old_end
                                    and target['line_end'] >= max(1, old_start)):
                                covered.add(number)
            if len(covered) != len(required):
                missing = [f"{t['path']}:{t['line_start']}-{t['line_end']}" for n, t in enumerate(required) if n not in covered]
                raise AssessmentError('each edit mapping requires changed candidate evidence; missing: ' + ', '.join(missing))
        return raw

    @source_guard('target_root')
    def run(self, *, inspect_only=False, max_attempts=3, verify=False,
            impact_only=False, mechanical=True):
        if max_attempts < 1:
            raise ValueError('max_attempts must be positive')
        if self._started:
            raise ValueError('this run has already started; use a new run root')
        self._started = True
        try:
            # Constructor and execution can be separated in time. Never run
            # against a baseline changed while this controller held no lease.
            self._originals_unchanged()
            from .output_budget import write_bytes
            write_bytes(self.run_dir / 'input.patch', self.patch_bytes)
            self._protect(self.run_dir / 'input.patch')
            inventory = [{'key': r.key, 'original_root': str(r.root), 'head': r.head,
                          'tracked_files': r.tracked_count, 'status': 'AVAILABLE'} for r in self.repos]
            inventory.extend({'key': key, 'original_root': str(self.repo_keys[key]), 'status': 'UNAVAILABLE',
                              'head': None, 'tracked_files': None}
                             for key in sorted(set(self.repo_keys) - set(self.by_key)))
            _write(self.run_dir / 'inventory.json', inventory)
            self.record['repositories'] = inventory
            self.record['source_provenance'] = self.donor
            if not self.repos:
                self.record.update(status='INCONCLUSIVE', completion_blocked_by='NO_AVAILABLE_REPOSITORIES')
                self._save()
                return self.record
            from .hunk_groups import review_groups, review_prompt
            review = review_groups(self.units)
            _write(self.run_dir / 'hunk-review-groups.json', review)
            self._protect(self.run_dir / 'hunk-review-groups.json')
            self.record['hunk_review_groups'] = 'hunk-review-groups.json'
            # Text-only diff needs the same pinned source tool context as a
            # donor-backed input. History remains explicitly unavailable.
            self.record['tool_target_repositories'] = {
                r.key: {'root': str(r.root), 'head': r.head} for r in self.repos}
            if len(self.repos) == 1:
                self.record.update(worktree=str(self.repos[0].root), target_commit=self.repos[0].head)
            _write(self.run_dir / 'inspection.json', {'hunks': self.units, 'source_diff': self.diff})
            self._save()
            if self.donor['status'] in ('VERIFIED', 'VERIFIED_SEQUENCE'):
                from .agent_tools import _write_wrappers
                if self.donor['status'] == 'VERIFIED':
                    self.record.update({key: self.donor[key] for key in ('source_commit', 'source_parent', 'donor_git')})
                else:
                    self.record['tool_source_repositories'] = {s['id']: s for s in self.donor['steps']}
                self._save()
                _write_wrappers(self.run_dir)
            locator = Locator(self.repos, self.units)
            location = locator.locate(lambda state: _write(self.run_dir / 'discovery-progress.json', state))
            location['issues'] = self.inventory_issues + location['issues']
            location['inventory_status'] = self.record['inventory_status']
            self.record['discovery_status'] = ('INCOMPLETE' if any('error' in i for i in location['issues'])
                                                else 'CANDIDATES_WITH_DEFERRED_SEARCH'
                                                if location['retrieval_summary']['deferred_project_searches']
                                                else 'COMPLETE_WITH_RETRIEVAL_LIMITS')
            self.record['retrieval_summary'] = location['retrieval_summary']
            location['target_history'] = locator.history(location)
            location['source_history'] = self.donor
            _write(self.run_dir / 'location.json', location)
            self._originals_unchanged()
            self.record['status'] = 'DISCOVERED'
            self._save()
            if inspect_only:
                if self.inventory_issues or self.record['discovery_status'] == 'INCOMPLETE':
                    self.record.update(status='INCONCLUSIVE', available_scope_status='DISCOVERED',
                                       completion_blocked_by='INCOMPLETE_DISCOVERY')
                    self._save()
                return self.record
            with self._runtime('assessment') as runtime:
                from .exclusion_review import ExclusionReviewError, review_exclusions, unresolved_exclusions
                from .mapped_impact import ImpactProofError, PROOF_CONTEXT, check_impact_proofs
                require_causality = self.require_scope_closure or self.donor['status'] == 'VERIFIED_SEQUENCE'
                runtime.start(self.run_dir, SYSTEM + '\nAssessment phase is strictly read-only, using pinned original Git objects.')
                prompt = (assessment_prompt(self.diff, inventory, location) + self._donor_tools_context()
                          + review_prompt(review) + self.assessment_context
                          + (PROOF_CONTEXT if require_causality else ''))
                for attempt in range(1, max_attempts + 1):
                    raw = self._turn(runtime, prompt, ASSESSMENT_SCHEMA, read_only=True)
                    _write(self.run_dir / f'assessment-{attempt}.json', raw)
                    try:
                        assessment = self.ground(raw)
                        from .scope_evidence import check_scope
                        scope = check_scope(self, assessment, self.require_scope_closure)
                        self.record['scope_evidence'] = scope
                        if scope['status'] in ('EXPANSION_REQUIRED', 'OPEN_QUESTIONS'):
                            _write(self.run_dir / 'assessment.json', assessment)
                            self.record.update(status='INCONCLUSIVE', impact_decision='UNKNOWN',
                                replan_required=scope['status'], scope_requests=scope.get('requests', []))
                            self._save()
                            return self.record
                        self.record['causal_evidence'] = check_impact_proofs(self, assessment, require_causality)
                        review_exclusions(self, assessment, inventory, attempt)
                        break
                    except AssessmentError as exc:
                        self.record.setdefault('assessment_rejections', []).append(str(exc))
                        if attempt == max_attempts:
                            if isinstance(exc, ImpactProofError):
                                self.record.update(status='INCONCLUSIVE', impact_decision='UNKNOWN',
                                    completion_blocked_by='CAUSAL_EVIDENCE_UNRESOLVED',
                                    replan_required='CAUSAL_EVIDENCE_UNRESOLVED',
                                    causal_evidence={'status': 'UNRESOLVED', 'reason': str(exc)})
                                self._save()
                                return self.record
                            if isinstance(exc, ExclusionReviewError):
                                assessment = unresolved_exclusions(self, assessment, str(exc))
                                break
                            raise
                        prompt = (f'Correct the complete read-only assessment. Evidence rejection: {exc}. '
                                  'Return all units in the same schema. Do not edit files.'
                                  + (PROOF_CONTEXT if require_causality else ''))
            _write(self.run_dir / 'assessment.json', assessment)
            self._protect(self.run_dir / 'assessment.json')
            self.record.update(model_execution='succeeded', impact_decision=assessment['status'])
            if assessment['status'] != 'AFFECTED':
                self.record['status'] = 'INCONCLUSIVE' if assessment['status'] == 'UNKNOWN' else assessment['status']
                self._save()
                return self.record
            self._prepare_children(assessment, build_requested=verify and not impact_only)
            if self.donor['status'] == 'VERIFIED':
                from .mapped_backend import run_backends
                from .retrieval import suspend_investigation_budget
                with suspend_investigation_budget():
                    return run_backends(self, assessment, verify=verify, max_attempts=max_attempts,
                                        impact_only=impact_only, mechanical=mechanical)
            if impact_only:
                self.record['status'] = 'AFFECTED'
                self._save()
                return self.record
            from .text_backend import run_text_backends
            from .retrieval import suspend_investigation_budget
            with suspend_investigation_budget():
                return run_text_backends(self, assessment, verify=verify, max_attempts=max_attempts)
        except Exception as exc:
            from .lifecycle import RecoveryBlocked
            self.record.update(status='BLOCKED' if isinstance(exc, RecoveryBlocked) else 'FAILED', error={'type': type(exc).__name__, 'kind': getattr(exc, 'kind', 'DIFF_WORKFLOW_ERROR'),
                'message': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))})
            if self.record['model_execution'] == 'not_run' and not inspect_only:
                self.record['model_execution'] = 'failed'
            self._save()
            raise
