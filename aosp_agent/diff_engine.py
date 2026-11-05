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
from pathlib import Path

from .case import Case, validate_relative_path
from .git_policy import OFFLINE_GIT_ENV
from .discovery import Locator, diff_units, local_git, repositories
from .donor import verify_donor
from .diff_prompts import ASSESSMENT_SCHEMA, MIGRATION_SCHEMA, assessment_prompt, migration_prompt
from .engine import AospBackportAgent, AssessmentError, CandidateRejected
from .prompts import SYSTEM
from .validation_plan import make_plan, normalize_checks
from .mapping_plan import MappingPlanner, MappingPlan, _shape, _excerpt


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)
class DiffBackportAgent:
    def __init__(self, patch: Path, target_root: Path, run_root: Path, *, model=None,
                 model_provider=None, turn_timeout=900, runtime_factory=None, validation=None,
                 donor_repo=None, source_commit=None, source_parent=None,
                 auto_validation=True, build_runner=None, mapping_model=None,
                 task_id=None, pinned_heads=None):
        self.patch_bytes = patch if isinstance(patch, bytes) else patch.read_bytes()
        self.diff = self.patch_bytes.decode('utf-8')
        self.units = diff_units(self.diff)
        self.donor = verify_donor(donor_repo, source_commit, source_parent, self.diff)
        self.digest = hashlib.sha256(self.patch_bytes).hexdigest()
        self.task_id = validate_relative_path(task_id) if task_id else 'patch-' + self.digest[:16]
        self.target_root = target_root.resolve()
        self.repos = repositories(target_root, pinned_heads=pinned_heads)
        self.by_key = {r.key: r for r in self.repos}
        self.mapper = MappingPlanner(self.repos, self.units)
        self.mapping_plan = None
        self.run_dir = run_root.resolve() / self.task_id
        if any(self.run_dir.is_relative_to(r.root) for r in self.repos):
            raise ValueError('run directory must be outside original repositories')
        self.workspace = self.run_dir / 'workspace'
        self.model, self.provider, self.timeout = model, model_provider or os.environ.get('AOSP_AGENT_MODEL_PROVIDER'), turn_timeout
        self.mapping_model = mapping_model or model
        self.factory, self.validation = runtime_factory, {} if validation is None else validation
        if not isinstance(self.validation, dict):
            raise ValueError('validation must be an object keyed by repository')
        self.auto_validation = auto_validation
        self.build_runner = Path(build_runner).resolve(strict=True) if build_runner else None
        if self.build_runner and (not self.build_runner.is_file() or not os.access(self.build_runner, os.X_OK)
                                  or any(self.build_runner.is_relative_to(r.root) for r in self.repos)):
            raise ValueError('build runner must be executable and outside supplied target repositories')
        unknown = set(self.validation) - set(self.by_key)
        if unknown:
            raise ValueError(f'validation names unknown repositories: {sorted(unknown)}')
        for spec in self.validation.values():
            normalize_checks(spec)
        self.before = {r.key: r.state() for r in self.repos}
        self.children = {}
        self.protected = {}
        if self.build_runner:
            self._protect(self.build_runner)
        self.record = {'task_id': self.task_id, 'input_patch_sha256': self.digest, 'status': 'INITIALIZED',
                       'backend': 'codex_sdk', 'model': model or 'codex_config_default', 'model_execution': 'not_run',
                       'impact_decision': 'UNKNOWN', 'patch_replay': 'not_run',
                       'verification_scope': 'configured_commands_only', 'runtime_security_proven': False,
                       'android_module_build': 'NOT_CONFIGURED', 'android_runtime': 'NOT_CONFIGURED',
                       'poc_execution': 'NOT_RUN'}

    def _save(self):
        _write(self.run_dir / 'run.json', self.record)

    def _protect(self, path):
        self.protected[path] = hashlib.sha256(path.read_bytes()).hexdigest()

    def _donor_tools_context(self):
        if self.donor['status'] != 'VERIFIED':
            return '\nDonor history: NOT_AVAILABLE; evidence is limited to supplied diff lines.\n'
        tools = self.run_dir / 'bin'
        return ('\nVerified donor history (read only):\n' + json.dumps(self.donor) +
                '\nControlled tools: ' + str(tools) +
                '/view-code --repo donor --ref SHA --path P --start N --end M; ' +
                str(tools) + '/hunk-history --hunk-id ID; ' + str(tools) +
                '/show-commit --sha SHA [--hunk-id ID]. Use only recorded revisions.\n')

    def _owner(self, path):
        return self.mapper._owner(path)

    def _originals_unchanged(self):
        for repo in self.repos:
            if repo.state() != self.before[repo.key]:
                raise RuntimeError(f'original repository changed: {repo.key}')

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
        if self.factory is None:
            from .sdk_runtime import CodexRuntime
            factory = CodexRuntime
        else:
            factory = self.factory
        return factory(events_path=self.run_dir / f'sdk-{name}.jsonl',
                       model=self.mapping_model if name == 'assessment' else self.model,
                       model_provider=self.provider, turn_timeout=self.timeout,
                       env=OFFLINE_GIT_ENV)

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

    def _prepare_children(self, assessment):
        self.mapping_plan = MappingPlan.create(assessment, self.repos, self.units, self.donor)
        _write(self.run_dir / 'mapping-plan.json', self.mapping_plan.data())
        self._protect(self.run_dir / 'mapping-plan.json')
        self.record['mapping_plan_sha256'] = self.mapping_plan.sha256
        # Read dependencies in the same workspace; only AFFECTED mappings/new files become writable.
        selected = {self._owner(t['path'])[0].key for u in assessment['units'] for t in u['targets']}
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
                             build_runner=self.build_runner)
            _write(self.run_dir / 'validation-plans' / key / 'plan.json', plan)
            self._protect(self.run_dir / 'validation-plans' / key / 'plan.json')
            validation_case = Case.from_dict({'cve': 'CVE-2099-0000', 'project': 'validation contract',
                'repository': 'repo', 'source_commit': '0', 'source_parent': '0', 'target_commit': repo.head,
                'files': ['placeholder'], 'validation': plan['checks']})
            dependencies = tuple({'path': self.by_key[k].root.relative_to(source_root).as_posix(),
                                  'role': 'read_only_dependency', 'files': []}
                                 for k in sorted(selected - {key}))
            case = Case(cve=self.task_id, project='AOSP mapped backport',
                        repository=repo.root.relative_to(source_root).as_posix(),
                        source_commit=self.donor.get('source_commit', ''),
                        source_parent=self.donor.get('source_parent', ''), target_commit=repo.head, files=files,
                        validation=validation_case.validation, validation_checks=validation_case.validation_checks,
                        repositories=dependencies)
            child = AospBackportAgent(source_root, self.run_dir / 'exports', case,
                                      model=self.model, source_diff=self.diff)
            child.run_dir = self.run_dir / 'repositories' / key
            child.worktree = self.workspace / key
            child.mapping_plan, child.mapping_repository = self.mapping_plan, key
            self.children[key] = child
            child.prepare()
            from dataclasses import asdict
            _write(child.run_dir / 'runtime-case.json', asdict(case))
            self._protect(child.run_dir / 'runtime-case.json')
            for check in case.validation_checks:
                argv = check['argv']
                scripts = [argv[0]]
                if re.fullmatch(r'(?:python[\d.]*|pypy[\d.]*|node|ruby|perl)', Path(argv[0]).name):
                    if '-m' not in argv:
                        scripts.extend(next(([a] for a in argv[1:] if not a.startswith('-')), []))
                for script in scripts:
                    path = Path(script) if Path(script).is_absolute() else child.worktree / script
                    if path.is_file():
                        self._protect(path.resolve())
            child.record['validation_plan'] = str(self.run_dir / 'validation-plans' / key / 'plan.json')
            child._write_record()
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

    def run(self, *, inspect_only=False, max_attempts=3, verify=False,
            impact_only=False, mechanical=True):
        if max_attempts < 1:
            raise ValueError('max_attempts must be positive')
        self.run_dir.mkdir(parents=True, exist_ok=False)
        try:
            (self.run_dir / 'input.patch').write_bytes(self.patch_bytes)
            self._protect(self.run_dir / 'input.patch')
            inventory = [{'key': r.key, 'original_root': str(r.root), 'head': r.head,
                          'tracked_files': len(r.files)} for r in self.repos]
            _write(self.run_dir / 'inventory.json', inventory)
            self.record['repositories'] = inventory
            self.record['source_provenance'] = self.donor
            if self.donor['status'] == 'VERIFIED':
                from .agent_tools import _write_wrappers
                self.record.update({key: self.donor[key] for key in
                                    ('source_commit', 'source_parent', 'donor_git')})
                self.record.update(worktree=str(self.repos[0].root),
                                   target_commit=self.repos[0].head)
                _write(self.run_dir / 'inspection.json', {'hunks': self.units,
                                                         'source_diff': self.diff})
                self._save()
                _write_wrappers(self.run_dir)
            locator = Locator(self.repos, self.units)
            location = locator.locate(lambda state: _write(self.run_dir / 'discovery-progress.json', state))
            location['target_history'] = locator.history(location)
            location['source_history'] = self.donor
            _write(self.run_dir / 'location.json', location)
            self._originals_unchanged()
            self.record['status'] = 'DISCOVERED'
            self._save()
            if inspect_only:
                return self.record
            with self._runtime('assessment') as runtime:
                runtime.start(self.run_dir, SYSTEM + '\nAssessment phase is strictly read-only, using pinned original Git objects.')
                prompt = assessment_prompt(self.diff, inventory, location) + self._donor_tools_context()
                for attempt in range(1, max_attempts + 1):
                    raw = self._turn(runtime, prompt, ASSESSMENT_SCHEMA, read_only=True)
                    _write(self.run_dir / f'assessment-{attempt}.json', raw)
                    try:
                        assessment = self.ground(raw)
                        break
                    except AssessmentError as exc:
                        self.record.setdefault('assessment_rejections', []).append(str(exc))
                        if attempt == max_attempts:
                            raise
                        prompt = f'Correct the complete read-only assessment. Evidence rejection: {exc}. Return all units in the same schema. Do not edit files.'
            _write(self.run_dir / 'assessment.json', assessment)
            self._protect(self.run_dir / 'assessment.json')
            self.record.update(model_execution='succeeded', impact_decision=assessment['status'])
            if assessment['status'] != 'AFFECTED':
                self.record['status'] = 'INCONCLUSIVE' if assessment['status'] == 'UNKNOWN' else assessment['status']
                self._save()
                return self.record
            self._prepare_children(assessment)
            if self.donor['status'] == 'VERIFIED':
                from .mapped_backend import run_backends
                return run_backends(self, assessment, verify=verify, max_attempts=max_attempts,
                                    impact_only=impact_only, mechanical=mechanical)
            if impact_only:
                self.record['status'] = 'AFFECTED'
                self._save()
                return self.record
            with self._runtime('migration') as runtime:
                runtime.start(self.workspace, SYSTEM)
                prompt = (migration_prompt(self.diff, assessment, assessment['writable_paths'], self.workspace)
                          + self._donor_tools_context())
                for attempt in range(1, max_attempts + 1):
                    self.record['attempt'] = attempt
                    raw = self._turn(runtime, prompt, MIGRATION_SCHEMA, read_only=False)
                    _write(self.run_dir / f'coverage-{attempt}.json', raw)
                    coverage_error = None
                    try:
                        self._coverage(raw, assessment)
                    except AssessmentError as exc:
                        coverage_error = str(exc)
                    patches, verification = {}, {}
                    for key, child in self.children.items():
                        child.record['attempt'] = attempt
                        required_ids = {t['unit_id'] for t in self.mapping_plan.targets(key)
                                        if t['action'] == 'edit' and t['status'] == 'AFFECTED'}
                        child._current_hunks = [u for u in self.units if u['id'] in required_ids]
                        try:
                            patch = child.export_patch(attempt)
                        except CandidateRejected as exc:
                            coverage_error = coverage_error or str(exc)
                            verification[key] = {'status': 'NOT_RUN',
                                                 'blocked_by': 'NEW_FILE_INTEGRATION'}
                            child.record.update(status='VALIDATION_FAILED',
                                                final_verification=verification[key])
                            child._write_record()
                            continue
                        if patch.strip():
                            patches[key] = {'file': str(child.run_dir / 'backport.patch'),
                                            'sha256': child.record['patch_sha256'], 'target': child.case.target_commit,
                                            'replay': child.record['patch_replay']}
                            if not coverage_error:
                                declarations = '\n'.join(
                                    f"HUNK-RESULT {c['id']} implemented {c['explanation']}"
                                    for c in raw['coverage'] if c['id'] in required_ids and c['status'] == 'implemented')
                                ledger = child._check_hunk_results(declarations, child._last_audit['changed_files'], patch)
                                child.record['hunk_results'] = ledger['claims']
                                if not ledger['ok']:
                                    coverage_error = ledger['feedback']
                            verification[key] = ({'status': 'NOT_RUN', 'blocked_by': 'HUNK_LEDGER'}
                                if coverage_error else child.verify() if verify else {'status': 'NOT_REQUESTED'})
                            child.record['final_verification'] = verification[key]
                        child._write_record()
                    self._audit()
                    self.record['patches'], self.record['verification'] = patches, verification
                    for layer in ('source_contract', 'android_module_build', 'android_runtime'):
                        outcomes = [v.get('stages', {}).get(layer) for v in verification.values()]
                        self.record[layer] = ('FAIL' if 'FAIL' in outcomes else
                            'PASS' if outcomes and all(o == 'PASS' for o in outcomes) else
                            'PARTIAL' if 'PASS' in outcomes else 'NOT_CONFIGURED')
                    if not patches:
                        coverage_error = coverage_error or 'affected assessment produced no patch'
                    if coverage_error:
                        self.record.update(status='MIGRATION_INCOMPLETE', coverage_error=coverage_error)
                    elif any(v['status'] == 'FAIL' for v in verification.values()):
                        self.record['status'] = 'VALIDATION_FAILED'
                    else:
                        self.record.pop('coverage_error', None)
                        self.record['patch_replay'] = 'pass'
                        self.record['status'] = ('VALIDATED' if verification and all(
                            v['status'] == 'PASS' and v.get('sufficient_for_validated', False)
                            for v in verification.values())
                                                 else 'PATCH_UNVERIFIED')
                        break
                    self._save()
                    prompt = ('Revise the candidate using the same complete migration coverage schema. Keep the allowlist and plan. '
                              'Do not weaken validation.\n' + json.dumps({'coverage_error': coverage_error, 'verification': verification}, ensure_ascii=False))
            _write(self.run_dir / 'patch-bundle.json', self.record['patches'])
            self._save()
            return self.record
        except Exception as exc:
            self.record.update(status='FAILED', error={'type': type(exc).__name__, 'kind': getattr(exc, 'kind', 'DIFF_WORKFLOW_ERROR'),
                'message': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))})
            if self.record['model_execution'] == 'not_run' and not inspect_only:
                self.record['model_execution'] = 'failed'
            self._save()
            raise
