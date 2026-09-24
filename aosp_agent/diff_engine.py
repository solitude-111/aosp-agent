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
from .discovery import Locator, diff_units, local_git, repositories
from .diff_prompts import ASSESSMENT_SCHEMA, MIGRATION_SCHEMA, assessment_prompt, migration_prompt
from .engine import AospBackportAgent, AssessmentError
from .glm_runtime import DEFAULT_GLM_MODEL
from .prompts import SYSTEM


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    temporary.replace(path)


def _shape(raw, schema):
    from jsonschema import validate, ValidationError
    try:
        validate(raw, schema)
    except ValidationError as exc:
        raise AssessmentError('invalid response structure: ' + exc.message) from exc


def _excerpt(lines, evidence):
    start, end = evidence['line_start'], evidence['line_end']
    if start < 1 or end < start or end > len(lines):
        raise AssessmentError(f'invalid range: {evidence["path"]}:{start}-{end}')
    if '\n'.join(lines[start - 1:end]).strip() != evidence['excerpt'].strip():
        raise AssessmentError(f'excerpt mismatches exact range: {evidence["path"]}:{start}-{end}')


class DiffBackportAgent:
    def __init__(self, patch: Path, target_root: Path, run_root: Path, *, model=DEFAULT_GLM_MODEL,
                 model_provider=None, turn_timeout=900, runtime_factory=None, validation=None,
                 api_base_url=None, api_key_env=None):
        self.patch_bytes = patch.read_bytes()
        self.diff = self.patch_bytes.decode('utf-8')
        self.target_root = target_root.resolve()
        self.units = diff_units(self.diff)
        self.digest = hashlib.sha256(self.patch_bytes).hexdigest()
        self.task_id = 'patch-' + self.digest[:16]
        self.repos = repositories(target_root)
        self.by_key = {r.key: r for r in self.repos}
        self.run_dir = run_root.resolve() / self.task_id
        if any(self.run_dir.is_relative_to(r.root) for r in self.repos):
            raise ValueError('run directory must be outside original repositories')
        self.workspace = self.run_dir / 'workspace'
        self.model, self.provider, self.timeout = model, model_provider or 'bigmodel', turn_timeout
        self.api_base_url = api_base_url or os.environ.get('AOSP_AGENT_GLM_BASE_URL')
        self.api_key_env = api_key_env or os.environ.get('AOSP_AGENT_GLM_API_KEY_ENV') or 'GLM_API_KEY'
        self.factory, self.validation = runtime_factory, validation or {}
        unknown = set(self.validation) - set(self.by_key)
        if unknown:
            raise ValueError(f'validation names unknown repositories: {sorted(unknown)}')
        self.before = {r.key: r.state() for r in self.repos}
        self.children = {}
        self.record = {'task_id': self.task_id, 'input_patch_sha256': self.digest, 'status': 'INITIALIZED',
                       'backend': 'glm_api', 'model': model, 'model_execution': 'not_run',
                       'impact_decision': 'UNKNOWN', 'patch_replay': 'not_run',
                       'verification_scope': 'configured_commands_only', 'runtime_security_proven': False,
                       'android_module_build': 'NOT_CONFIGURED', 'android_runtime': 'NOT_CONFIGURED',
                       'poc_execution': 'NOT_RUN'}

    def _save(self):
        _write(self.run_dir / 'run.json', self.record)

    def _owner(self, workspace_path):
        validate_relative_path(workspace_path)
        matches = [r for r in self.repos if workspace_path.startswith(r.key + '/')]
        if not matches:
            raise AssessmentError(f'path does not belong to a supplied repository: {workspace_path}')
        repo = max(matches, key=lambda r: len(r.key))
        relative = workspace_path[len(repo.key) + 1:]
        validate_relative_path(relative)
        return repo, relative

    def _originals_unchanged(self):
        for repo in self.repos:
            if repo.state() != self.before[repo.key]:
                raise RuntimeError(f'original repository changed: {repo.key}')

    def _audit(self):
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
        _shape(raw, ASSESSMENT_SCHEMA)
        expected = {u['id']: u for u in self.units}
        if len(raw['units']) != len(expected) or {u['id'] for u in raw['units']} != set(expected):
            raise AssessmentError('assessment must cover every diff unit exactly once')
        for item in raw['units']:
            unit = expected[item['id']]
            if not unit['supported'] and item['status'] != 'UNKNOWN':
                raise AssessmentError('unsupported change units require UNKNOWN')
            for target in item['targets']:
                repo, path = self._owner(target['path'])
                lines = repo.read(path).splitlines()
                start, end = target['line_start'], target['line_end']
                if start < 1 or end < start or end > len(lines):
                    raise AssessmentError(f'invalid target mapping range: {target["path"]}')
                if target['relationship'] not in ('dependency', 'test', 'data_or_configuration'):
                    symbol = re.split(r'[.#]|::', target['symbol'])[-1]
                    if (not re.fullmatch(r'[A-Za-z_$][\w$]*', symbol)
                            or not re.search(r'\b' + re.escape(symbol) + r'\s*\(', '\n'.join(lines[start - 1:end]))):
                        raise AssessmentError(f'named function is not present in the mapped region: {target["symbol"]}')
                if not any(e['origin'] == 'target' and e['path'] == target['path']
                           and start <= e['line_start'] <= e['line_end'] <= end for e in item['evidence']):
                    raise AssessmentError(f'target mapping lacks an excerpt within its range: {target["path"]}')
            for evidence in item['evidence']:
                if evidence['origin'] == 'target':
                    repo, path = self._owner(evidence['path'])
                    _excerpt(repo.read(path).splitlines(), evidence)
                    if evidence['path'] not in {t['path'] for t in item['targets']}:
                        raise AssessmentError('target evidence must be included in the mapping')
                else:
                    side = 'before' if evidence['origin'] == 'patch_before' else 'after'
                    source_path = unit['old_path'] if side == 'before' else unit['new_path']
                    if source_path != evidence['path']:
                        raise AssessmentError('source excerpt path is not this unit diff side')
                    start, end = evidence['line_start'], evidence['line_end']
                    if start < 1 or end < start or end - start > len(unit[side]):
                        raise AssessmentError('invalid diff evidence range')
                    try:
                        excerpt = '\n'.join(unit[side][n] for n in range(start, end + 1))
                    except KeyError as exc:
                        raise AssessmentError('source evidence refers to lines outside the supplied diff') from exc
                    if excerpt.strip() != evidence['excerpt'].strip():
                        raise AssessmentError('source evidence mismatches supplied diff')
            if item['status'] != 'UNKNOWN':
                origins = {e['origin'] for e in item['evidence']}
                if 'target' not in origins or not origins & {'patch_before', 'patch_after'}:
                    raise AssessmentError('determinate unit requires target AND diff evidence')
            if item['status'] == 'NOT_AFFECTED':
                if item['absence_basis'] != 'feature_absent':
                    raise AssessmentError('equivalent protection belongs to ALREADY_FIXED; absence requires feature_absent')
                target_evidence = {(e['path'], e['line_start'], e['line_end']) for e in item['evidence'] if e['origin'] == 'target'}
                if len(target_evidence) < 2:
                    raise AssessmentError('feature absence requires two distinct target excerpts, including its entry point')
            elif item['status'] == 'ALREADY_FIXED':
                if item['absence_basis'] != 'equivalent_protection':
                    raise AssessmentError('ALREADY_FIXED requires equivalent_protection rationale')
            elif item['absence_basis'] != 'none':
                raise AssessmentError('AFFECTED/UNKNOWN cannot claim an absence basis')
        affected = {t['path'] for u in raw['units'] if u['status'] == 'AFFECTED'
                    for t in u['targets'] if t['action'] == 'edit'}
        for item in raw['units']:
            if item['status'] == 'AFFECTED' and not any(t['action'] == 'edit' for t in item['targets']):
                raise AssessmentError('affected unit requires at least one explicit edit mapping')
        new_paths = set()
        for addition in raw['new_files']:
            repo, relative = self._owner(addition['path'])
            anchor_repo, _ = self._owner(addition['anchor_path'])
            if repo.key != anchor_repo.key or addition['anchor_path'] not in affected:
                raise AssessmentError('new file must be anchored to an affected mapping in the same repository')
            if relative in repo.files or addition['path'] in new_paths:
                raise AssessmentError('new file exists or is duplicated')
            new_paths.add(addition['path'])
        statuses = {u['status'] for u in raw['units']}
        status = ('UNKNOWN' if 'UNKNOWN' in statuses else 'AFFECTED' if 'AFFECTED' in statuses else
                  'ALREADY_FIXED' if 'ALREADY_FIXED' in statuses else 'NOT_AFFECTED')
        return {**raw, 'status': status, 'writable_paths': sorted(affected | new_paths),
                'evidence_scope': 'source_at_pinned_heads_and_supplied_diff_only',
                'semantic_equivalence': 'model_assessed_not_formally_proven'}

    def _runtime(self, name):
        if self.factory is None:
            from .glm_runtime import GLMRuntime
            factory = GLMRuntime
        else:
            factory = self.factory
        return factory(events_path=self.run_dir / f'glm-{name}.jsonl', model=self.model,
                       model_provider=self.provider, turn_timeout=self.timeout,
                       api_base_url=self.api_base_url, api_key_env=self.api_key_env,
                       env={'GIT_NO_LAZY_FETCH': '1', 'AOSP_AGENT_ENABLE_SEARCH': '1'})

    def _turn(self, runtime, prompt, schema, *, read_only):
        result = runtime.run(prompt, read_only=read_only, output_schema=schema)
        self._audit()
        if result.get('status') != 'completed':
            raise RuntimeError(f'GLM turn did not complete: {result.get("status")}')
        self.record.setdefault('turns', []).append({k: result.get(k) for k in ('thread_id', 'turn_id', 'usage', 'events_path')})
        return json.loads(result['final_response'])

    def _prepare_children(self, assessment):
        # Read dependencies in the same workspace; only AFFECTED mappings/new files become writable.
        selected = {self._owner(t['path'])[0].key for u in assessment['units'] for t in u['targets']}
        for key in sorted(selected):
            repo = self.by_key[key]
            files = tuple(self._owner(p)[1] for p in assessment['writable_paths'] if self._owner(p)[0].key == key)
            spec = self.validation.get(key, [])
            validation_case = Case.from_dict({'cve': 'CVE-2099-0000', 'project': 'validation contract',
                'repository': 'repo', 'source_commit': '0', 'source_parent': '0', 'target_commit': repo.head,
                'files': ['placeholder'], 'validation': spec})
            case = Case(cve=self.task_id, project='AOSP diff-only backport', repository=repo.root.name,
                        source_commit='', source_parent='', target_commit=repo.head, files=files,
                        validation=validation_case.validation, validation_checks=validation_case.validation_checks)
            child = AospBackportAgent(repo.root.parent, self.run_dir / 'exports', case,
                                      model=self.model, source_diff=self.diff)
            child.run_dir = self.run_dir / 'repositories' / key
            child.worktree = self.workspace / key
            self.children[key] = child
            child.prepare()
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

    def run(self, *, inspect_only=False, max_attempts=3, verify=False):
        if max_attempts < 1:
            raise ValueError('max_attempts must be positive')
        self.run_dir.mkdir(parents=True, exist_ok=False)
        try:
            (self.run_dir / 'input.patch').write_bytes(self.patch_bytes)
            inventory = [{'key': r.key, 'original_root': str(r.root), 'head': r.head,
                          'tracked_files': len(r.files)} for r in self.repos]
            _write(self.run_dir / 'inventory.json', inventory)
            self.record['repositories'] = inventory
            locator = Locator(self.repos, self.units)
            location = locator.locate(lambda state: _write(self.run_dir / 'discovery-progress.json', state))
            location['target_history'] = locator.history(location)
            location['source_history'] = 'NOT_PROVIDED; source before/after evidence is limited to diff lines'
            _write(self.run_dir / 'location.json', location)
            self._originals_unchanged()
            self.record['status'] = 'DISCOVERED'
            self._save()
            if inspect_only:
                return self.record
            with self._runtime('assessment') as runtime:
                runtime.start(self.target_root, SYSTEM + '\nAssessment phase is strictly read-only, using pinned original Git objects.')
                prompt = assessment_prompt(self.diff, inventory, location)
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
            self.record.update(model_execution='succeeded', impact_decision=assessment['status'])
            if assessment['status'] != 'AFFECTED':
                self.record['status'] = 'INCONCLUSIVE' if assessment['status'] == 'UNKNOWN' else assessment['status']
                self._save()
                return self.record
            self._prepare_children(assessment)
            with self._runtime('migration') as runtime:
                runtime.start(self.workspace, SYSTEM)
                prompt = migration_prompt(self.diff, assessment, assessment['writable_paths'], self.workspace)
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
                        patch = child.export_patch(attempt)
                        if patch.strip():
                            patches[key] = {'file': str(child.run_dir / 'backport.patch'),
                                            'sha256': child.record['patch_sha256'], 'target': child.case.target_commit,
                                            'replay': child.record['patch_replay']}
                            verification[key] = child.verify() if verify else {'status': 'NOT_REQUESTED'}
                        child._write_record()
                    self._audit()
                    self.record['patches'], self.record['verification'] = patches, verification
                    if not patches:
                        coverage_error = coverage_error or 'affected assessment produced no patch'
                    if coverage_error:
                        self.record.update(status='MIGRATION_INCOMPLETE', coverage_error=coverage_error)
                    elif any(v['status'] == 'FAIL' for v in verification.values()):
                        self.record['status'] = 'VALIDATION_FAILED'
                    else:
                        self.record.pop('coverage_error', None)
                        self.record['patch_replay'] = 'pass'
                        self.record['status'] = ('VALIDATED' if verification and all(v['status'] == 'PASS' for v in verification.values())
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
