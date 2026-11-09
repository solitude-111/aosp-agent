"""Shared, grounded mapping front end; no dataset target filenames are inputs."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re

from .case import validate_relative_path
from .diff_prompts import ASSESSMENT_RESPONSE_SCHEMA
from .discovery import RepositoryReadConstraintError
from .engine import AssessmentError


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


class MappingEvidenceError(AssessmentError):
    """Independent locations can be corrected together without weakening checks."""
    def __init__(self, errors):
        self.errors = errors
        super().__init__('assessment evidence errors: ' + json.dumps(errors, ensure_ascii=False))


def _expand_evidence_references(raw):
    assessment = deepcopy(raw)
    assessment.pop('candidate_resolution', None)
    unit_evidence = {row['id']: row['evidence'] for row in assessment['units']}
    errors = []

    def resolve(unit_id, index, pointer):
        evidence = unit_evidence.get(unit_id, [])
        if not 1 <= index <= len(evidence):
            errors.append({'path': pointer, 'error': f'invalid evidence index {index} for unit {unit_id}'})
            return None
        return evidence[index - 1]

    for i, row in enumerate(assessment.get('scope_closure', {}).get('units', [])):
        for j, entry in enumerate(row['evidence']):
            if type(entry) is int:
                row['evidence'][j] = resolve(row['unit_id'], entry, f'/scope_closure/units/{i}/evidence/{j}')
    revisions = {'target': 'target', 'patch_before': 'source_parent', 'patch_after': 'source_fix'}
    for i, group in enumerate(assessment.get('proof_groups', [])):
        evidence = group['impact']['evidence']
        for j, entry in enumerate(evidence):
            if 'evidence_index' not in entry:
                continue
            source = resolve(entry['unit_id'], entry['evidence_index'], f'/proof_groups/{i}/impact/evidence/{j}')
            if source is not None:
                evidence[j] = {key: source[key] for key in ('path', 'line_start', 'line_end', 'excerpt')}
                evidence[j].update(unit_id=entry['unit_id'], revision=revisions[source['origin']], claim=entry['claim'])
    if errors:
        raise MappingEvidenceError(errors[:32])
    return assessment


class MappingPlanner:
    def __init__(self, repositories, units):
        self.repos, self.units = repositories, units

    def _owner(self, workspace_path):
        try:
            validate_relative_path(workspace_path)
        except ValueError as exc:
            raise AssessmentError(str(exc)) from exc
        matches = [r for r in self.repos if workspace_path.startswith(r.key + '/')]
        if not matches:
            raise AssessmentError(f'path does not belong to a supplied repository: {workspace_path}')
        repo = max(matches, key=lambda r: len(r.key))
        relative = workspace_path[len(repo.key) + 1:]
        try:
            validate_relative_path(relative)
        except ValueError as exc:
            raise AssessmentError(str(exc)) from exc
        return repo, relative

    def _check_target(self, item, target, read, java_sources):
        lines = read(target["path"])
        start, end = target['line_start'], target['line_end']
        if start < 1 or end < start or end > len(lines):
            raise AssessmentError(f'invalid target mapping range: {target["path"]}:{start}-{end}; pinned file has {len(lines)} lines')
        if target['relationship'] not in ('dependency', 'test', 'data_or_configuration'):
            name = target['symbol'].strip()
            signature = re.fullmatch(r'([A-Za-z_$][\w$]*(?:(?:[.#]|::)[A-Za-z_$][\w$]*)*)(?:\([^()\n]*\))?', name)
            symbol = re.split(r'[.#]|::', signature[1])[-1] if signature else ''
            has_symbol = bool(symbol and re.search(r'\b' + re.escape(symbol) + r'\s*\(',
                                                  '\n'.join(lines[start - 1:end])))
            if target['path'].endswith('.java') and (target['action'] == 'edit' or not has_symbol):
                from .java_regions import JavaSource, method_name
                path = target['path']
                if path not in java_sources:
                    source = JavaSource(path, '\n'.join(lines))
                    java_sources[path] = None if source.tree.root_node.has_error else source
                source = java_sources[path]
                methods = source.overlapping_methods(start, end) if source else []
                if target['action'] == 'edit' and len(methods) > 1:
                    ranges = ', '.join(f'{method_name(m)}:{source.first(m)}-{source.last(m)}' for m in methods[:8])
                    raise AssessmentError('Java edit mapping crosses method boundaries. Map each needed '
                                          'method separately with its own evidence. Pinned declarations: ' + ranges)
                if not has_symbol and len(methods) == 1:
                    method = methods[0]
                    has_symbol = (method_name(method) == symbol and source.first(method) <= start
                                  and end <= source.last(method) and not any(
                                      other != method and source.first(other) <= end and start <= source.last(other)
                                      for other in source.methods))
            if not has_symbol:
                raise AssessmentError(f'named function is not present in the mapped region: {target["symbol"]}')
        if not any(e['origin'] == 'target' and e['path'] == target['path']
                   and start <= e['line_start'] <= e['line_end'] <= end for e in item['evidence']):
            raise AssessmentError(f'target mapping lacks an excerpt within its range: {target["path"]}')

    def _check_evidence(self, unit, item, evidence, read):
        if evidence['origin'] == 'target':
            _excerpt(read(evidence['path']), evidence)
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

    def _check_all_evidence(self, raw, expected, *, excluded_unit_evidence=()):
        cache, java_sources, errors = {}, {}, []
        def read(path):
            if path not in cache:
                repo, relative = self._owner(path)
                cache[path] = repo.read(relative).splitlines()
            return cache[path]
        def check(pointer, callback):
            try:
                callback()
            except (AssessmentError, RepositoryReadConstraintError) as exc:
                errors.append({'path': pointer, 'error': str(exc)})
                if len(errors) >= 32:
                    raise MappingEvidenceError(errors) from exc
        for i, item in enumerate(raw['units']):
            for j, target in enumerate(item['targets']):
                check(f'/units/{i}/targets/{j}', lambda: self._check_target(item, target, read, java_sources))
            for j, evidence in enumerate(item['evidence']):
                # Keep error pointers indexed against the original response.
                if (i, j) in excluded_unit_evidence:
                    continue
                check(f'/units/{i}/evidence/{j}',
                      lambda: self._check_evidence(expected[item['id']], item, evidence, read))
        # Report repeated bad target quotations across sections together. Their
        # scope, role, donor provenance and causal checks still run afterwards.
        rows = [(f'/scope_closure/units/{i}', r) for i, r in
                enumerate(raw.get('scope_closure', {}).get('units', []))]
        rows += [(f'/proof_groups/{i}/impact', g['impact']) for i, g in
                 enumerate(raw.get('proof_groups', []))]
        for pointer, row in rows:
            for j, evidence in enumerate(row['evidence']):
                if evidence.get('origin', evidence.get('revision')) == 'target':
                    check(f'{pointer}/evidence/{j}', lambda: _excerpt(read(evidence['path']), evidence))
        if errors:
            raise MappingEvidenceError(errors)

    def ground(self, raw):
        _shape(raw, ASSESSMENT_RESPONSE_SCHEMA)
        expected = {u['id']: u for u in self.units}
        if len(raw['units']) != len(expected) or {u['id'] for u in raw['units']} != set(expected):
            raise AssessmentError('assessment must cover every diff unit exactly once')
        raw = _expand_evidence_references(raw)
        self._check_all_evidence(raw, expected)
        for item in raw['units']:
            unit = expected[item['id']]
            if not unit['supported'] and item['status'] != 'UNKNOWN':
                raise AssessmentError('unsupported change units require UNKNOWN')
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
        no_target_edit = {link['unit_id'] for group in raw.get('proof_groups', [])
                          for link in group['support_links'] if link.get('target_disposition') == 'no_target_edit'}
        for item in raw['units']:
            if item['status'] == 'AFFECTED' and not any(t['action'] == 'edit' for t in item['targets']):
                if item['id'] not in no_target_edit or not item['targets']:
                    raise AssessmentError('affected unit requires an explicit edit mapping or a read-only support link')
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


@dataclass(frozen=True)
class MappingPlan:
    # Store canonical JSON rather than a mutable nested dict shared with a model.
    payload: str

    @classmethod
    def create(cls, assessment, repositories, units, source, *, repair_contract=()):
        plan = {
            'version': 1, 'assessment': assessment, 'source': source,
            'targets': {repo.key: repo.head for repo in repositories},
            'donor_paths': {u['id']: [p for p in (u['old_path'], u['new_path']) if p] for u in units},
            'write_scope_origin': 'grounded_mapping_not_dataset_files',
        }
        if repair_contract:
            plan['repair_contract'] = repair_contract
        return cls(json.dumps(plan, sort_keys=True, ensure_ascii=False))

    @property
    def sha256(self):
        return hashlib.sha256(self.payload.encode()).hexdigest()

    def data(self):
        return json.loads(self.payload)

    def files(self, key):
        prefix = key + '/'
        return tuple(p[len(prefix):] for p in self.data()['assessment']['writable_paths']
                     if p.startswith(prefix))

    def targets(self, key, *, unit_id=None, donor_path=None):
        data = self.data()
        prefix = key + '/'
        result = []
        for unit in data['assessment']['units']:
            if unit_id is not None and unit['id'] != unit_id:
                continue
            if donor_path is not None and donor_path not in data['donor_paths'][unit['id']]:
                continue
            for target in unit['targets']:
                if target['path'].startswith(prefix):
                    result.append({**target, 'path': target['path'][len(prefix):],
                                   'unit_id': unit['id'], 'status': unit['status']})
        return result
