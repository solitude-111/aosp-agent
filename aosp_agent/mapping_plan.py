"""Shared, grounded mapping front end; no dataset target filenames are inputs."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .case import validate_relative_path
from .diff_prompts import ASSESSMENT_SCHEMA
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


class MappingPlanner:
    def __init__(self, repositories, units):
        self.repos, self.units = repositories, units

    def _owner(self, workspace_path):
        validate_relative_path(workspace_path)
        matches = [r for r in self.repos if workspace_path.startswith(r.key + '/')]
        if not matches:
            raise AssessmentError(f'path does not belong to a supplied repository: {workspace_path}')
        repo = max(matches, key=lambda r: len(r.key))
        relative = workspace_path[len(repo.key) + 1:]
        validate_relative_path(relative)
        return repo, relative

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


@dataclass(frozen=True)
class MappingPlan:
    # Store canonical JSON rather than a mutable nested dict shared with a model.
    payload: str

    @classmethod
    def create(cls, assessment, repositories, units, source):
        return cls(json.dumps({
            'version': 1, 'assessment': assessment, 'source': source,
            'targets': {repo.key: repo.head for repo in repositories},
            'donor_paths': {u['id']: [p for p in (u['old_path'], u['new_path']) if p] for u in units},
            'write_scope_origin': 'grounded_mapping_not_dataset_files',
        }, sort_keys=True, ensure_ascii=False))

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
