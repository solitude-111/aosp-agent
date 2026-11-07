"""Ground repository expansion and per-unit scope claims before final decisions."""
from .engine import AssessmentError
from .mapping_plan import MappingEvidenceError, _excerpt
from .discovery import functions
from pathlib import Path


def _mapped_anchor(evidence, targets):
    return [t for t in targets if evidence['origin'] == 'target' and t['path'] == evidence['path']
            and t['line_start'] <= evidence['line_start'] <= evidence['line_end'] <= t['line_end']]


def ground_evidence(controller, unit_id, evidence):
    units = {u['id']: u for u in controller.units}
    if unit_id not in units:
        raise AssessmentError('scope evidence names an unknown source unit')
    unit = units[unit_id]
    if evidence['origin'] == 'target':
        repo, path = controller._owner(evidence['path'])
        _excerpt(repo.read(path).splitlines(), evidence)
    else:
        side = 'before' if evidence['origin'] == 'patch_before' else 'after'
        path = unit['old_path'] if side == 'before' else unit['new_path']
        first, last = evidence['line_start'], evidence['line_end']
        if evidence['path'] != path or last < first or last - first >= len(unit[side]):
            raise AssessmentError('scope evidence is outside its source diff unit')
        try:
            content = '\n'.join(unit[side][n] for n in range(first, last + 1))
        except KeyError as exc:
            raise AssessmentError('scope source lines are outside the supplied diff') from exc
        if content.strip() != evidence['excerpt'].strip():
            raise AssessmentError('scope source excerpt mismatch')


def check_scope(controller, assessment, required=False):
    requests = assessment.get('repository_requests') or []
    for request in requests:
        if not request['evidence']:
            raise AssessmentError('repository expansion requires grounded evidence, not a bare guess')
        for evidence in request['evidence']:
            ground_evidence(controller, request['unit_id'], evidence)
    if requests:
        return {'status': 'EXPANSION_REQUIRED', 'requests': requests}
    closure = assessment.get('scope_closure')
    if not closure:
        if required:
            raise AssessmentError('project-first assessment requires per-unit scope_closure or grounded repository_requests')
        return {'status': 'EXPLICIT_SCOPE_ONLY'}
    expected = {u['id'] for u in controller.units}
    mapped = {u['id']: u for u in assessment['units']}
    sources = {u['id']: u for u in controller.units}
    rows = closure['units']
    if len(rows) != len(expected) or {r['unit_id'] for r in rows} != expected:
        raise AssessmentError('scope closure must cover every source unit exactly once')
    open_questions = []
    errors, function_checks = [], []

    def report(path, unit_id, message):
        errors.append({'path': path, 'unit_id': unit_id, 'error': message})
        if len(errors) == 32:
            raise MappingEvidenceError(errors)

    for row_index, row in enumerate(rows):
        unit_id = row['unit_id']
        prefix = f'/scope_closure/units/{row_index}'
        open_questions.extend({'unit_id': unit_id, 'question': q} for q in row['unresolved_questions'])
        for evidence in row['evidence']:
            ground_evidence(controller, unit_id, evidence)
        if not row['unresolved_questions']:
            targets = mapped[unit_id]['targets']
            origins = {e['origin'] for e in row['evidence']}
            source = sources[unit_id]
            donor_origins = {origin for side, origin in (('before', 'patch_before'), ('after', 'patch_after')) if source[side]}
            missing = ({'target'} | donor_origins) - origins
            if missing:
                report(prefix + '/evidence', unit_id,
                       'closed scope requires target and all available donor diff sides; missing: '
                       + ', '.join(sorted(missing)))
            target_evidence = [(i, e) for i, e in enumerate(row['evidence']) if e['origin'] == 'target']
            for i, e in target_evidence:
                if not _mapped_anchor(e, targets):
                    same_path = [t for t in targets if t['path'] == e['path']]
                    ranges = ', '.join(f"{t['line_start']}-{t['line_end']}" for t in same_path[:8]) or 'none'
                    report(f'{prefix}/evidence/{i}', unit_id,
                           'scope evidence must anchor within this unit target mappings; '
                           f"cited {e['path']}:{e['line_start']}-{e['line_end']}, mapped ranges: {ranges}")
            for t in targets:
                if not any(t in _mapped_anchor(e, targets) for _, e in target_evidence):
                    report(prefix + '/evidence', unit_id,
                           'scope closure must support every mapped target region; missing citation for '
                           f"{t['path']}:{t['line_start']}-{t['line_end']}")
            projects = {controller._owner(t['path'])[0].key for t in targets}
            if not projects or set(row['dependencies_checked']) != projects:
                report(prefix + '/dependencies_checked', unit_id,
                       f'scope dependencies must equal the evidenced mapped projects; expected: {sorted(projects)}')
            steps = row.get('proof_steps', [])
            roles = {'entrypoint', 'state_flow', 'security_condition', 'dependency'}
            if len(steps) != len(roles) or {s['role'] for s in steps} != roles:
                report(prefix + '/proof_steps', unit_id,
                       'scope closure requires entrypoint, state flow, security condition and dependency obligations exactly once')
            for step_index, step in enumerate(steps):
                pointer = f'{prefix}/proof_steps/{step_index}/evidence'
                role = step['role']
                indices = step['evidence']
                if not indices or any(not 1 <= i <= len(row['evidence']) for i in indices):
                    report(pointer, unit_id, f'{role} scope proof obligation lacks valid evidence indices; '
                           f"use 1-based indices within 1-{len(row['evidence'])}")
                    continue
                target_indices = [i for i in indices if row['evidence'][i - 1]['origin'] == 'target']
                anchors = [row['evidence'][i - 1] for i in target_indices]
                if not anchors:
                    report(pointer, unit_id, f'{role}: each scope proof obligation needs mapped target evidence; '
                           f'target evidence indices: {[i + 1 for i, e in target_evidence if _mapped_anchor(e, targets)]}')
                    continue
                if role == 'dependency':
                    if {controller._owner(e['path'])[0].key for e in anchors} != projects:
                        report(pointer, unit_id, f'dependency obligation must cite every mapped project: {sorted(projects)}')
                    continue
                for evidence_index, e in zip(target_indices, anchors):
                    regions = _mapped_anchor(e, targets)
                    # Data/configuration and test changes still need exact mapped
                    # evidence; code claims must anchor inside a real function.
                    if all(t['relationship'] in ('data_or_configuration', 'test') for t in regions):
                        continue
                    function_checks.append((pointer, unit_id, role, evidence_index, e))
    # Check source definitions only after structural diagnostics are clear.
    if errors:
        raise MappingEvidenceError(errors)
    definitions_by_path = {}
    for pointer, unit_id, role, evidence_index, e in function_checks:
        if e['path'] not in definitions_by_path:
            repo, path = controller._owner(e['path'])
            definitions_by_path[e['path']] = functions(repo.read(path), Path(path).suffix)
        definitions = definitions_by_path[e['path']]
        if not any(d['line_start'] <= e['line_start'] <= e['line_end'] <= d['line_end'] for d in definitions):
            overlaps = [d for d in definitions if d['line_start'] <= e['line_end']
                        and e['line_start'] <= d['line_end']]
            ranges = ', '.join(f"{d['symbol']}:{d['line_start']}-{d['line_end']}"
                               for d in overlaps[:8]) or 'none'
            report(pointer, unit_id, 'code scope obligations require function-region evidence; '
                   f"{role} cites closure evidence #{evidence_index} at {e['path']}:{e['line_start']}-{e['line_end']}; "
                   f'overlapping functions: {ranges}. Cite a separate exact excerpt within each needed function.')
    if errors:
        raise MappingEvidenceError(errors)
    return {'status': 'OPEN_QUESTIONS' if open_questions else 'GROUNDED_MODEL_SCOPE',
            'unresolved_questions': open_questions,
            'limitation': 'Grounded scope claims are model-assessed; not a whole-program or product reachability proof.'}
