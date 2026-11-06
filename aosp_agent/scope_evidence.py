"""Ground repository expansion and per-unit scope claims before final decisions."""
from .engine import AssessmentError
from .mapping_plan import _excerpt
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
    for row in rows:
        open_questions.extend({'unit_id': row['unit_id'], 'question': q} for q in row['unresolved_questions'])
        for evidence in row['evidence']:
            ground_evidence(controller, row['unit_id'], evidence)
        if not row['unresolved_questions']:
            targets = mapped[row['unit_id']]['targets']
            origins = {e['origin'] for e in row['evidence']}
            source = sources[row['unit_id']]
            donor_origins = {origin for side, origin in (('before', 'patch_before'), ('after', 'patch_after')) if source[side]}
            if 'target' not in origins or not donor_origins <= origins:
                raise AssessmentError('closed scope requires target and all available donor diff sides')
            target_evidence = [e for e in row['evidence'] if e['origin'] == 'target']
            if any(not _mapped_anchor(e, targets) for e in target_evidence):
                raise AssessmentError('scope evidence must anchor within this unit target mappings')
            if any(not any(t in _mapped_anchor(e, targets) for e in target_evidence) for t in targets):
                raise AssessmentError('scope closure must support every mapped target region')
            projects = {controller._owner(t['path'])[0].key for t in targets}
            if not projects or set(row['dependencies_checked']) != projects:
                raise AssessmentError('scope dependencies must equal the evidenced mapped projects')
            steps = row.get('proof_steps', [])
            roles = {'entrypoint', 'state_flow', 'security_condition', 'dependency'}
            if len(steps) != len(roles) or {s['role'] for s in steps} != roles:
                raise AssessmentError('scope closure requires entrypoint, state flow, security condition and dependency obligations')
            for step in steps:
                indices = step['evidence']
                if not indices or any(not 1 <= i <= len(row['evidence']) for i in indices):
                    raise AssessmentError('scope proof obligation lacks valid evidence indices')
                anchors = [row['evidence'][i - 1] for i in indices if row['evidence'][i - 1]['origin'] == 'target']
                if not anchors:
                    raise AssessmentError('each scope proof obligation needs mapped target evidence')
                if step['role'] == 'dependency':
                    if {controller._owner(e['path'])[0].key for e in anchors} != projects:
                        raise AssessmentError('dependency obligation must cite every mapped project')
                    continue
                for e in anchors:
                    regions = _mapped_anchor(e, targets)
                    # Data/configuration and test changes still need exact mapped
                    # evidence; code claims must anchor inside a real function.
                    if all(t['relationship'] in ('data_or_configuration', 'test') for t in regions):
                        continue
                    repo, path = controller._owner(e['path'])
                    definitions = functions(repo.read(path), Path(path).suffix)
                    if not any(d['line_start'] <= e['line_start'] <= e['line_end'] <= d['line_end'] for d in definitions):
                        raise AssessmentError('code scope obligations require function-region evidence')
    return {'status': 'OPEN_QUESTIONS' if open_questions else 'GROUNDED_MODEL_SCOPE',
            'unresolved_questions': open_questions,
            'limitation': 'Grounded scope claims are model-assessed; not a whole-program or product reachability proof.'}
