"""Independent, read-only challenge before accepting feature-absence exclusions.

Grounding establishes provenance and required proof coverage, not formal semantic
correctness. Missing modern APIs never constitute a proof that an older fault
path is absent. No dataset verdict or historical answer is an input here.
"""
from __future__ import annotations

import copy
import ast
import json
import re
from pathlib import Path

from .diff_prompts import EVIDENCE, STRING, array, enum, obj
from .discovery import functions
from .engine import AssessmentError
from .mapping_plan import _excerpt, _shape


INDEXES = array({'type': 'integer', 'minimum': 1})
REVIEW_SCHEMA = obj({'units': array(obj({
    'id': STRING,
    'verdict': enum('CONFIRMED_ABSENT', 'CONFIRMED_PROTECTED', 'COUNTERPART_POSSIBLE', 'UNKNOWN'),
    'security_operation': STRING,
    'representation': enum('same', 'equivalent', 'absent', 'unknown'),
    'old_entrypoint_analysis': STRING,
    'old_state_flow_analysis': STRING,
    'blocking_analysis': STRING,
    'entrypoint_evidence': INDEXES,
    'state_flow_evidence': INDEXES,
    'blocking_evidence': INDEXES,
    'donor_evidence': INDEXES,
    'evidence': array(EVIDENCE),
    'unresolved_assumptions': array(STRING),
})), 'limitations': array(STRING)})


class ExclusionReviewError(AssessmentError):
    """An exclusion needs remapping; exhaustion must remain UNKNOWN."""


def review_prompt(controller, assessment, inventory):
    proposals = [u for u in assessment['units'] if u['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED')]
    return '''Independently challenge these proposed no-fix-needed conclusions. Work READ ONLY.
The proposals are hypotheses, not reference answers. Do not fetch, edit originals, run builds,
read previous runs or look for dataset verdicts. Inspect pinned target code and the supplied diff.
UNAVAILABLE inventory entries cannot be read or mapped; missing objects are not negative evidence.
Initial discovery may defer directory or project searches after finding a text anchor. DEFERRED
means not searched, not absent; matching text does not close dependency or competing-path questions.
Independently investigate the actual old entry/state flow and necessary dependencies. Use bounded
aosp_source search/paths with a path before escalating to project-wide searches when needed.

For each proposed unit, identify the security-relevant OPERATION and faulty state, separately from
the new helper, object type, field, flag, hook or API used to fix it. Trace the older entry point,
caller/dispatch, object and identity/credential/lifetime flow, checks and security-relevant sink.
Follow required dependencies across repositories. A new protection mechanism may be absent precisely
because the older implementation still lacks that protection. Different representation, a new API,
or a prerequisite commit missing from the old tree does not establish that the operation is absent.

Return exactly one review for every proposed unit. Evidence indices are 1-based within that review's
evidence array. Cite exact pinned target excerpts and original diff-side coordinates for that unit.
An ALREADY_FIXED proposal requires CONFIRMED_PROTECTED: identify the existing protection, prove
it applies on the relevant entry/state-flow path before the harmful operation, and compare its
semantics with the donor fix. Merely finding a guard, matching token or similar helper is insufficient.
For this verdict representation must be same or equivalent, with no unresolved material assumptions.
Use UNKNOWN or COUNTERPART_POSSIBLE if coverage, ordering or equivalence is unestablished.
For CONFIRMED_ABSENT, provide executable target entrypoint, state/dispatch flow AND the condition
that blocks the faulty operation; compare the donor diff and resolve every material assumption.
Data/type/registration declarations, comments, absent identifiers and unsuccessful searches alone
cannot support CONFIRMED_ABSENT. Explain what the OLD code actually does, not just what it lacks.
Representation=absent means the security-relevant operation is absent/unreachable, not a missing
modern representation. If the old operation exists under the same or an equivalent representation,
use COUNTERPART_POSSIBLE and cite that path for remapping (including possible existing protection).
COUNTERPART_POSSIBLE is not an AFFECTED verdict. UNKNOWN is mandatory if proof remains incomplete.
Never infer runtime safety or affectedness just from compilation, version numbers or API names.

Repository inventory:\n''' + json.dumps(inventory, ensure_ascii=False) + '\nInitial retrieval limits:\n' + json.dumps(
        controller.record.get('retrieval_summary', {}), ensure_ascii=False) + '\nProposals:\n' + json.dumps(
        proposals, ensure_ascii=False) + '\nComplete input diff:\n' + controller.diff + controller._donor_tools_context()


def ground_review(controller, assessment, raw):
    """Validate citations and proof obligations, returning units needing remapping."""
    _shape(raw, REVIEW_SCHEMA)
    proposed_status = {u['id']: u['status'] for u in assessment['units']
                       if u['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED')}
    proposed = set(proposed_status)
    if len(raw['units']) != len(proposed) or {u['id'] for u in raw['units']} != proposed:
        raise AssessmentError('exclusion review must cover every proposed no-fix-needed unit exactly once')
    source = {u['id']: u for u in controller.units}
    cache = {}

    def target_content(e):
        if e['path'] not in cache:
            repo, path = controller.mapper._owner(e['path'])
            cache[e['path']] = repo.read(path)
        return cache[e['path']]

    def executable(e):
        if e['origin'] != 'target':
            return False
        content = target_content(e)
        definitions = functions(content, Path(e['path']).suffix)
        # This is a conservative lexical/AST anchor, not a control-flow proof.
        # Reject pure data definitions and declarations even if their excerpts
        # are perfectly grounded and mention every donor identifier.
        if not any(d['line_start'] <= e['line_start'] <= e['line_end'] <= d['line_end']
                   for d in definitions):
            return False
        if Path(e['path']).suffix == '.py':
            try:
                nodes = ast.walk(ast.parse(content))
                return any(isinstance(n, (ast.Return, ast.Raise, ast.If, ast.For, ast.While,
                                           ast.Assign, ast.AugAssign, ast.With, ast.Try))
                           and e['line_start'] <= n.lineno <= n.end_lineno <= e['line_end'] for n in nodes)
            except SyntaxError:
                return False
        text = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                      ' ', e['excerpt'], flags=re.DOTALL)
        return bool(re.search(r'\b(return|raise|throw|if|switch|while|for)\b|\b\w+\s*\([^;{}]*\)\s*;', text))

    challenged = []
    for item in raw['units']:
        unit = source[item['id']]
        for e in item['evidence']:
            if e['origin'] == 'target':
                _excerpt(target_content(e).splitlines(), e)
            else:
                side = 'before' if e['origin'] == 'patch_before' else 'after'
                path = unit['old_path'] if side == 'before' else unit['new_path']
                start, end = e['line_start'], e['line_end']
                if path != e['path'] or end < start or end - start >= len(unit[side]):
                    raise AssessmentError('exclusion review source evidence is outside its diff unit')
                try:
                    actual = '\n'.join(unit[side][n] for n in range(start, end + 1))
                except KeyError as exc:
                    raise AssessmentError('exclusion review source evidence is outside its diff unit') from exc
                if actual.strip() != e['excerpt'].strip():
                    raise AssessmentError('exclusion review source excerpt mismatches supplied diff')
        groups = {}
        for field in ('entrypoint_evidence', 'state_flow_evidence', 'blocking_evidence', 'donor_evidence'):
            indices = item[field]
            if any(not 1 <= n <= len(item['evidence']) for n in indices):
                raise AssessmentError(f'exclusion review {field} has invalid evidence indices')
            groups[field] = [item['evidence'][n - 1] for n in indices]
        expected_verdict = ('CONFIRMED_ABSENT' if proposed_status[item['id']] == 'NOT_AFFECTED'
                            else 'CONFIRMED_PROTECTED')
        if item['verdict'] != expected_verdict:
            challenged.append(item['id'])
            continue
        representations = {'absent'} if expected_verdict == 'CONFIRMED_ABSENT' else {'same', 'equivalent'}
        if item['representation'] not in representations or item['unresolved_assumptions']:
            requirement = 'absent operation' if expected_verdict == 'CONFIRMED_ABSENT' else 'same or equivalent protection'
            raise AssessmentError('confirmed exclusion requires ' + requirement + ' and no unresolved assumptions')
        for field in ('entrypoint_evidence', 'state_flow_evidence', 'blocking_evidence'):
            if not groups[field] or not all(executable(e) for e in groups[field]):
                raise AssessmentError(f'confirmed absence {field} must cite executable target function regions')
        target_locations = {(e['path'], e['line_start'], e['line_end'])
                            for field in ('entrypoint_evidence', 'state_flow_evidence', 'blocking_evidence')
                            for e in groups[field]}
        if len(target_locations) < 2:
            raise AssessmentError('confirmed absence needs distinct entry/flow and blocking target anchors')
        origins = {e['origin'] for e in groups['donor_evidence']}
        required = {origin for side, origin in (('before', 'patch_before'), ('after', 'patch_after')) if unit[side]}
        if not required or not required <= origins or 'target' in origins:
            raise AssessmentError('confirmed absence must compare available before/after diff evidence')
    return challenged


def review_exclusions(controller, assessment, inventory, attempt):
    """Run a fresh challenge session within the existing mapping attempt budget."""
    if not any(u['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED') for u in assessment['units']):
        return
    from .diff_engine import _write
    name = f'exclusion-review-{attempt}'
    with controller._runtime(name) as runtime:
        runtime.start(controller.run_dir, 'Independently review feature-absence claims. Strictly read only; original repositories must remain unchanged.')
        raw = controller._turn(runtime, review_prompt(controller, assessment, inventory), REVIEW_SCHEMA, read_only=True)
    path = controller.run_dir / f'{name}.json'
    _write(path, raw)
    controller._protect(path)
    entry = {'attempt': attempt, 'file': path.name, 'status': 'UNRESOLVED'}
    controller.record.setdefault('exclusion_reviews', []).append(entry)
    try:
        challenged = ground_review(controller, assessment, raw)
    except AssessmentError as exc:
        entry['error'] = str(exc)
        raise ExclusionReviewError('feature-absence review rejected: ' + str(exc)) from exc
    if challenged:
        entry.update(status='REMAP_REQUIRED', units=challenged)
        # Grounded counterexample excerpts may guide another complete mapping;
        # they do not directly manufacture an affected verdict or edit scope.
        details = [u for u in raw['units'] if u['id'] in challenged]
        raise ExclusionReviewError('feature-absence not established; reconsider old-operation counterparts: '
                                   + json.dumps(details, ensure_ascii=False))
    entry['status'] = ('CONFIRMED_ABSENT' if all(u['status'] != 'ALREADY_FIXED' for u in assessment['units'])
                       else 'CONFIRMED_EXCLUSIONS')


def unresolved_exclusions(controller, assessment, reason):
    """Keep the grounded proposal, but prevent an unreviewed exclusion escaping."""
    result = copy.deepcopy(assessment)
    for unit in result['units']:
        if unit['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED'):
            unit.update(status='UNKNOWN', absence_basis='none')
            unit['reasoning'] += '\nFeature-absence review did not establish exclusion.'
    result['limitations'].append('Feature-absence review unresolved; see stored review/rejection records.')
    controller.record['exclusion_review_blocked_by'] = reason
    return controller.ground({k: result[k] for k in ('reasoning', 'limitations', 'units', 'new_files')})
