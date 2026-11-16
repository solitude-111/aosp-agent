"""Independent, read-only challenge before accepting feature-absence exclusions.

Grounding establishes provenance and required proof coverage, not formal semantic
correctness. Missing modern APIs never constitute a proof that an older fault
path is absent. No dataset verdict or historical answer is an input here.
"""
from __future__ import annotations

import copy
import ast
from dataclasses import dataclass
import json
import re
from pathlib import Path

from .assessment_repair import REPAIR_SCHEMA, apply_repair, digest
from .diff_prompts import EVIDENCE, STRING, array, enum, obj
from .discovery import RepositoryReadConstraintError, functions
from .engine import AssessmentError
from .mapping_plan import MappingEvidenceError, _excerpt, _shape


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


class ExclusionCounterpartChallenge(ExclusionReviewError):
    """Grounded target behavior challenges the proposed exclusion."""

    def __init__(self, details):
        self.details = details
        super().__init__('feature-absence not established; reconsider old-operation counterparts: '
                         + json.dumps(details, ensure_ascii=False))


class ExclusionReviewUnresolved(ExclusionReviewError):
    """No grounded counterevidence can be sent back to mapping."""


@dataclass
class ExclusionCorrections:
    """Limit reviewer corrections across every scope round of the task."""

    remaining: int = 2


PATH_GUIDANCE = (
    'For origin=target, use the exact repository key plus "/" plus the pinned file path, '
    'as in the proposal, without a "target:" prefix. For patch_before and patch_after, '
    'use the original old and new diff paths respectively, with original side line numbers '
    'and no added repository key.'
)


def review_prompt(controller, assessment, inventory):
    proposals = [u for u in assessment['units'] if u['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED')]
    behaviors = [row for row in getattr(controller, 'guarded_obligations', ())
                 if row['unit_id'] in {u['id'] for u in proposals}]
    return f'''Independently challenge these proposed no-fix-needed conclusions. Work READ ONLY.
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
Follow the same object or state through its last relevant update, the protection check and the
sensitive operation. Verify the check sees the updated state before that operation on every relevant
path. A check of a different object or of pre-update state cannot establish equivalent protection.
For a configuration-only hunk, inspect declaration and consumers separately. Its absence does not
settle whether a production hunk's operation exists in the old implementation.

Return exactly one review for every proposed unit. Evidence indices are 1-based within that review's
evidence array. Cite short, exact, contiguous excerpts. {PATH_GUIDANCE}
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
use COUNTERPART_POSSIBLE and cite its target entry/state-flow path for remapping.
COUNTERPART_POSSIBLE is not an AFFECTED verdict. UNKNOWN is mandatory if proof remains incomplete.
Never infer runtime safety or affectedness just from compilation, version numbers or API names.
For any extracted guarded source behaviors, separately account for every operation and protection
before confirming an exclusion. Missing any one of them leaves the proposal unresolved.
Extracted source behaviors: {json.dumps(behaviors, ensure_ascii=False)}

Repository inventory:\n''' + json.dumps(inventory, ensure_ascii=False) + '\nInitial retrieval limits:\n' + json.dumps(
        controller.record.get('retrieval_summary', {}), ensure_ascii=False) + '\nProposals:\n' + json.dumps(
        proposals, ensure_ascii=False) + '\nComplete input diff:\n' + controller.diff + controller._donor_tools_context()


def ground_review(controller, assessment, raw, *, target_cache=None):
    """Validate citations and proof obligations, returning units needing remapping."""
    _shape(raw, REVIEW_SCHEMA)
    proposed_status = {u['id']: u['status'] for u in assessment['units']
                       if u['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED')}
    proposed = set(proposed_status)
    if len(raw['units']) != len(proposed) or {u['id'] for u in raw['units']} != proposed:
        raise AssessmentError('exclusion review must cover every proposed no-fix-needed unit exactly once')
    source = {u['id']: u for u in controller.units}
    cache = {} if target_cache is None else target_cache

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

    errors = []
    for i, item in enumerate(raw['units']):
        unit = source[item['id']]
        for j, e in enumerate(item['evidence']):
            try:
                if e['origin'] == 'target':
                    _excerpt(target_content(e).splitlines(), e)
                else:
                    _ground_donor_excerpt(unit, e)
            except (AssessmentError, RepositoryReadConstraintError) as exc:
                errors.append({'path': f'/units/{i}/evidence/{j}', 'error': str(exc)})
                if len(errors) >= 32:
                    raise MappingEvidenceError(errors) from exc
    if errors:
        raise MappingEvidenceError(errors)

    challenged = []
    for i, item in enumerate(raw['units']):
        unit = source[item['id']]
        groups = {}
        for field in ('entrypoint_evidence', 'state_flow_evidence', 'blocking_evidence', 'donor_evidence'):
            indices = item[field]
            if any(not 1 <= n <= len(item['evidence']) for n in indices):
                raise AssessmentError(f'/units/{i}/{field}: exclusion review has invalid evidence indices')
            groups[field] = [item['evidence'][n - 1] for n in indices]
        expected_verdict = ('CONFIRMED_ABSENT' if proposed_status[item['id']] == 'NOT_AFFECTED'
                            else 'CONFIRMED_PROTECTED')
        if item['verdict'] == 'COUNTERPART_POSSIBLE':
            if item['representation'] not in ('same', 'equivalent') or not all(
                any(e['origin'] == 'target' for e in groups[field])
                for field in ('entrypoint_evidence', 'state_flow_evidence')
            ):
                raise AssessmentError(f'/units/{i}: counterpart requires same or equivalent representation '
                                      'and pinned target entrypoint and state-flow evidence')
        if item['verdict'] != expected_verdict:
            challenged.append(item['id'])
            continue
        representations = {'absent'} if expected_verdict == 'CONFIRMED_ABSENT' else {'same', 'equivalent'}
        if item['representation'] not in representations or item['unresolved_assumptions']:
            requirement = 'absent operation' if expected_verdict == 'CONFIRMED_ABSENT' else 'same or equivalent protection'
            raise AssessmentError(f'/units/{i}: confirmed exclusion requires ' + requirement + ' and no unresolved assumptions')
        for field in ('entrypoint_evidence', 'state_flow_evidence', 'blocking_evidence'):
            if not groups[field] or not all(executable(e) for e in groups[field]):
                raise AssessmentError(f'/units/{i}/{field}: confirmed absence {field} must cite executable target function regions')
        target_locations = {(e['path'], e['line_start'], e['line_end'])
                            for field in ('entrypoint_evidence', 'state_flow_evidence', 'blocking_evidence')
                            for e in groups[field]}
        if len(target_locations) < 2:
            raise AssessmentError(f'/units/{i}: confirmed absence needs distinct entry/flow and blocking target anchors')
        origins = {e['origin'] for e in groups['donor_evidence']}
        required = {origin for side, origin in (('before', 'patch_before'), ('after', 'patch_after')) if unit[side]}
        if not required or not required <= origins or 'target' in origins:
            raise AssessmentError(f'/units/{i}/donor_evidence: confirmed absence must compare available before/after diff evidence')
    return challenged


def _ground_donor_excerpt(unit, evidence):
    side = 'before' if evidence['origin'] == 'patch_before' else 'after'
    path = unit['old_path'] if side == 'before' else unit['new_path']
    start, end = evidence['line_start'], evidence['line_end']
    if path != evidence['path'] or end < start or end - start >= len(unit[side]):
        raise AssessmentError('exclusion review source evidence is outside its diff unit')
    try:
        actual = '\n'.join(unit[side][n] for n in range(start, end + 1))
    except KeyError as exc:
        raise AssessmentError('exclusion review source evidence is outside its diff unit') from exc
    if actual.strip() != evidence['excerpt'].strip():
        raise AssessmentError('exclusion review source excerpt mismatches supplied diff')


def _review_repair_prompt(raw, error):
    return f'''Correct the latest independent read-only review in this session.
Current base_sha256: {digest(raw)}
Validation errors: {error}
{PATH_GUIDANCE}
Return only base_sha256 and replacements. Each replacement uses a JSON pointer path
(zero-based array indices) and a JSON-encoded value_json. Address all reported locations.
Correct only the invalid fields or evidence entries. Preserve one review per proposed unit
and consistent 1-based evidence indices. To add evidence, replace the existing evidence array
with its old entries and the additions. Overlapping pointers are invalid. A structurally
rejected correction was not applied. Read the pinned source where needed and cite exact lines.
Use UNKNOWN if the proof is incomplete. Do not edit source or change the original proposal.
'''


def review_exclusions(controller, assessment, inventory, attempt):
    """Challenge exclusions independently and correct grounding in the same session."""
    if not any(u['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED') for u in assessment['units']):
        return
    from .diff_engine import _write
    name = f'exclusion-review-{attempt}'
    path = controller.run_dir / f'{name}.json'
    entry = {'attempt': attempt, 'file': path.name, 'status': 'UNRESOLVED', 'corrections': []}
    controller.record.setdefault('exclusion_reviews', []).append(entry)
    cache = {}
    with controller._runtime(name) as runtime:
        runtime.start(controller.run_dir, 'Independently review feature-absence claims. Strictly read only; original repositories must remain unchanged.')
        raw = controller._turn(runtime, review_prompt(controller, assessment, inventory), REVIEW_SCHEMA, read_only=True)
        repair = None
        while True:
            try:
                if repair is not None:
                    raw = apply_repair(raw, repair, schema=REVIEW_SCHEMA)
                challenged = ground_review(controller, assessment, raw, target_cache=cache)
            except AssessmentError as exc:
                entry['error'] = str(exc)
                budget = controller.exclusion_corrections
                if not budget.remaining:
                    break
                number = len(entry['corrections']) + 1
                prior = controller.run_dir / f'{name}-before-repair-{number}.json'
                _write(prior, raw)
                controller._protect(prior)
                entry['corrections'].append({'base': prior.name, 'error': str(exc)})
                budget.remaining -= 1
                controller._save()
                repair = controller._turn(runtime, _review_repair_prompt(raw, exc), REPAIR_SCHEMA, read_only=True)
                repair_path = controller.run_dir / f'{name}-repair-{number}.json'
                _write(repair_path, repair)
                controller._protect(repair_path)
                entry['corrections'][-1]['response'] = repair_path.name
            else:
                entry.pop('error', None)
                break
    _write(path, raw)
    controller._protect(path)
    if 'error' in entry:
        raise ExclusionReviewUnresolved('feature-absence review rejected: ' + entry['error'])
    if challenged:
        details = [u for u in raw['units'] if u['id'] in challenged and u['verdict'] == 'COUNTERPART_POSSIBLE']
        if not details:
            entry['units'] = challenged
            raise ExclusionReviewUnresolved('independent review did not confirm exclusion for: ' + ', '.join(challenged))
        entry.update(status='REMAP_REQUIRED', units=[u['id'] for u in details])
        raise ExclusionCounterpartChallenge(details)
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
    response = {k: result[k] for k in ('reasoning', 'limitations', 'units', 'new_files')}
    if 'proof_groups' in result:
        response['proof_groups'] = [g for g in result['proof_groups'] if g['impact']['status'] == 'AFFECTED']
    return controller.ground(response)
