"""Read-only location handoff for the verified-donor backport backend."""
from copy import deepcopy
import json

from .diff_prompts import ASSESSMENT_SCHEMA, EVIDENCE, LINE, STRING, TARGET, array, compact_location, obj
from .discovery import RepositoryReadConstraintError
from .engine import AssessmentError
from .mapping_plan import _shape
from .prompts import IMPACT_SCHEMA
from .scope_evidence import check_scope


REQUESTS = ASSESSMENT_SCHEMA['properties']['repository_requests']
LOCATION_SCHEMA = obj({
    'primary_repository': {'type': 'string'},
    'units': array(obj({'id': STRING, 'targets': array(TARGET), 'evidence': array(EVIDENCE),
                        'location_notes': STRING})),
    'new_files': ASSESSMENT_SCHEMA['properties']['new_files'],
    'repository_requests': REQUESTS,
})
EDIT_FIELDS = {
    'edits': array(obj({'unit_id': STRING, 'target_indices': array(LINE)})),
    'repair_obligations': ASSESSMENT_SCHEMA['properties']['proof_groups']['items']['properties']['repair_obligations'],
    'repository_requests': REQUESTS,
    'location_gaps': array(STRING),
    'new_files': array(STRING),
    'flag_cleanup_support': array(obj({'unit_id': STRING, 'supports': array(STRING)})),
}
BACKEND_SCHEMA = obj({'impact': IMPACT_SCHEMA, **EDIT_FIELDS})
EDIT_SCHEMA = obj(EDIT_FIELDS)


def ground_locations(controller, raw):
    _shape(raw, LOCATION_SCHEMA)
    source = {unit['id']: unit for unit in controller.units}
    units = raw['units']
    if len(units) != len(source) or {unit['id'] for unit in units} != set(source):
        raise AssessmentError('location response must account for every donor unit exactly once')
    controller.mapper._check_all_evidence(raw, source)
    scope = check_scope(controller, {'repository_requests': raw['repository_requests']})
    anchors, writable = set(), set()
    for unit in units:
        for target in unit['targets']:
            repo, _ = controller._owner(target['path'])
            anchors.add(repo.key)
            if target['action'] == 'edit':
                if not source[unit['id']]['supported']:
                    raise AssessmentError('unsupported donor unit cannot propose edits: ' + unit['id'])
                writable.add(target['path'])
    primary = raw['primary_repository']
    if (anchors and primary not in anchors) or (not anchors and primary):
        raise AssessmentError('primary_repository must own a grounded target anchor')
    owners = {controller._owner(path)[0].key for path in writable}
    if len(owners) == 1 and primary not in owners:
        raise AssessmentError('primary_repository must own the candidate edits')
    additions = set()
    for row in raw['new_files']:
        repo, path = controller._owner(row['path'])
        anchor_repo, _ = controller._owner(row['anchor_path'])
        if (anchor_repo.key != repo.key or row['anchor_path'] not in writable
                or path in repo.files or row['path'] in additions):
            raise AssessmentError('new file requires a unique absent path and a grounded edit anchor in the same repository')
        additions.add(row['path'])
    return {**raw, 'units': [{**unit, 'status': 'LOCATED' if unit['targets'] else 'UNLOCATED'} for unit in units],
            'writable_paths': sorted(writable | additions), 'write_projects': sorted(owners),
            'scope_requests': scope.get('requests', [])}


def locate(controller, inventory, location, max_attempts):
    from .diff_engine import _write
    from .retrieval import ACTIVE_BUDGET

    prompt = ('''Locate target code on the pinned commits. Work read-only.
Return every donor unit ID once. Map its counterpart, callers and dependencies to exact
repository-prefixed paths, symbols and line ranges with short pinned target excerpts inside
each range. Mark possible edits as edit and other evidence as read_dependency. This is a
candidate scope for a later backend, not a required edit. For imports, fields, tests and
configuration map the actual region. Report unmapped units with empty targets and a specific
location_notes. Use the write project's key as primary_repository, or a grounded read project
when no edit is known. Leave it empty when no anchor exists. Request a missing project only
with evidence from loaded pinned source or the supplied donor diff. Search bounded paths first.
Do not judge affectedness, prove a vulnerability chain, or edit files.
'''
              + '\nInventory: ' + json.dumps(inventory, ensure_ascii=False)
              + '\nLocation hints: ' + json.dumps(compact_location(location), ensure_ascii=False)
              + '\nDonor diff:\n' + controller.diff + controller._donor_tools_context())
    if controller.location_feedback:
        prompt += '\nRecheck only these gaps; preserve still-valid locations:\n' + json.dumps(
            controller.location_feedback, ensure_ascii=False)
    if controller.location_seed:
        if not controller.location_feedback:
            grounded = ground_locations(controller, controller.location_seed)
            save_location(controller, controller.location_seed)
            controller.record['location_reused'] = True
            return grounded
        prompt += '\nPrevious grounded locations to preserve: ' + json.dumps(
            controller.location_seed, ensure_ascii=False)
    budget = ACTIVE_BUDGET.get()
    controller.record.update(stage='LOCATION', location_handoff={'status': 'RUNNING'})
    controller._save()
    with controller._runtime('location-handoff', timeout=budget.remaining() / 2 if budget else None) as runtime:
        runtime.start(controller.run_dir, 'Resolve source locations. Read pinned objects only.')
        for attempt in range(1, min(max_attempts, 2) + 1):
            raw = controller._turn(runtime, prompt, LOCATION_SCHEMA, read_only=True)
            _write(controller.run_dir / f'location-attempt-{attempt}.json', raw)
            try:
                grounded = ground_locations(controller, raw)
            except AssessmentError as exc:
                controller.record.setdefault('location_rejections', []).append(str(exc))
                controller._save()
                prompt = ('Correct the previous location response. Preserve unaffected locations. '
                          'The controller rejected it for: ' + str(exc))
                continue
            save_location(controller, raw)
            return grounded
    controller.record['location_handoff'] = {'status': 'UNRESOLVED', 'reason': 'LOCATION_EVIDENCE_REJECTED'}
    return None


def save_location(controller, raw):
    from .diff_engine import _write
    path = controller.run_dir / 'grounded-location.json'
    _write(path, raw)
    controller._protect(path)
    controller.record['location_handoff'] = {
        'status': 'READY' if raw['primary_repository'] else 'UNRESOLVED',
        'file': path.name, 'sha256': controller.protected[path],
        'primary_repository': raw['primary_repository'],
        'targets': {repo.key: repo.head for repo in controller.repos},
        'unmapped_units': [row['id'] for row in raw['units'] if not row['targets']]}
    controller.grounded_location = raw


def select_edits(location, response):
    """Restrict the location ceiling to the backend's selected grounded regions."""
    assessment = deepcopy(location)
    units = {row['id']: row for row in assessment['units']}
    selected = {}
    for row in response['edits']:
        ident, indices = row['unit_id'], row['target_indices']
        if ident in selected or ident not in units or not indices or len(indices) != len(set(indices)):
            raise AssessmentError('edits require unique grounded unit IDs and target indices')
        targets = units[ident]['targets']
        if any(i > len(targets) or targets[i - 1]['action'] != 'edit' for i in indices):
            raise AssessmentError('backend edit exceeds grounded location scope: ' + ident)
        selected[ident] = set(indices)
    writable = set()
    for ident, row in units.items():
        edits = selected.get(ident, set())
        for index, target in enumerate(row['targets'], 1):
            if index in edits:
                writable.add(target['path'])
            else:
                target['action'] = 'read_dependency'
        if edits:
            row['status'] = 'AFFECTED'
    allowed_additions = {row['path']: row for row in assessment['new_files'] if row['anchor_path'] in writable}
    additions = response.get('new_files', [])
    if len(additions) != len(set(additions)) or set(additions) - allowed_additions.keys():
        raise AssessmentError('new files exceed grounded scope or lack a selected edit anchor')
    assessment['new_files'] = [allowed_additions[path] for path in additions]
    assessment['writable_paths'] = sorted(writable | {row['path'] for row in assessment['new_files']})
    return assessment, set(selected)


def ground_flag_support(controller, rows, edit_ids):
    from .flag_cleanup import check_flag_cleanup

    units = {unit['id']: unit for unit in controller.units}
    receipts = {}
    for row in rows:
        ident, supports = row['unit_id'], set(row['supports'])
        if (ident in receipts or ident in edit_ids or ident not in units
                or not supports or len(supports) != len(row['supports']) or not supports <= edit_ids):
            raise AssessmentError('flag cleanup must name a read-only unit and selected edit units')
        linked = [units[key] for key in sorted(supports)]
        # These coordinates come from the verified donor diff, not model text.
        entries = [{'unit_id': unit['id'], 'revision': 'source_parent',
                    'line_start': min(unit['before']), 'line_end': max(unit['before'])}
                   for unit in [units[ident], *linked] if unit['before']]
        receipts[ident] = check_flag_cleanup(controller, units[ident], linked, entries)
    return receipts


class BackendHandoff:
    def __init__(self, controller, location):
        from .retrieval import ACTIVE_BUDGET
        self.controller, self.location = controller, location
        self.primary = location['primary_repository']
        self.migration = None
        self.flag_support = {}
        self.location_gaps = []
        self.budget = ACTIVE_BUDGET.get()
        seed = controller.backend_impact_seed
        targets = {repo.key: repo.head for repo in controller.repos}
        self.accepted_impact = seed['assessment'] if seed and seed['targets'] == targets else None

    def target_content(self, path):
        # Preserve local paths used by the original backend. Fully qualified
        # dependency evidence resolves to the admitted repository's own pin.
        controller = self.controller
        qualified = path if any(path.startswith(key + '/') for key in controller.by_key) else self.primary + '/' + path
        repo, relative = controller._owner(qualified)
        try:
            return repo.read(relative)
        except RepositoryReadConstraintError as exc:
            raise AssessmentError('cannot ground target evidence at its pinned repository: ' + qualified) from exc

    def instructions(self, *, reused_impact=False):
        assessment = ('Use the already grounded backend AFFECTED assessment below. Return only the edit '
                      'scope and obligations requested by the schema.\n'
                      + json.dumps(self.accepted_impact, ensure_ascii=False)
                      if reused_impact else 'Use your usual impact analysis in the impact field.')
        return ('''
The locations below are pinned candidate anchors, not a verdict. Qualify cross-project target evidence with its
repository key. To read an admitted dependency, use dependency:<repository-key> and its pinned ref.
Check all relevant donor changes, including read-only support.
After an AFFECTED decision, select the edits with 1-based target_indices within
each unit. Select only candidate edit locations. List location_gaps only for
missing required edit locations. For a missing project, return repository_requests
with pinned evidence, and keep impact UNKNOWN if that dependency is required for
the causal conclusion. For each guarded obligation select target indices and
disposition edit or already_covered. Use empty edits and repair_obligations for
UNKNOWN, NOT_AFFECTED or ALREADY_FIXED. Do not edit in this analysis turn.
If needed, select exact new_files already in the proposed scope. For a deleted aconfig
declaration that is absent from the target, use flag_cleanup_support to link it to
the selected production hunk(s) that remove the flag check. The controller checks
the donor delta and target flag references. Return an empty array for either field
when it does not apply.
''' + '\n' + assessment + '\nGrounded locations: ' + json.dumps(self.location, ensure_ascii=False)
                + '\nGuarded obligations: ' + json.dumps(self.controller.guarded_obligations, ensure_ascii=False))

    def accept(self, child, impact, response, *, impact_only):
        from .exclusion_review import ExclusionReviewError, ExclusionReviewUnresolved, review_exclusions
        from .mapped_impact import ground_repair_contract

        controller = self.controller
        decision = impact['status']
        if decision == 'AFFECTED':
            self.confirm(child, decision)
        try:
            requests = check_scope(controller, {'repository_requests': response['repository_requests']}).get('requests', [])
        except (AssessmentError, KeyError) as exc:
            return self.unresolved(child, 'BACKEND_SCOPE_REQUEST_REJECTED', str(exc))
        if requests:
            controller.record.update(scope_requests=requests, replan_required='EXPANSION_REQUIRED')
            return self.unresolved(child, 'EXPANSION_REQUIRED')
        if decision == 'UNKNOWN':
            return self.unresolved(child, 'BACKEND_IMPACT_UNRESOLVED')
        if decision in ('NOT_AFFECTED', 'ALREADY_FIXED'):
            proposals = {**self.location, 'units': [
                {**unit, 'status': decision, 'reasoning': impact['reasoning'],
                 'invariant': impact['scope_contract']['donor_security_invariant']}
                for unit in self.location['units']]}
            try:
                review_exclusions(controller, proposals, controller.record['repositories'], 1)
            except ExclusionReviewUnresolved as exc:
                return self.unresolved(child, 'BACKEND_EXCLUSION_UNRESOLVED', str(exc))
            except ExclusionReviewError as exc:
                controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
                return self.unresolved(child, 'BACKEND_EXCLUSION_CHALLENGED', str(exc))
            self.confirm(child, decision)
            child.record['status'] = decision
            return False
        if impact_only:
            child.record['status'] = 'AFFECTED'
            return False
        try:
            assessment, ids = select_edits(self.location, response)
            if not ids:
                raise AssessmentError(' / '.join(response['location_gaps']) or
                                      'confirmed impact requires at least one grounded edit location')
            obligations = {row['id']: row for row in controller.guarded_obligations}
            repair = ground_repair_contract(controller, {row['id']: row for row in assessment['units']},
                                            obligations, response['repair_obligations'], '/repair_obligations')
            self.flag_support = ground_flag_support(controller, response.get('flag_cleanup_support', []), ids)
        except AssessmentError as exc:
            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
            return self.unresolved(child, 'MIGRATION_SCOPE_UNRESOLVED', str(exc))
        if repair:
            controller.record['causal_evidence'] = {'status': 'BACKEND_CONFIRMED',
                                                    'groups': [{'repair_obligations': repair}]}
        if self.flag_support:
            controller.record['no_target_edit_support'] = list(self.flag_support.values())
            child.record['no_target_edit_support'] = list(self.flag_support.values())
        self.location_gaps = response['location_gaps']
        if self.location_gaps:
            controller.record.update(replan_required='LOCATION_SCOPE_UNRESOLVED',
                                     completion_blocked_by='MIGRATION_SCOPE_UNRESOLVED',
                                     migration_scope_error=' / '.join(self.location_gaps))
            child.record['location_gaps'] = self.location_gaps
        controller.record['stage'] = 'MIGRATION'
        child.mechanical_hunk_ids = ids
        controller._save()
        return assessment

    def activate(self, assessment, *, verify):
        self.controller._activate_location_migration(assessment, self.primary,
                                                     build_requested=verify and not self.location_gaps)
        self.migration = assessment

    def confirm(self, child, decision):
        controller = self.controller
        path = child.run_dir / 'impact.json'
        controller._protect(path)
        controller.record.update(impact_decision=decision, impact_analysis={
            'status': 'CONFIRMED', 'decision': decision, 'origin': 'backend',
            'assessment_file': path.relative_to(controller.run_dir).as_posix(),
            'assessment_sha256': controller.protected[path],
            'targets': {repo.key: repo.head for repo in controller.repos}})
        controller._save()

    def unresolved(self, child, reason, detail=None):
        controller = self.controller
        child.record.update(status='INCONCLUSIVE', completion_blocked_by=reason)
        controller.record['completion_blocked_by'] = reason
        if controller.record['impact_analysis']['status'] != 'CONFIRMED':
            child.record['impact_decision'] = 'unknown'
            controller.record['impact_analysis'] = {'status': 'EVIDENCE_INSUFFICIENT', 'reason': reason}
        if detail:
            controller.record['migration_scope_error'] = detail
        controller._save()
        return False


def run_location_handoff(controller, inventory, candidates, *, verify, impact_only, mechanical, max_attempts):
    from contextlib import nullcontext
    from .mapped_backend import run_backends
    from .retrieval import ACTIVE_BUDGET

    budget = ACTIVE_BUDGET.get()
    controller.record['frontend_workflow'] = {'mode': 'location_handoff'}
    with budget.phase('LOCATION') if budget else nullcontext():
        location = locate(controller, inventory, candidates, max_attempts)
    if location and location['scope_requests']:
        controller.record.update(status='INCONCLUSIVE', replan_required='EXPANSION_REQUIRED',
                                 scope_requests=location['scope_requests'])
        controller._save()
        return controller.record
    if not location or not location['primary_repository']:
        controller.record.update(status='INCONCLUSIVE', completion_blocked_by='LOCATION_UNRESOLVED')
        controller._save()
        return controller.record
    if len(location['write_projects']) > 1:
        controller.record['frontend_workflow'] = {'mode': 'legacy', 'reason': 'MULTIPLE_WRITE_PROJECTS'}
        return None
    handoff = BackendHandoff(controller, location)
    controller.record.update(stage='IMPACT_ANALYSIS', impact_analysis={'status': 'RUNNING'}, model_execution='succeeded')
    controller._save()
    with budget.phase('IMPACT_ANALYSIS') if budget else nullcontext():
        controller._prepare_children(location, location_only=True)
        result = run_backends(controller, location, verify=verify, impact_only=impact_only,
                              mechanical=mechanical, max_attempts=max_attempts, handoff=handoff)
    if result['impact_analysis']['status'] == 'RUNNING':
        error = result.get('repository_errors', {}).get(handoff.primary, {})
        result['impact_analysis'] = {
            'status': 'EVIDENCE_INSUFFICIENT' if error.get('type') == 'AssessmentError' else 'INTERRUPTED',
            'reason': error.get('kind') or error.get('type') or 'BACKEND_ANALYSIS_INCOMPLETE'}
        controller._save()
    return result
