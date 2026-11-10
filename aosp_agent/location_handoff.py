"""Read-only location handoff for the verified-donor backport backend."""
from copy import deepcopy
import json

from .diff_prompts import ASSESSMENT_SCHEMA, EVIDENCE, LINE, STRING, TARGET, array, compact_location, obj
from .discovery import RepositoryReadConstraintError
from .engine import AssessmentError
from .location_regions import donor_adds_callable, import_changes, normalize_java_target
from .mapping_plan import MappingEvidenceError, _shape
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


class BackendEditSelectionError(AssessmentError):
    """An invalid selection table does not itself invalidate grounded locations."""
    kind = 'BACKEND_EDIT_SELECTION_INVALID'

    def __init__(self, message, path):
        super().__init__(message)
        self.diagnostic = {'category': self.kind, 'path': path, 'message': message}


def backend_scope_feedback(record, location, handoff, targets):
    """Admit only a selection-only retry bound to the same checked location/pins."""
    from .assessment_repair import digest
    retry = record.get('backend_scope_retry')
    if (not isinstance(retry, dict) or retry.get('kind') != BackendEditSelectionError.kind
            or not location or handoff.get('status') != 'READY'
            or handoff.get('scope') == 'READ_ONLY_WITH_GAPS' or handoff.get('unmapped_units')
            or handoff.get('targets') != targets or retry.get('targets') != targets
            or retry.get('location_digest') != digest(location)
            or record.get('location_gaps') or record.get('scope_requests')
            or record.get('backend_conflicts') or retry.get('report', {}).get('location_gaps')
            or retry.get('report', {}).get('repository_requests')):
        return None
    return {'diagnostic': retry['diagnostic'], 'previous_scope_report': retry['report']}


def ground_locations(controller, raw, *, unassociated=None):
    _shape(raw, LOCATION_SCHEMA)
    source = {unit['id']: unit for unit in controller.units}
    if len(raw['units']) != len(source) or {unit['id'] for unit in raw['units']} != set(source):
        raise AssessmentError('location response must account for every donor unit exactly once')
    units, excluded = [], set()
    for unit_index, unit in enumerate(raw['units']):
        mapped_paths = {target['path'] for target in unit['targets']}
        evidence = []
        for index, citation in enumerate(unit['evidence']):
            if citation['origin'] == 'target' and citation['path'] not in mapped_paths:
                excluded.add((unit_index, index))
                if unassociated is not None:
                    unassociated.append({
                        'unit_id': unit['id'], 'evidence_index': index,
                        'reason': 'TARGET_PATH_NOT_MAPPED',
                        **{key: citation[key] for key in ('path', 'line_start', 'line_end')},
                    })
                continue
            evidence.append(citation)
        units.append({**unit, 'targets': [dict(target) for target in unit['targets']], 'evidence': evidence})
    # Keep citation indices in validation feedback tied to the model response.
    validation = {**raw, 'units': [{**unit, 'evidence': original['evidence']}
                                   for unit, original in zip(units, raw['units'])]}
    import_units, donor_members, donor_sources = {}, {}, {}

    def normalize_target(unit, target, lines, java_sources):
        read_context = target['action'] == 'read_dependency' and target['relationship'] in (
            'dependency', 'test', 'data_or_configuration')
        if target['path'].endswith('.java') and not read_context:
            ident = unit['id']
            if ident not in import_units:
                donor = source[ident]
                import_units[ident] = donor['supported'] and import_changes(donor['patch']) is not None
            def adds_callable():
                if ident not in donor_members:
                    donor_members[ident] = donor_adds_callable(controller, source[ident], donor_sources)
                return donor_members[ident]
            normalize_java_target(unit, target, lines, java_sources, import_units[ident], adds_callable)

    controller.mapper._check_all_evidence(validation, source, excluded_unit_evidence=excluded,
                                          normalize_target=normalize_target)
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


def _read_only_locations(controller, raw, errors):
    """Recover checked anchors after a local mapping failure, with no edit scope."""
    rejected_targets, rejected_evidence = set(), set()
    for entry in errors:
        parts = entry['path'].split('/')
        if len(parts) != 5 or parts[1] != 'units':
            return None
        unit_index, index = int(parts[2]), int(parts[4])
        if parts[3] == 'targets':
            rejected_targets.add((unit_index, index))
        elif parts[3] == 'evidence':
            rejected_evidence.add((unit_index, index))
        else:
            return None
    units, owners = [], set()
    for i, unit in enumerate(raw['units']):
        evidence = [e for j, e in enumerate(unit['evidence']) if (i, j) not in rejected_evidence]
        targets = [{**t, 'action': 'read_dependency'} for j, t in enumerate(unit['targets'])
                   if (i, j) not in rejected_targets and any(
                       e['origin'] == 'target' and e['path'] == t['path']
                       and t['line_start'] <= e['line_start'] <= e['line_end'] <= t['line_end']
                       for e in evidence)]
        owners.update(controller._owner(t['path'])[0].key for t in targets)
        notes = [e['error'] for e in errors if e['path'].startswith(f'/units/{i}/')]
        units.append({**unit, 'targets': targets, 'evidence': evidence,
                      'location_notes': ' '.join([unit['location_notes'], *notes])})
    if not owners:
        return None
    primary = raw['primary_repository']
    return ground_locations(controller, {**raw, 'units': units, 'new_files': [],
                                         'primary_repository': primary if primary in owners else min(owners)})


def locate(controller, inventory, location, max_attempts):
    from .assessment_repair import REPAIR_SCHEMA, apply_repair, repair_prompt
    from .diff_engine import _write
    from .retrieval import ACTIVE_BUDGET
    from .sdk_runtime import CodexRuntimeError

    prompt = ('''Locate target code on the pinned commits. Work read-only.
Return every donor unit ID once. Map its counterpart, callers and dependencies to exact
repository-prefixed paths and line ranges with short pinned target excerpts inside each range.
Use names observed in the target. When the donor API is missing, look for the older operation,
its entrypoint or caller. Do not invent a matching declaration. Mark possible edits as edit
and other evidence as read_dependency. For a needed new helper, quote the boundary between
adjacent members of the actual target class and separately map affected callers. This is a
candidate scope for a later backend, not a required edit. For imports, fields, tests and
configuration map the actual region. Cite target files only when they are mapped in the same
unit. For a required dependency, map its region as read_dependency and cite the pinned lines.
Report unmapped units with empty targets and a specific
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
            save_location(controller, grounded)
            controller.record['location_reused'] = True
            return grounded
        prompt += '\nPrevious grounded locations to preserve: ' + json.dumps(
            controller.location_seed, ensure_ascii=False)
    budget = ACTIVE_BUDGET.get()
    controller.record.update(stage='LOCATION', location_handoff={'status': 'RUNNING'})
    controller._save()
    raw, errors = None, []
    with controller._runtime('location-handoff', timeout=budget.remaining() / 2 if budget else None) as runtime:
        runtime.start(controller.run_dir, 'Resolve source locations. Read pinned objects only.')
        from .execution_budget import ACTIVE_EXECUTION
        execution = ACTIVE_EXECUTION.get()
        limit = execution.phase_limit('location_attempts', max_attempts) if execution else min(max_attempts, 2)
        for attempt in range(1, limit + 1):
            unassociated = []
            try:
                if raw is None:
                    raw = controller._turn(runtime, prompt, LOCATION_SCHEMA, read_only=True)
                else:
                    if execution is not None:
                        execution.charge('report_corrections', phase='LOCATION')
                    correction = controller._turn(runtime, prompt, REPAIR_SCHEMA, read_only=True)
                    _write(controller.run_dir / f'location-repair-{attempt}.json', correction)
                    raw = apply_repair(raw, correction, schema=LOCATION_SCHEMA)
                errors = []
                _write(controller.run_dir / f'location-attempt-{attempt}.json', raw)
                grounded = ground_locations(controller, raw, unassociated=unassociated)
            except AssessmentError as exc:
                grounded = None
                controller.record.setdefault('location_rejections', []).append(str(exc))
                if isinstance(exc, MappingEvidenceError):
                    errors = exc.errors
                if raw is not None:
                    prompt = repair_prompt(raw, str(exc))
                if execution is not None and execution.repeated_error('LOCATION', type(exc).__name__,
                        errors or [str(exc)]):
                    controller.record['completion_blocked_by'] = 'REPEATED_ERROR_NO_PROGRESS'
                    controller._save()
                    break
            except CodexRuntimeError as exc:
                if raw is None or exc.kind != 'INVALID_OUTPUT':
                    raise
                controller.record.setdefault('location_rejections', []).append(str(exc)[:1000])
                break
            if unassociated:
                controller.record.setdefault('location_unassociated_evidence', []).extend(
                    {**entry, 'attempt': attempt} for entry in unassociated)
            if grounded is not None:
                save_location(controller, grounded)
                return grounded
            controller._save()
    if errors:
        try:
            partial = _read_only_locations(controller, raw, errors)
        except AssessmentError:
            partial = None
        if partial is not None:
            controller.record['location_gaps'] = errors
            save_location(controller, partial)
            return partial
    controller.record['location_handoff'] = {'status': 'UNRESOLVED', 'reason': 'LOCATION_EVIDENCE_REJECTED'}
    return None


def save_location(controller, grounded):
    from .diff_engine import _write
    raw = {key: grounded[key] for key in LOCATION_SCHEMA['properties']}
    raw['units'] = [{**{key: value for key, value in unit.items() if key != 'status'},
                     'targets': [{key: target[key] for key in TARGET['properties']} for target in unit['targets']]}
                    for unit in raw['units']]
    path = controller.run_dir / 'grounded-location.json'
    _write(path, raw)
    controller._protect(path)
    controller.record['location_handoff'] = {
        'status': 'READY' if raw['primary_repository'] else 'UNRESOLVED',
        'file': path.name, 'sha256': controller.protected[path],
        **({'scope': 'READ_ONLY_WITH_GAPS'} if controller.record.get('location_gaps') else {}),
        'primary_repository': raw['primary_repository'],
        'targets': {repo.key: repo.head for repo in controller.repos},
        'unmapped_units': [row['id'] for row in raw['units'] if not row['targets']]}
    controller.grounded_location = raw
    from .execution_budget import ACTIVE_EXECUTION
    execution = ACTIVE_EXECUTION.get()
    if execution is not None:
        # These citations have passed _check_all_evidence against fixed blobs;
        # neither model notes nor changed report wording grant extra time.
        execution.record_progress('LOCATION', [
            {'targets': controller.record['location_handoff']['targets'],
             'unit': unit['id'], 'citation': {key: citation[key] for key in
                 ('origin', 'path', 'line_start', 'line_end', 'excerpt') if key in citation}}
            for unit in grounded['units'] for citation in unit['evidence']])


def select_edits(location, response):
    """Restrict the location ceiling to the backend's selected grounded regions."""
    assessment = deepcopy(location)
    units = {row['id']: row for row in assessment['units']}
    selected = {}
    for row_index, row in enumerate(response['edits']):
        ident, indices = row['unit_id'], row['target_indices']
        pointer = f'/edits/{row_index}'
        if ident in selected or ident not in units:
            raise BackendEditSelectionError('edits require unique grounded unit IDs', pointer + '/unit_id')
        if not indices:
            raise BackendEditSelectionError('edits require nonempty target indices', pointer + '/target_indices')
        targets = units[ident]['targets']
        for index, value in enumerate(indices):
            if type(value) is not int or value < 1 or value > len(targets):
                raise BackendEditSelectionError('backend edit index is outside grounded targets: ' + ident,
                                                pointer + f'/target_indices/{index}')
        if len(indices) != len(set(indices)):
            raise BackendEditSelectionError('edits require unique target indices', pointer + '/target_indices')
        if any(targets[i - 1]['action'] != 'edit' for i in indices):
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
        self.scope_feedback = seed.get('scope_feedback') if self.accepted_impact is not None else None

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
        scope_feedback = ('\nCorrect the rejected backend edit selection below within the unchanged '
                          'grounded locations. A read-only unit needs no edits entry. Return the '
                          'requested scope schema; do not invent an edit or change the accepted impact.\n'
                          + json.dumps(self.scope_feedback, ensure_ascii=False) if self.scope_feedback else '')
        return ('''
The locations below are pinned candidate anchors, not a verdict. Qualify cross-project target evidence with its
repository key. To read an admitted dependency, use target:<repository-key> and its pinned ref.
Search and symbol lookup without a path use the grounded files in the requested project.
If more evidence is needed, name a specific file or directory in the path argument. A limited
search result or a timed-out read cannot establish absence.
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
Select a member_insertion only if a new target member is required. Its insertion_lines
name the permitted boundary; the wider quoted range is context.
''' + '\n' + assessment + scope_feedback + '\nGrounded locations: ' + json.dumps(self.location, ensure_ascii=False)
                + '\nUnverified location gaps: ' + json.dumps(self.controller.record.get('location_gaps', []), ensure_ascii=False)
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
                gaps = [entry['error'] for entry in controller.record.get('location_gaps', [])]
                raise AssessmentError(' / '.join(response['location_gaps'] or gaps) or
                                      'confirmed impact requires at least one grounded edit location')
            obligations = {row['id']: row for row in controller.guarded_obligations}
            repair = ground_repair_contract(controller, {row['id']: row for row in assessment['units']},
                                            obligations, response['repair_obligations'], '/repair_obligations')
            self.flag_support = ground_flag_support(controller, response.get('flag_cleanup_support', []), ids)
        except BackendEditSelectionError as exc:
            from .assessment_repair import digest
            controller.record['migration_scope_diagnostic'] = exc.diagnostic
            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
            location = controller.record.get('location_handoff', {})
            if (location.get('status') == 'READY' and not location.get('unmapped_units')
                    and location.get('scope') != 'READ_ONLY_WITH_GAPS'
                    and not controller.record.get('location_gaps') and not response['location_gaps']):
                controller.record['backend_scope_retry'] = {
                    'kind': exc.kind, 'diagnostic': exc.diagnostic,
                    'targets': location['targets'], 'location_digest': digest(controller.grounded_location),
                    'report': {key: deepcopy(response[key]) for key in EDIT_FIELDS}}
                controller.record['replan_required'] = 'BACKEND_SCOPE_CORRECTION_REQUIRED'
            return self.unresolved(child, 'MIGRATION_SCOPE_UNRESOLVED', str(exc))
        except AssessmentError as exc:
            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
            return self.unresolved(child, 'MIGRATION_SCOPE_UNRESOLVED', str(exc))
        if repair:
            controller.record['causal_evidence'] = {'status': 'BACKEND_CONFIRMED',
                                                    'groups': [{'repair_obligations': repair}]}
        if self.flag_support:
            controller.record['no_target_edit_support'] = list(self.flag_support.values())
            child.record['no_target_edit_support'] = list(self.flag_support.values())
        for unit in assessment['units']:
            unit['invariant'] = impact['scope_contract']['donor_security_invariant']
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
        from .execution_budget import ACTIVE_EXECUTION
        execution = ACTIVE_EXECUTION.get()
        if execution is not None:
            execution.record_progress('IMPACT', [{'verified_decision': decision,
                'targets': controller.record['impact_analysis']['targets']}])

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
    search_paths = {repo.key: set() for repo in controller.repos}
    for unit in location['units']:
        for target in unit['targets']:
            repo, relative = controller._owner(target['path'])
            search_paths[repo.key].add(relative)
    controller.record.update(stage='IMPACT_ANALYSIS', impact_analysis={'status': 'RUNNING'},
                             model_execution='succeeded',
                             source_search_paths={key: sorted(paths) for key, paths in search_paths.items()})
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
