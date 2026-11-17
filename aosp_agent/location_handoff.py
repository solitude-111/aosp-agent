"""Read-only location handoff for the verified-donor backport backend."""
from copy import deepcopy
import json

from .diff_prompts import ASSESSMENT_SCHEMA, EVIDENCE, LINE, STRING, TARGET, array, compact_location, enum, obj
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


def backend_report_schema(guarded_obligations, *, reused_impact=False):
    """Bind model-authored obligations to the controller's list for this run."""
    schema = deepcopy(EDIT_SCHEMA if reused_impact else BACKEND_SCHEMA)
    allowed = list(dict.fromkeys(row['id'] for row in guarded_obligations))
    obligations = schema['properties']['repair_obligations']
    obligations['maxItems'] = len(allowed)
    if allowed:
        obligations['items']['properties']['id'] = enum(*allowed)
    return schema


class BackendEditSelectionError(AssessmentError):
    """An invalid selection table does not itself invalidate grounded locations."""
    kind = 'BACKEND_EDIT_SELECTION_INVALID'

    def __init__(self, message, path):
        super().__init__(message)
        self.diagnostic = {'category': self.kind, 'path': path, 'message': message}


class BackendLocationGap(AssessmentError):
    def __init__(self, unit_id, targets):
        super().__init__('backend edit exceeds grounded location scope: ' + unit_id)
        self.gaps = [{'unit_id': unit_id, **{field: target[field] for field in
                     ('path', 'line_start', 'line_end', 'symbol')},
                     'error': 'The edit plan needs a location currently grounded for reading only.'}
                     for target in targets]


def backend_scope_feedback(record, location, handoff, targets):
    """Admit only a selection-only retry bound to the same checked location/pins."""
    from .assessment_repair import digest
    retry = record.get('backend_scope_retry')
    if (not isinstance(retry, dict) or retry.get('kind') != BackendEditSelectionError.kind
            or not location or handoff.get('status') != 'READY'
            or handoff.get('scope') == 'READ_ONLY_WITH_GAPS'
            or set(handoff.get('unmapped_units', [])) - set(retry.get('verified_no_edit_units', []))
            or handoff.get('targets') != targets or retry.get('targets') != targets
            or retry.get('location_digest') != digest(location)
            or record.get('location_gaps') or record.get('scope_requests')
            or record.get('backend_conflicts') or retry.get('report', {}).get('location_gaps')
            or retry.get('report', {}).get('repository_requests')):
        return None
    return {'diagnostic': retry['diagnostic'], 'previous_scope_report': retry['report']}


def affected_fault_units(impact, units):
    """Bind changed donor fault sites in the checked proof to migration coverage."""
    from .impact_proof import CausalityChecks

    evidence = impact['evidence']
    causal = impact.get('causal_chain') or {}
    anchor = [evidence[i - 1] for i in causal.get('donor_fault_evidence', [])]
    required = set()
    for unit in units:
        changed = CausalityChecks._changed_hunk_lines(unit, 'source_parent')
        if any(CausalityChecks._evidence_matches_hunk(entry, unit)
               and any(entry['line_start'] <= line <= entry['line_end'] for line in changed)
               for entry in anchor):
            required.add(unit['id'])
    return required


def focused_impact_challenge(record, location, targets):
    """Reuse a location only when the challenged units still have grounded anchors."""
    challenge = record.get('impact_challenge')
    handoff = record.get('location_handoff', {})
    if (not challenge or record.get('completion_blocked_by') != 'BACKEND_EXCLUSION_CHALLENGED'
            or record.get('replan_required') != 'IMPACT_RECHECK_REQUIRED'
            or not location or handoff.get('status') != 'READY'
            or handoff.get('scope') == 'READ_ONLY_WITH_GAPS' or handoff.get('targets') != targets
            or record.get('location_gaps') or record.get('scope_requests')):
        return None
    mapped = {unit['id'] for unit in location['units'] if unit['targets']}
    return challenge if all(item['id'] in mapped for item in challenge) else None


def _compact_impact_challenge(details):
    result = []
    for item in details:
        indices = list(dict.fromkeys(item['blocking_evidence'] + item['state_flow_evidence']))
        citations = [{k: entry[k] for k in ('origin', 'path', 'line_start', 'line_end')}
                     for entry in (item['evidence'][i - 1] for i in indices[:8])]
        result.append({'id': item['id'], 'operation': item['security_operation'][:600],
                       'dispute': item['blocking_analysis'][:1800], 'locations': citations,
                       'unresolved_assumptions': [a[:400] for a in item['unresolved_assumptions'][:6]]})
    return result


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


def _retain_confirmed_edits(controller, raw):
    """Keep prior candidate locations when a replan loses every edit of a proven fault."""
    seed = controller.backend_impact_seed or {}
    impact = seed.get('assessment') or {}
    targets = {repo.key: repo.head for repo in controller.repos}
    prior = controller.location_seed
    if (not prior or impact.get('status') != 'AFFECTED' or seed.get('targets') != targets
            or raw['repository_requests'] or raw['primary_repository'] != prior['primary_repository']):
        return raw, []
    required = affected_fault_units(impact, controller.units)
    old_units = {unit['id']: unit for unit in prior['units']}
    units, retained = [], []

    def key(target):
        return tuple(target[field] for field in ('path', 'line_start', 'line_end', 'symbol'))

    for unit in raw['units']:
        previous = old_units.get(unit['id'])
        if (unit['id'] not in required or previous is None
                or any(target['action'] == 'edit' for target in unit['targets'])):
            units.append(unit)
            continue
        edits = [target for target in previous['targets'] if target['action'] == 'edit']
        if not edits:
            units.append(unit)
            continue
        old_keys = {key(target) for target in edits}
        evidence = list(unit['evidence'])
        for citation in previous['evidence']:
            if (citation['origin'] == 'target' and citation not in evidence
                    and any(citation['path'] == target['path']
                            and target['line_start'] <= citation['line_start'] <= citation['line_end'] <= target['line_end']
                            for target in edits)):
                evidence.append(citation)
        units.append({**unit, 'evidence': evidence,
                      'targets': edits + [target for target in unit['targets'] if key(target) not in old_keys]})
        retained.append(unit['id'])
    return {**raw, 'units': units}, retained


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
                revised, retained = _retain_confirmed_edits(controller, raw)
                if retained:
                    grounded = ground_locations(controller, revised)
                    controller.record['retained_location_units'] = retained
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
        read_targets = [targets[i - 1] for i in indices if targets[i - 1]['action'] != 'edit']
        if read_targets:
            raise BackendLocationGap(ident, read_targets)
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
        seed = seed if seed and seed['targets'] == targets else {}
        self.accepted_impact = seed.get('assessment')
        self.impact_challenge = seed.get('challenge')
        self.scope_feedback = seed.get('scope_feedback') if self.accepted_impact is not None else None
        self.coverage_feedback = (seed.get('coverage_feedback', [])[:8]
                                  if self.accepted_impact is not None else [])
        if self.impact_challenge:
            controller.record['impact_recheck'] = {'units': [item['id'] for item in self.impact_challenge]}

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
                      + '\nUnits containing the checked donor fault must retain a selected edit: '
                      + json.dumps(sorted(affected_fault_units(self.accepted_impact, self.controller.units)))
                      if reused_impact else 'Use your usual impact analysis in the impact field.')
        scope_feedback = ('\nCorrect the rejected backend plan below within the unchanged grounded locations. '
                          'A read-only unit needs no edits entry. Return the requested scope schema; '
                          'do not invent an edit or change the accepted impact. Preserve edits and '
                          'flag_cleanup_support unless the diagnostic points to those fields. '
                          'When correcting repair_obligations, reuse the grounded locations.\n'
                          + json.dumps(self.scope_feedback, ensure_ascii=False) if self.scope_feedback else '')
        challenge = ('\nAn independent review challenged the previous exclusion. Recheck the disputed '
                     'behavior on the pinned target using the locations below. Trace the specific state write, '
                     'lifetime, consumer and effect in dispute. Do not infer absence from a changed API. '
                     'Use UNKNOWN and name any material premise still unresolved. Report a location gap only '
                     'if a required edit has no grounded location. The review is evidence to investigate, not a verdict.\n'
                     + json.dumps(self.impact_challenge, ensure_ascii=False) if self.impact_challenge else '')
        return ('''
The locations below are pinned candidate anchors, not a verdict. Qualify cross-project target evidence with its
repository key. To read an admitted dependency, use target:<repository-key> and its pinned ref.
Search and symbol lookup without a path use the grounded files in the requested project.
If more evidence is needed, name a specific file or directory in the path argument. A limited
search result or a timed-out read cannot establish absence.
Check all relevant donor changes, including read-only support.
After an AFFECTED decision, select the edits with 1-based target_indices within
each unit. Use donor unit IDs in edits, and select only candidate edit locations.
Check that the selected regions can change the confirmed fault. For a shared-state
fault, check where the target stores and consumes that state before selecting edits.
If the needed change is in a read-only location, identify the unit, path and range
in location_gaps so the location checker can reconsider it.
List location_gaps only for missing required edit locations. For a missing project, return repository_requests
with pinned evidence, and keep impact UNKNOWN if that dependency is required for
the causal conclusion. The repair_obligations IDs come only from the Guarded obligations list
below. If that list is empty, return repair_obligations: []. For an AFFECTED edit plan, include
each listed ID exactly once with target indices and disposition edit or already_covered.
Use empty edits and repair_obligations for UNKNOWN, NOT_AFFECTED or ALREADY_FIXED.
Do not edit in this analysis turn.
If needed, select exact new_files already in the proposed scope. For a deleted aconfig
declaration that is absent from the target, use flag_cleanup_support to link it to
the selected production hunk(s) that remove the flag check. The controller checks
the donor delta and target flag references. Return an empty array for either field
when it does not apply.
Select a member_insertion only if a new target member is required. Its insertion_lines
name the permitted boundary; the wider quoted range is context.
''' + '\n' + assessment + scope_feedback + challenge + self.coverage_feedback_prompt()
                + '\nGrounded locations: ' + json.dumps(self.location, ensure_ascii=False)
                + '\nUnverified location gaps: ' + json.dumps(self.controller.record.get('location_gaps', []), ensure_ascii=False)
                + '\nGuarded obligations: ' + json.dumps(self.controller.guarded_obligations, ensure_ascii=False))

    def coverage_feedback_prompt(self):
        if not self.coverage_feedback:
            return ''
        return ('\nThe previous candidate did not establish the behaviors below. Recheck the cited '
                'state writes, consumers and ordering using pinned source. Use these diagnostics '
                'to correct the edit plan or report a grounded location gap.\n'
                + json.dumps(self.coverage_feedback, ensure_ascii=False))

    def accept(self, child, impact, response, *, impact_only):
        from .exclusion_review import (ExclusionCounterpartChallenge, ExclusionReviewError,
                                       ExclusionReviewUnresolved, review_exclusions)
        from .mapped_impact import RepairContractError, ground_repair_contract

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
            except ExclusionCounterpartChallenge as exc:
                if len(exc.details) <= 8:
                    controller.record['impact_challenge'] = _compact_impact_challenge(exc.details)
                    if not self.impact_challenge:
                        controller.record['replan_required'] = 'IMPACT_RECHECK_REQUIRED'
                        # A genuine missing anchor still needs location work.
                        if focused_impact_challenge(
                                {**controller.record, 'completion_blocked_by': 'BACKEND_EXCLUSION_CHALLENGED'},
                                self.location, {repo.key: repo.head for repo in controller.repos}) is None:
                            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
                else:
                    controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
                return self.unresolved(child, 'BACKEND_EXCLUSION_CHALLENGED', str(exc))
            except ExclusionReviewError as exc:
                controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
                return self.unresolved(child, 'BACKEND_EXCLUSION_CHALLENGED', str(exc))
            self.confirm(child, decision)
            child.record['status'] = decision
            return False
        if impact_only:
            child.record['status'] = 'AFFECTED'
            return False
        required = affected_fault_units(impact, controller.units)
        verified_no_edit = {}
        try:
            assessment, ids = select_edits(self.location, response)
            missing = required - ids
            if missing:
                with_edit_anchor = {unit['id'] for unit in self.location['units']
                                    if any(target['action'] == 'edit' for target in unit['targets'])}
                no_edit_anchor = missing - with_edit_anchor
                if no_edit_anchor:
                    gaps = [{'unit_id': unit_id,
                             'error': 'the confirmed donor fault has no writable target location'}
                            for unit_id in sorted(no_edit_anchor)]
                    existing = controller.record.setdefault('location_gaps', [])
                    messages = [entry['error'] for entry in existing]
                    existing.extend(gaps)
                    messages.append('missing edit locations for confirmed donor fault: '
                                    + ', '.join(sorted(no_edit_anchor)))
                    raise AssessmentError(' / '.join(messages))
            if not ids:
                gaps = [entry['error'] for entry in controller.record.get('location_gaps', [])]
                raise AssessmentError(' / '.join(response['location_gaps'] or gaps) or
                                      'confirmed impact requires at least one grounded edit location')
            obligations = {row['id']: row for row in controller.guarded_obligations}
            # A verified no-edit support unit is not a missing target location.
            verified_no_edit = ground_flag_support(controller, response.get('flag_cleanup_support', []), ids)
            if missing:
                raise BackendEditSelectionError('edits must retain every confirmed donor fault unit: '
                                                + ', '.join(sorted(missing)), '/edits')
            repair = ground_repair_contract(controller, {row['id']: row for row in assessment['units']},
                                            obligations, response['repair_obligations'], '/repair_obligations')
        except (BackendEditSelectionError, RepairContractError) as exc:
            from .assessment_repair import digest
            diagnostic = (exc.diagnostic if isinstance(exc, BackendEditSelectionError) else {
                'category': 'BACKEND_REPAIR_CONTRACT_INVALID', 'path': '/repair_obligations',
                'message': str(exc), 'expected_ids': list(obligations),
                'submitted_ids': [row['id'] for row in response['repair_obligations']],
            })
            controller.record['migration_scope_diagnostic'] = diagnostic
            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
            location = controller.record.get('location_handoff', {})
            if (location.get('status') == 'READY'
                    and not set(location.get('unmapped_units', [])) - verified_no_edit.keys()
                    and location.get('scope') != 'READ_ONLY_WITH_GAPS'
                    and not controller.record.get('location_gaps') and not response['location_gaps']):
                controller.record['backend_scope_retry'] = {
                    'kind': BackendEditSelectionError.kind, 'diagnostic': diagnostic,
                    'verified_no_edit_units': sorted(verified_no_edit),
                    'targets': location['targets'], 'location_digest': digest(controller.grounded_location),
                    'report': {key: deepcopy(response[key]) for key in EDIT_FIELDS}}
                controller.record['replan_required'] = 'BACKEND_SCOPE_CORRECTION_REQUIRED'
            return self.unresolved(child, 'MIGRATION_SCOPE_UNRESOLVED', str(exc))
        except BackendLocationGap as exc:
            controller.record.setdefault('location_gaps', []).extend(exc.gaps)
            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
            return self.unresolved(child, 'MIGRATION_SCOPE_UNRESOLVED', str(exc))
        except AssessmentError as exc:
            controller.record['replan_required'] = 'LOCATION_SCOPE_UNRESOLVED'
            return self.unresolved(child, 'MIGRATION_SCOPE_UNRESOLVED', str(exc))
        self.flag_support = verified_no_edit
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
        child.record['required_affected_units'] = sorted(required)
        controller.record['required_affected_units'] = sorted(required)
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
