"""Candidate-side proof for Java mappings whose donor spelling does not survive."""
from collections import Counter
import hashlib
import json
import re

from .activation_flow import branches, literal_truth, ts_key, txt, walk
from .diff_prompts import LINE, STRING, array, enum, obj
from .engine import AssessmentError
from .git_policy import OFFLINE_GIT_ENV
from .hunk_scope import change_blocks
from .java_regions import JavaSource, TYPES, TYPE_DECLARATIONS, mapped_name, method_name, owner as _owner
from .mapping_plan import _shape
from .patches import split_hunks


REVIEW_SCHEMA = obj({'regions': array(obj({
    'id': STRING, 'verdict': enum('COVERED', 'UNRESOLVED'), 'reason': STRING,
    'candidate_lines': array(LINE),
}))})
REVIEW_SCHEMA['properties']['regions']['items']['properties']['state_evidence'] = array(LINE)
MAX_CONTEXT = 48 * 1024
STATEMENTS = {'if_statement', 'return_statement', 'throw_statement',
              'expression_statement', 'local_variable_declaration'}


def _direct_sites(source, method, blocks, region):
    changed = set().union(*(lines for first, last, lines in blocks
                            if region['line_start'] <= first <= last <= region['line_end']))
    return sorted({source.first(node) for node in walk(method)
                   if node.type in STATEMENTS and source.first(node) in changed})


def _calls(source, name):
    return [node for node in walk(source.tree.root_node) if node.type == 'method_invocation'
            and txt(node.child_by_field_name('name')) == name]


def _guard(source, node, target, changed):
    statement = node.parent
    block = statement.parent
    caller = _owner(node, {'method_declaration', 'constructor_declaration'})
    if (statement.type != 'expression_statement' or block.type != 'block' or not caller
            or block != caller.child_by_field_name('body') or _owner(node, TYPES) != _owner(target, TYPES)
            or txt(node.child_by_field_name('object')) not in ('', 'this')):
        return None
    siblings = [child for child in block.named_children if not child.type.endswith('_comment')]
    index = siblings.index(statement)
    if not index or siblings[index - 1].type != 'if_statement':
        return None
    guard = check = siblings[index - 1]
    for _ in range(3):
        condition, consequence, alternative = branches(check)
        if (not condition or literal_truth(txt(condition)) is not None or alternative
                or source.first(check) not in changed):
            return None
        step = (next((child for child in consequence.named_children if not child.type.endswith('_comment')), None)
                if consequence and consequence.type == 'block' else consequence)
        if not step or source.first(step) not in changed:
            return None
        if step.type == 'return_statement':
            return {'guard': source.snippet(guard), 'call': source.snippet(node)}
        if step.type != 'if_statement':
            return None
        check = step
    return None


def _guarded_callers(before, after, baseline_method, candidate_method, blocks):
    name = txt(candidate_method.child_by_field_name('name'))
    calls = _calls(after, name)
    changed = set().union(*(lines for _, _, lines in blocks))
    guarded = [_guard(after, node, candidate_method, changed) for node in calls]
    unguarded = [after.first(node) for node, guard in zip(calls, guarded) if guard is None]
    if unguarded:
        return None, 'candidate calls without a newly added preceding exit guard at lines ' + ', '.join(map(str, unguarded[:8]))
    modifiers = next((node for node in candidate_method.named_children if node.type == 'modifiers'), None)
    baseline_modifiers = next((node for node in baseline_method.named_children if node.type == 'modifiers'), None)
    for source, mods in ((before, baseline_modifiers), (after, modifiers)):
        if not mods or not any(node.type == 'private' for node in mods.children):
            return None, 'caller proof requires a private Java method with a closed local set of direct callers'
        declarations = [n for n in walk(source.tree.root_node) if n.type == 'method_declaration'
                        and txt(n.child_by_field_name('name')) == name]
        if len(declarations) != 1 or any(
                n.type == 'method_reference' and re.search(r'\b' + re.escape(name) + r'\b', txt(n))
                for n in walk(source.tree.root_node)):
            return None, 'caller proof cannot resolve overloads or method references'
    old_calls = _calls(before, name)
    if not calls or len(calls) > 6 or len(calls) != len(old_calls):
        return None, 'caller proof requires a small unchanged set of local call edges'

    def owners(nodes):
        return Counter(ts_key(owner) for node in nodes
                       if (owner := _owner(node, {'method_declaration', 'constructor_declaration'})))
    if owners(calls) != owners(old_calls):
        return None, 'candidate changes the set of caller functions'
    old_callers = {ts_key(owner): owner for node in old_calls
                   if (owner := _owner(node, {'method_declaration', 'constructor_declaration'}))}
    for node, edge in zip(calls, guarded):
        caller = _owner(node, {'method_declaration', 'constructor_declaration'})
        edge['caller_baseline'] = before.snippet(old_callers[ts_key(caller)])
        edge['caller_candidate'] = after.snippet(caller)
    return guarded, None


def _parse_path(agent, path, hunks):
    if not path.endswith('.java') or not hunks:
        return None
    baseline = agent._artifact_baseline_text(path)
    candidate = agent.worktree / path
    if (baseline is None or candidate.is_symlink() or not candidate.is_file()
            or candidate.stat().st_size > 4 * 1024 * 1024):
        return None
    before, after = JavaSource(path, baseline), JavaSource(path, candidate.read_text())
    if before.tree.root_node.has_error or after.tree.root_node.has_error:
        return None
    blocks = [(first, last, {row['new_line'] for row in rows if row['marker'] == '+'})
              for unit in hunks for first, last, rows in change_blocks(unit['patch'])]
    return before, after, blocks


def _method_evidence(before, after, blocks, region):
    start, end = region['line_start'], region['line_end']
    typed = region.get('region_kind') in ('method', 'constructor')
    methods = before.overlapping_callables(start, end) if typed else before.overlapping_methods(start, end)
    named = [m for m in methods if method_name(m) == mapped_name(region['symbol'])]
    if len(methods) == 1 and before.first(methods[0]) <= start <= end <= before.last(methods[0]):
        old = methods[0]
    elif len(named) == 1:
        # Older saved plans can span siblings. Credit only the named
        # declaration's intersection with the pinned mapping.
        old = named[0]
        region = {**region, 'line_start': max(start, before.first(old)),
                  'line_end': min(end, before.last(old))}
    else:
        return None, 'map each Java method separately with its pinned declaration and range'
    identity = ts_key(old)
    matches = [m for m in (after.callables if typed else after.methods) if ts_key(m) == identity]
    if len(matches) != 1:
        return None, 'candidate has no uniquely corresponding Java method'
    new = matches[0]
    detail = {'baseline': before.snippet(old), 'candidate': after.snippet(new),
              'effective_range': [region['line_start'], region['line_end']]}
    direct = _direct_sites(after, new, blocks, region)
    if direct:
        return {**detail, 'kind': 'direct_edit', 'added_executable_lines': direct}, None
    if region.get('region_kind') == 'constructor':
        return None, 'constructor coverage requires a changed executable statement in the pinned region'
    calls, error = _guarded_callers(before, after, old, new, blocks)
    return (None, error) if error else ({**detail, 'kind': 'guarded_callers', 'call_edges': calls}, None)


def _import_evidence(before, after, hunks, region, donor_patch):
    from .location_regions import import_changes, import_key
    expected = import_changes(donor_patch)
    if not expected:
        return None, 'import coverage requires a donor unit consisting of import changes'
    changed = {'+': set(), '-': set()}
    for hunk in hunks:
        for first, last, rows in change_blocks(hunk['patch']):
            if region['line_start'] <= first <= last <= region['line_end']:
                for row in rows:
                    marker = row['marker']
                    if marker in changed and row['text'].strip():
                        changed[marker].add(row['new_line' if marker == '+' else 'old_line'])
    nodes = {marker: [n for n in source.imports
                       if any(source.first(n) <= line <= source.last(n) for line in changed[marker])]
             for marker, source in (('-', before), ('+', after))}
    actual = {marker: Counter(import_key(node) for node in entries) for marker, entries in nodes.items()}
    neutral = actual['+'] & actual['-']
    for marker in changed:
        actual[marker] -= neutral
        skipped = neutral.copy()
        relevant = []
        for node in nodes[marker]:
            key = import_key(node)
            if skipped[key]:
                skipped[key] -= 1
            else:
                relevant.append(node)
        nodes[marker] = relevant
    donor_neutral = expected['+'] & expected['-']
    required = {'+': expected['+'] - donor_neutral - Counter(import_key(n) for n in before.imports),
                '-': expected['-'] - donor_neutral}
    if any(required[m].total() > actual[m].total() for m in changed):
        return None, 'candidate does not supply the required import changes inside the pinned region'
    if not any(actual.values()):
        return None, 'no changed import declaration inside the pinned region'
    return {'kind': 'import_edit',
            'exact': all(not (required[m] - actual[m]) for m in changed),
            'removed_imports': [before.snippet(n) for n in nodes['-']],
            'added_imports': [after.snippet(n) for n in nodes['+']]}, None


def _type_header_evidence(before, after, blocks, region):
    def declarations(source):
        return [n for n in walk(source.tree.root_node)
                if n.type in TYPE_DECLARATIONS and method_name(n) == region['symbol']]
    old = [n for n in declarations(before)
           if (bounds := before.header_bounds(n)) and bounds[0] <= region['line_start'] <= region['line_end'] <= bounds[1]]
    if len(old) != 1:
        return None, 'type header requires one pinned declaration'
    new = [n for n in declarations(after) if ts_key(n) == ts_key(old[0])]
    if len(new) != 1 or not (header := after.header_bounds(new[0])):
        return None, 'candidate type header is ambiguous or unavailable'
    changed = sorted({line for first, last, lines in blocks
                      if region['line_start'] <= first <= last <= region['line_end']
                      for line in lines if header[0] <= line <= header[1]})
    if not changed:
        return None, 'no changed declaration lines inside the candidate type header'
    lines = after.text.splitlines()
    return {'kind': 'type_header_edit', 'candidate_lines': changed,
            'candidate': {'first_line': header[0], 'last_line': header[1],
                          'excerpt': '\n'.join(lines[header[0] - 1:header[1]])}}, None


def _member_evidence(before, after, blocks, region):
    from .location_regions import type_path
    start, end = region['insertion_lines']
    peers = [n for n in before.callables if type_path(_owner(n, TYPE_DECLARATIONS)) == region['type_path']]
    left = [n for n in peers if before.last(n) == start - 1]
    right = [n for n in peers if before.first(n) == end]
    if len(left) != 1 or len(right) != 1:
        return None, 'baseline member boundary is ambiguous'
    after_left = [n for n in after.callables if ts_key(n) == ts_key(left[0])]
    after_right = [n for n in after.callables if ts_key(n) == ts_key(right[0])]
    if len(after_left) != 1 or len(after_right) != 1:
        return None, 'candidate no longer has the pinned neighboring declarations'
    # Git may group the inserted helper with a preceding caller edit. Bind
    # the new declaration to the AST neighbors instead of the diff offset.
    changed = set().union(*(lines for _, _, lines in blocks))
    old = {ts_key(node) for node in before.callables}
    members = [after.snippet(n) for n in after.callables
               if after.first(n) in changed and ts_key(n) not in old
               and n.parent == after_left[0].parent == after_right[0].parent
               and after.last(after_left[0]) < after.first(n) <= after.last(n) < after.first(after_right[0])]
    if not members:
        return None, 'no new callable declaration at the pinned member boundary'
    return {'kind': 'member_insertion', 'members': members,
            'candidate_lines': [m['first_line'] for m in members]}, None


def collect_regions(agent, claims, candidate_patch):
    """Return structurally grounded review inputs and update precise ledger blockers."""
    plan = agent.mapping_plan
    hunks = split_hunks(candidate_patch)
    mapped = plan.data()['assessment']
    units = {unit['id']: unit for unit in mapped['units']}
    donors = {hunk['id']: hunk for hunk in agent._current_hunks}
    cache, requests = {}, []
    for claim in claims:
        evidence = claim.get('target_evidence')
        if not evidence or evidence['ok']:
            continue
        mappings = [row for row in plan.targets(agent.mapping_repository, unit_id=claim['id'])
                    if row['action'] == 'edit' and row['status'] == 'AFFECTED']
        for index, (region, row) in enumerate(zip(mappings, evidence.get('regions', [])), 1):
            row['mapping'] = region
            if row['ok'] or 'site_binding' in row or 'site_evidence' in row:
                continue  # Keep exact donor-site contradictions authoritative.
            path = region['path']
            if path not in cache:
                cache[path] = _parse_path(agent, path, [h for h in hunks if h['path'] == path])
            if cache[path] is None:
                continue
            before, after, blocks = cache[path]
            request = {'id': f"{claim['id']}:{index}", 'mapping': region,
                       'invariant': units[claim['id']]['invariant'], 'donor_patch': donors[claim['id']]['patch']}
            if region.get('region_kind') == 'imports':
                detail, error = _import_evidence(before, after, [h for h in hunks if h['path'] == path],
                                                 region, donors[claim['id']]['patch'])
                if detail and detail.pop('exact'):
                    row.update(ok=True, error=None, match='required import changes in the pinned region')
                    continue
            elif region.get('region_kind') == 'type_header':
                detail, error = _type_header_evidence(before, after, blocks, region)
            elif region.get('region_kind') == 'member_insertion':
                detail, error = _member_evidence(before, after, blocks, region)
            elif region.get('region_kind') == 'field' or (
                    not region.get('region_kind') and region.get('relationship') == 'data_or_configuration'):
                from .java_field_coverage import field_evidence
                for related in {m['path'] for m in mappings}:
                    if related not in cache:
                        cache[related] = _parse_path(agent, related, [h for h in hunks if h['path'] == related])
                detail, error = field_evidence(region, cache[path], {
                    p: cache[p] for p in sorted({m['path'] for m in mappings}) if cache[p] is not None})
            else:
                detail, error = _method_evidence(before, after, blocks, region)
            if error:
                row['error'] = error
                continue
            request.update(detail)
            if len(requests) >= 8 or len(json.dumps(request, ensure_ascii=False).encode()) > MAX_CONTEXT:
                row['error'] = 'mapped coverage proof exceeds its bounded source window'
                continue
            row.update(coverage_request=request['id'], coverage_kind=detail['kind'],
                       error='candidate has mapped evidence pending semantic review')
            requests.append(request)
    return requests


def _review(agent, requests, candidate_patch, contract=()):
    payload = json.dumps(requests, ensure_ascii=False)
    schema, extra = REVIEW_SCHEMA, ''
    if contract:
        from .guarded_repair import REVIEW_GUIDANCE, review_source, reviewer_schema
        schema = reviewer_schema(REVIEW_SCHEMA)
        source = review_source(agent, contract, candidate_patch)
        pin = agent.mapping_plan.data()['targets'][agent.mapping_repository]
        extra = (REVIEW_GUIDANCE + f'\nPinned target selector target:{agent.mapping_repository}, ref {pin}.'
                 + '\nGuarded obligations:\n' + json.dumps(contract, ensure_ascii=False)
                 + '\nPinned baseline and candidate evidence:\n'
                 + json.dumps(source, ensure_ascii=False))
    if len((payload + extra).encode()) > (72 * 1024 if contract else MAX_CONTEXT):
        raise AssessmentError('mapped coverage review exceeds its bounded source window')
    key = hashlib.sha256((candidate_patch + '\0' + payload + extra).encode()).hexdigest()
    cache = agent.__dict__.setdefault('_mapped_coverage_reviews', {})
    if key in cache:
        review, receipt = cache[key]
        if receipt:
            agent.record['repair_obligation_review'] = receipt
        return review
    from .sdk_runtime import CodexRuntime
    factory = agent.runtime_factory or CodexRuntime
    scope = agent.model_scope(read_only=True)
    if contract and scope is not None:
        from dataclasses import replace
        scope = replace(scope, tool_readable=(), tool_context=None, tool_repositories={})
    try:
        with factory(events_path=agent.run_dir / 'sdk-mapped-coverage.jsonl', model=agent.model,
                     model_provider=agent.model_provider, turn_timeout=min(480 if contract else 180, agent.turn_timeout),
                     env=OFFLINE_GIT_ENV, read_scope=scope) as runtime:
            runtime.start(agent.worktree, 'Independently review candidate coverage. Strictly read only.')
            result = runtime.run('''Review every region in the controller evidence below. Use only the supplied snippets.
For direct_edit, confirm the changed executable code implements that region's part of the invariant.
For import_edit, compare every donor import change with the actual added/removed declarations.
Confirm any different import binds the API needed by the target repair. Unrelated declarations
do not count. For COVERED cite the first_line of every listed added import, or an empty list for
a removal-only change. For type_header_edit, cite a changed declaration line and explain its role.
For member_insertion, cite the new declaration's first_line and confirm its implementation
supports the target repair obligation. A helper declaration alone does not prove its callers use it.
For guarded_callers, confirm each listed guard blocks the relevant operation for the same object and
state at the right time, and ordinary behavior remains possible. A guard or change alone is insufficient.
For field_lifecycle, verify the same object is updated, used by the guard, and cleared after the
required state or transition. Inspect all shown uses, including alternate release paths. For COVERED,
candidate_lines must cite the declaration first_line, and state_evidence must cite 1-based state_uses
indices for the set, guard_read, and clear roles on the same bound receiver. Missing ordering, identity,
or release proof is UNRESOLVED.
If behavior depends on an omitted implementation, path, release condition or unproven ordering, use
UNRESOLVED. Explain the actual obligation in reason. For COVERED, candidate_lines must include
a listed added_executable_lines entry for direct_edit, or the first_line of every guard for
guarded_callers. For UNRESOLVED the list may be empty.
Return every supplied id exactly once. Do not edit or claim build or runtime validation.
Controller evidence:\n''' + payload + ('\n' + extra if contract else '\nUse the supplied snippets only.'),
                                 read_only=True, output_schema=schema)
    finally:
        audit = agent.audit_diff()
        if agent._render_patch(audit) != candidate_patch:
            raise RuntimeError('mapped coverage review modified the exported candidate')
    if result.get('status') != 'completed':
        raise RuntimeError('mapped coverage review turn did not complete')
    raw = result.get('output') or json.loads(result.get('final_response', '{}'))
    _shape(raw, schema)
    rows = raw['regions']
    if len(rows) != len(requests) or {r['id'] for r in rows} != {r['id'] for r in requests}:
        raise AssessmentError('mapped coverage review must cover every requested region exactly once')
    by_id = {r['id']: r for r in requests}
    for row in rows:
        if row['verdict'] != 'COVERED':
            continue
        request = by_id[row['id']]
        cited = set(row['candidate_lines'])
        if request['kind'] == 'direct_edit':
            allowed = set(request['added_executable_lines'])
            valid = bool(cited) and cited <= allowed
        elif request['kind'] == 'import_edit':
            valid = cited == {entry['first_line'] for entry in request['added_imports']}
        elif request['kind'] in ('type_header_edit', 'member_insertion'):
            valid = bool(cited) and cited <= set(request['candidate_lines'])
        elif request['kind'] == 'field_lifecycle':
            from .java_field_coverage import ROLES, receiver_key
            uses = request['state_uses']
            indices = row.get('state_evidence', [])
            valid = (cited == {request['candidate']['first_line']}
                     and all(1 <= i <= len(uses) for i in indices)
                     and {uses[i - 1]['role'] for i in indices} == ROLES
                     and len({receiver_key(uses[i - 1]) for i in indices}) == 1)
        else:
            required = {edge['guard']['first_line'] for edge in request['call_edges']}
            valid = cited == required
        if not valid:
            raise AssessmentError('mapped coverage review cites ungrounded candidate lines for ' + row['id'])
    patch_sha = hashlib.sha256(candidate_patch.encode()).hexdigest()
    receipt = None
    if contract:
        from .guarded_repair import ground_review
        obligations = ground_review(agent, raw['obligations'], contract, candidate_patch, source)
        gaps = [{'obligation_id': row['id'], 'path_id': path['id'], 'reason': path['reason']}
                for row in obligations for path in row['paths'] if path['verdict'] in ('unresolved', 'remap')]
        receipt = {'patch_sha256': patch_sha, 'mapping_plan_sha256': agent.mapping_plan.sha256,
                   'status': 'UNRESOLVED' if gaps else 'COVERED',
                   'obligations': obligations, 'coverage_gaps': gaps, 'impact': raw['impact']}
        agent.record['repair_obligation_review'] = receipt
    agent._json(f'mapped-coverage-{key[:16]}.json', {'patch_sha256': patch_sha, 'requests': requests,
                 'regions': rows, **({'repair_obligation_review': receipt} if receipt else {})})
    review = {row['id']: row for row in rows}
    cache[key] = review, receipt
    return review


def review_regions(agent, claims, candidate_patch):
    pending = [claim for claim in claims if claim.get('target_evidence', {}).get('ok') is False]
    if not candidate_patch or not agent.mapping_plan:
        return
    contract = agent.mapping_plan.data().get('repair_contract', [])
    if not pending and not contract:
        return
    requests = collect_regions(agent, pending, candidate_patch) if pending else []
    rows = [r for c in pending for r in c['target_evidence'].get('regions', []) if not r['ok']]
    if any('coverage_request' not in row for row in rows):
        return  # A structural blocker already prevents this candidate from reaching build.
    try:
        review = _review(agent, requests, candidate_patch, contract) if requests or contract else {}
    except (AssessmentError, json.JSONDecodeError) as exc:
        for row in rows:
            row['error'] = str(exc)
        if contract:
            agent.record['repair_obligation_review'] = {'status': 'UNRESOLVED', 'error': str(exc)}
        return
    for row in rows:
        result = review.get(row['coverage_request'])
        if result is None:
            row['error'] = 'mapped coverage review exceeds its bounded source window'
        else:
            row['review'] = result
            row.update(ok=result['verdict'] == 'COVERED', error=None if result['verdict'] == 'COVERED' else result['reason'])
    for claim in pending:
        evidence = claim['target_evidence']
        if evidence.get('regions') and all(r['ok'] for r in evidence['regions']):
            evidence.update(ok=True, error=None, match='evidence in every grounded mapping region')
