"""Candidate-side proof for Java mappings whose donor spelling does not survive."""
from bisect import bisect_right
from collections import Counter
import hashlib
import json
import re

from .activation_binding import parse_source
from .activation_flow import branches, literal_truth, ts_key, txt, walk
from .diff_prompts import LINE, STRING, array, enum, obj
from .engine import AssessmentError
from .git_policy import OFFLINE_GIT_ENV
from .hunk_scope import change_blocks
from .mapping_plan import _shape
from .patches import split_hunks


REVIEW_SCHEMA = obj({'regions': array(obj({
    'id': STRING, 'verdict': enum('COVERED', 'UNRESOLVED'), 'reason': STRING,
    'candidate_lines': array(LINE),
}))})
MAX_CONTEXT = 48 * 1024
STATEMENTS = {'if_statement', 'return_statement', 'throw_statement',
              'expression_statement', 'local_variable_declaration'}
TYPES = {'class_body', 'interface_body', 'enum_body', 'record_declaration'}


class JavaSource:
    def __init__(self, path, text):
        _, self.tree = parse_source(path, text)
        # Use UTF-8 byte offsets. Point objects in the pinned parser binding
        # can crash on large Java trees on the Linux runtime.
        self.line_starts = [0, *(match.end() for match in re.finditer(b'\n', text.encode()))]

    def first(self, node):
        return bisect_right(self.line_starts, node.start_byte)

    def last(self, node):
        return bisect_right(self.line_starts, node.end_byte - 1)

    def snippet(self, node):
        return {'first_line': self.first(node), 'last_line': self.last(node), 'excerpt': txt(node)}


def _owner(node, kinds):
    cursor = node.parent
    while cursor is not None and cursor.type not in kinds:
        cursor = cursor.parent
    return cursor


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
            originals = [method for method in walk(before.tree.root_node) if method.type == 'method_declaration'
                         and before.first(method) <= region['line_start'] <= region['line_end'] <= before.last(method)]
            if len(originals) != 1:
                continue
            old = originals[0]
            identity = ts_key(old)
            methods = [m for m in walk(after.tree.root_node)
                       if m.type == 'method_declaration' and ts_key(m) == identity]
            if len(methods) != 1:
                continue
            new = methods[0]
            direct = _direct_sites(after, new, blocks, region)
            if direct:
                detail = {'kind': 'direct_edit', 'added_executable_lines': direct}
            else:
                calls, error = _guarded_callers(before, after, old, new, blocks)
                if error:
                    row['error'] = error
                    continue
                detail = {'kind': 'guarded_callers', 'call_edges': calls}
            request = {'id': f"{claim['id']}:{index}", 'mapping': region,
                       'invariant': units[claim['id']]['invariant'], 'donor_patch': donors[claim['id']]['patch'],
                       'baseline': before.snippet(old), 'candidate': after.snippet(new), **detail}
            if len(requests) >= 8 or len(json.dumps(request, ensure_ascii=False).encode()) > MAX_CONTEXT:
                row['error'] = 'mapped coverage proof exceeds its bounded source window'
                continue
            row.update(coverage_request=request['id'], coverage_kind=detail['kind'],
                       error='candidate has mapped evidence pending semantic review')
            requests.append(request)
    return requests


def _review(agent, requests, candidate_patch):
    payload = json.dumps(requests, ensure_ascii=False)
    if len(payload.encode()) > MAX_CONTEXT:
        return {}
    key = hashlib.sha256((candidate_patch + '\0' + payload).encode()).hexdigest()
    cache = agent.__dict__.setdefault('_mapped_coverage_reviews', {})
    if key in cache:
        return cache[key]
    from .sdk_runtime import CodexRuntime
    factory = agent.runtime_factory or CodexRuntime
    try:
        with factory(events_path=agent.run_dir / 'sdk-mapped-coverage.jsonl', model=agent.model,
                     model_provider=agent.model_provider, turn_timeout=min(180, agent.turn_timeout),
                     env=OFFLINE_GIT_ENV, read_scope=agent.model_scope(read_only=True)) as runtime:
            runtime.start(agent.worktree, 'Independently review candidate coverage. Strictly read only.')
            result = runtime.run('''Review every region in the controller evidence below. Use only the supplied snippets.
For direct_edit, confirm the changed executable code implements that region's part of the invariant.
For guarded_callers, confirm each listed guard blocks the relevant operation for the same object and
state at the right time, and ordinary behavior remains possible. A guard or change alone is insufficient.
If behavior depends on an omitted implementation, path, release condition or unproven ordering, use
UNRESOLVED. Explain the actual obligation in reason. For COVERED, candidate_lines must include
a listed added_executable_lines entry for direct_edit, or the first_line of every guard for
guarded_callers. For UNRESOLVED the list may be empty.
Return every supplied id exactly once. Do not edit, run tools or claim build or runtime validation.
Controller evidence:\n''' + payload, read_only=True, output_schema=REVIEW_SCHEMA)
    finally:
        audit = agent.audit_diff()
        if agent._render_patch(audit) != candidate_patch:
            raise RuntimeError('mapped coverage review modified the exported candidate')
    if result.get('status') != 'completed':
        raise RuntimeError('mapped coverage review turn did not complete')
    raw = result.get('output') or json.loads(result.get('final_response', '{}'))
    _shape(raw, REVIEW_SCHEMA)
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
        else:
            required = {edge['guard']['first_line'] for edge in request['call_edges']}
            valid = cited == required
        if not valid:
            raise AssessmentError('mapped coverage review cites ungrounded candidate lines for ' + row['id'])
    agent._json(f'mapped-coverage-{key[:16]}.json', {'patch_sha256': hashlib.sha256(candidate_patch.encode()).hexdigest(),
                 'requests': requests, 'regions': rows})
    cache[key] = {row['id']: row for row in rows}
    return cache[key]


def review_regions(agent, claims, candidate_patch):
    pending = [claim for claim in claims if claim.get('target_evidence', {}).get('ok') is False]
    if not pending or not candidate_patch or not agent.mapping_plan:
        return
    requests = collect_regions(agent, pending, candidate_patch)
    if not requests:
        return
    rows = [r for c in pending for r in c['target_evidence'].get('regions', []) if not r['ok']]
    if any('coverage_request' not in row for row in rows):
        return  # A structural blocker already prevents this candidate from reaching build.
    try:
        review = _review(agent, requests, candidate_patch)
    except (AssessmentError, json.JSONDecodeError) as exc:
        for row in rows:
            row['error'] = str(exc)
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
