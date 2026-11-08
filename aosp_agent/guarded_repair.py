"""Pinned obligations for Java repairs that remove a conjunct from a guard."""
from .activation_flow import branches, ts_key, txt, walk
from .discovery import Repository
from .java_regions import JavaSource, owner
from .patches import text_hunks
from .retrieval import LazyTree


def _terms(node):
    while node.type == 'parenthesized_expression' and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type == 'binary_expression' and txt(node.child_by_field_name('operator')) == '&&':
        return _terms(node.child_by_field_name('left')) + _terms(node.child_by_field_name('right'))
    return [txt(node)]


def _guards(source, changed):
    for node in walk(source.tree.root_node):
        if node.type != 'if_statement':
            continue
        condition, body, other = branches(node)
        method = owner(node, {'method_declaration', 'constructor_declaration'})
        if (method and condition and body and body.type == 'block' and other is None
                and any(source.first(condition) <= line <= source.last(condition) for line in changed)):
            statements = [n for n in body.named_children if not n.type.endswith('_comment')]
            yield ts_key(method), condition, statements


def guard_obligations(unit, before, after):
    """Bind a strict guard relaxation to each unchanged executable statement."""
    path = unit['new_path']
    if (not path or path != unit['old_path'] or not path.endswith('.java')
            or not unit['supported']):
        return []
    old, new = JavaSource(path, before), JavaSource(path, after)
    if old.tree.root_node.has_error or new.tree.root_node.has_error:
        return []
    rows = [r for h in text_hunks(unit['patch']) for r in h['lines']]
    previous = list(_guards(old, {r['old_line'] for r in rows if r['marker'] == '-'}))
    current = list(_guards(new, {r['new_line'] for r in rows if r['marker'] == '+'}))
    obligations = []
    for method, new_guard, body in current:
        if not body:
            continue
        terms = _terms(new_guard)
        matches = []
        for previous_method, old_guard, prior in previous:
            old_terms = _terms(old_guard)
            if (previous_method == method and len(old_terms) > len(terms)
                    and [t for t in old_terms if t in terms] == terms
                    and [txt(s) for s in prior] == [txt(s) for s in body]):
                matches.append(old_guard)
        if len(matches) != 1:
            continue
        old_guard = matches[0]
        for statement in body:
            obligations.append({'id': f"{unit['id']}:guard:{len(obligations) + 1}",
                'unit_id': unit['id'], 'path': path, 'parent_guard': old.snippet(old_guard),
                'fix_guard': new.snippet(new_guard), 'behavior': new.snippet(statement)})
    return obligations


def discover_obligations(controller):
    donor = controller.donor
    if donor['status'] != 'VERIFIED':
        return []
    from pathlib import Path
    root = Path(donor['donor_git'])
    parent, fix = (Repository('donor', root, sha, LazyTree(root, sha, controller.object_cache))
                   for sha in (donor['source_parent'], donor['source_commit']))
    cache, obligations = {}, []
    for unit in controller.units:
        path = unit['new_path']
        if (not path or path != unit['old_path'] or not path.endswith('.java')
                or not unit['supported'] or not any('if' in line and '&&' in line for line in unit['before'].values())):
            continue
        # Load only a Java file whose input hunk changes a conditional.
        delta = [row for h in text_hunks(unit['patch']) for row in h['lines'] if row['marker'] in ('-', '+')]
        if not any(row['marker'] == '-' and 'if' in row['text'] for row in delta):
            continue
        if path not in cache:
            cache[path] = parent.read(path), fix.read(path)
        obligations.extend(guard_obligations(unit, *cache[path]))
    return obligations


# Both paths are declared by the controller. The reviewer may establish that
# cancellation is inapplicable, but cannot omit it or decide the aggregate.
REQUIRED_PATHS = ('normal', 'cancellation')


def review_covers_contract(receipt, contract):
    expected = {row['id'] for row in contract}
    obligations = receipt.get('obligations', [])
    return (bool(expected) and receipt.get('status') == 'COVERED'
            and len(obligations) == len(expected) and {row['id'] for row in obligations} == expected
            and all(row['verdict'] == 'covered' and _paths_covered(row.get('paths', []))
                    for row in obligations))


def _paths_covered(paths):
    return (len(paths) == len(REQUIRED_PATHS) and {p['id'] for p in paths} == set(REQUIRED_PATHS)
            and all(p.get('evidence') and (p['verdict'] == 'covered'
                        or p['id'] != 'normal' and p['verdict'] == 'not_applicable') for p in paths))


def reviewer_schema(regions_schema):
    """Use one read-only turn for coverage and compatibility review."""
    from copy import deepcopy
    from .diff_prompts import LINE, STRING, array, enum, obj
    from .prompts import POST_FIX_SCHEMA

    schema = deepcopy(regions_schema)
    path = obj({'id': enum(*REQUIRED_PATHS), 'verdict': enum('covered', 'unresolved', 'not_applicable', 'remap'),
                'reason': STRING,
                'evidence': array(obj({'window_id': STRING, 'line_start': LINE, 'line_end': LINE}))})
    schema['properties']['obligations'] = array(obj({'id': STRING, 'paths': array(path)}))
    schema['properties']['impact'] = POST_FIX_SCHEMA
    schema['required'] += ['obligations', 'impact']
    return schema


REVIEW_GUIDANCE = '''
For EVERY guarded repair obligation return two separate paths, normal and cancellation.
Normal covers the required effect and ordinary completion. Cancellation covers relevant alternate exits
such as abort, timeout, and replacement while the protection is active. Account for each relevant exit
within that path. Do not mark a path covered while any of its required behavior is unresolved.
Compare the same object and state through update, protection and safe release. A pending transition is
not a running transition. Normal needs changed candidate evidence for an edit obligation, or pinned
baseline protection for already_covered. Cancellation may use either revision. If cancellation does not
apply, mark it not_applicable with the exact mapped source showing why the operation has no applicable
alternate exit. A missing callback or absent evidence alone never supports not_applicable.
Report unresolved with the specific gap when evidence is incomplete. Use remap only with a pinned
excerpt in a mapped read dependency establishing that an additional change is needed.
Use at least one distinct source citation showing cancellation handling when claiming that path is covered.
Record any compatibility concern that leaves a required path unproven in that path's verdict.
The controller computes each obligation verdict from the paths.
If the supplied windows cannot resolve a decisive dependency, say what is missing. Use only the
provided numbered candidate and pinned baseline windows; do not call tools or redo discovery.
Cite supplied window_id and its 1-based line range. Use the exact coordinates displayed.
In impact summarize concrete business compatibility effects briefly. This review occurs before
build; never claim build, runtime, or device verification.
'''


def review_source(agent, contract, patch):
    """Reuse pinned assessment excerpts and attach real candidate coordinates."""
    from .patches import split_hunks
    prefix = agent.mapping_repository + '/'
    units = {o['unit_id'] for o in contract}
    baseline = []
    seen, files = set(), {}
    for unit in agent.mapping_plan.data()['assessment']['units']:
        if unit['id'] not in units:
            continue
        for entry in unit.get('evidence', []):
            if entry['origin'] != 'target' or not entry['path'].startswith(prefix):
                continue
            key = entry['path'], entry['line_start'], entry['line_end']
            if key not in seen:
                seen.add(key)
                path = entry['path'][len(prefix):]
                if path not in files:
                    text = agent._artifact_baseline_text(path)
                    files[path] = text.splitlines() if text is not None else []
                low, high = entry['line_start'], entry['line_end']
                if 1 <= low <= high <= len(files[path]):
                    baseline.append({**entry, 'path': path, 'window_id': f'B{len(baseline) + 1}',
                                     'excerpt': '\n'.join(files[path][low - 1:high])})
    candidate = []
    for unit in split_hunks(patch):
        for hunk in text_hunks(unit['patch']):
            candidate.append({'path': unit['path'], 'window_id': f'C{len(candidate) + 1}',
                'lines': [[row['new_line'], row['text']] for row in hunk['lines'] if row['new_line'] is not None]})
    return {'baseline_windows': baseline, 'candidate_windows': candidate}


def ground_review(agent, rows, contract, patch, source):
    """Ground semantic review and remap suggestions in the actual source vector."""
    from .engine import AssessmentError
    from .integration import added_numbers
    from .mapping_plan import _excerpt
    from .patches import split_hunks

    expected = {row['id']: row for row in contract}
    if len(rows) != len(expected) or {r['id'] for r in rows} != set(expected):
        raise AssessmentError('review must cover every guarded repair obligation exactly once')
    prefix = agent.mapping_repository + '/'
    local_targets = agent.mapping_plan.targets(agent.mapping_repository)
    allowed = {t['path'] for t in local_targets}
    hunks = split_hunks(patch)
    changed = {path: added_numbers([h for h in hunks if h['path'] == path])
               for path in {h['path'] for h in hunks}}
    windows = {}
    for entry in source['baseline_windows']:
        windows[entry['window_id']] = ('baseline', entry['path'], dict(enumerate(
            entry['excerpt'].splitlines(), entry['line_start'])))
    for entry in source['candidate_windows']:
        windows[entry['window_id']] = ('candidate', entry['path'], dict(entry['lines']))
    cache = {}

    def ground_citations(citations):
        grounded = []
        for citation in citations:
            window_id = citation['window_id']
            if window_id not in windows:
                raise AssessmentError('unknown obligation evidence window: ' + window_id)
            revision, path, window = windows[window_id]
            low, high = citation['line_start'], citation['line_end']
            if high < low or high - low >= len(window) or any(i not in window for i in range(low, high + 1)):
                raise AssessmentError('obligation citation is outside the supplied evidence window: ' + window_id)
            evidence = {**citation, 'revision': revision, 'path': path,
                        'excerpt': '\n'.join(window[i] for i in range(low, high + 1))}
            if revision == 'candidate' and path not in allowed:
                raise AssessmentError('obligation review cites a path outside the grounded mapping: ' + path)
            cache_key = revision, path
            if cache_key not in cache:
                file = agent.worktree / path
                if revision == 'baseline':
                    text = agent._artifact_baseline_text(path)
                elif not file.is_file() or file.is_symlink() or file.stat().st_size > 4 * 1024 * 1024:
                    text = None
                else:
                    text = file.read_text()
                if text is None:
                    raise AssessmentError('obligation review cannot read ' + revision + ':' + path)
                cache[cache_key] = text.splitlines()
            _excerpt(cache[cache_key], evidence)
            grounded.append(evidence)
        return grounded

    for row in rows:
        obligation = expected[row['id']]
        targets = obligation['targets']
        edit_paths = {t['path'][len(prefix):] for t in targets
                      if t['action'] == 'edit' and t['path'].startswith(prefix)}
        submitted = {p['id']: p for p in row['paths']}
        if len(submitted) != len(row['paths']) or set(submitted) - set(REQUIRED_PATHS):
            raise AssessmentError('invalid or duplicate review path for ' + row['id'])
        paths, remap = [], []
        for ident in REQUIRED_PATHS:
            path = dict(submitted.get(ident, {'id': ident, 'verdict': 'unresolved',
                                             'reason': 'Required path was not reviewed.', 'evidence': []}))
            try:
                path['evidence'] = ground_citations(path['evidence'])
            except AssessmentError as exc:
                path.update(verdict='unresolved', reason='Invalid source citation: ' + str(exc), evidence=[])
            changed_cite, baseline_cite, mapped_source = False, False, False
            suggestions = []
            for e in path['evidence']:
                low, high = e['line_start'], e['line_end']
                matching = [t for t in targets if t['path'] == prefix + e['path']]
                if e['revision'] == 'candidate':
                    touched = any(low <= line <= high for line in changed.get(e['path'], ()))
                    changed_cite |= e['path'] in edit_paths and touched
                    mapped_source |= touched and any(t.get('relationship') not in ('test', 'data_or_configuration')
                                                     for t in matching)
                else:
                    pinned = [t for t in matching if t['line_start'] <= low <= high <= t['line_end']]
                    baseline_cite |= bool(pinned)
                    mapped_source |= any(t.get('relationship') not in ('test', 'data_or_configuration')
                                         for t in pinned)
                    suggestions.extend(t for t in local_targets if t['path'] == e['path']
                                       and t['unit_id'] == obligation['unit_id'] and t['action'] == 'read_dependency'
                                       and t['line_start'] <= low <= high <= t['line_end'])
            gap = None
            if path['verdict'] == 'covered':
                if not path['evidence']:
                    gap = 'No grounded evidence was cited for the path.'
                elif ident == 'normal' and not (changed_cite if obligation['disposition'] == 'edit' else baseline_cite):
                    gap = 'Normal path lacks grounded changed/baseline evidence.'
            elif path['verdict'] == 'not_applicable' and (ident == 'normal' or not mapped_source):
                gap = 'Non-applicability requires a mapped production source citation for an alternate path.'
            elif path['verdict'] == 'remap':
                if not suggestions:
                    gap = 'Remap requires pinned evidence in a mapped read dependency.'
                else:
                    remap.extend({**t, 'path': prefix + t['path'], 'review_path': ident} for t in suggestions)
            if ident != 'normal' and path['verdict'] == 'covered' and path['evidence']:
                def locations(entries):
                    return {(e['revision'], e['path'], e['line_start'], e['line_end']) for e in entries}
                if not locations(path['evidence']) - locations(paths[0]['evidence']):
                    gap = 'Cancellation requires its own source evidence.'
            if gap:
                path.update(verdict='unresolved', reason=gap + ' ' + path['reason'])
            paths.append(path)
        gaps = [f"{p['id']}: {p['reason']}" for p in paths if p['verdict'] in ('unresolved', 'remap')]
        covered = _paths_covered(paths)
        row.update(paths=paths, verdict='covered' if covered else 'remap' if remap else 'missing',
                   reason='; '.join(gaps if gaps else [f"{p['id']}: {p['reason']}" for p in paths]))
        if remap:
            row['targets_to_reconsider'] = remap
    return rows
