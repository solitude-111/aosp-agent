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


def reviewer_schema(regions_schema):
    """Use one read-only turn for coverage and compatibility review."""
    from copy import deepcopy
    from .diff_prompts import LINE, STRING, array, enum, obj
    from .prompts import POST_FIX_SCHEMA

    schema = deepcopy(regions_schema)
    schema['properties']['obligations'] = array(obj({
        'id': STRING, 'verdict': enum('covered', 'missing', 'remap'), 'reason': STRING,
        'evidence': array(obj({'window_id': STRING, 'line_start': LINE, 'line_end': LINE})),
    }))
    schema['properties']['impact'] = POST_FIX_SCHEMA
    schema['required'] += ['obligations', 'impact']
    return schema


REVIEW_GUIDANCE = '''
Also assess EVERY guarded repair obligation below, even if the candidate exactly matches a changed
donor line. Compare both fixed donor behaviors and old target behavior. Verify the protection for
the same object and affected state, from update to check/use and safe release. Follow actual old
definitions when names might hide semantic differences. A pending/starting transition is not a
running transition. Check normal removal and relevant alternate/cancellation paths; only explain
an exemption when it is backed by source evidence. A flag declaration or helper name is insufficient.
Use covered only with exact source excerpts that prove the whole behavior. Edit obligations need
at least one exact changed candidate excerpt. For already_covered cite exact baseline protection.
Use missing when the implementation or proof is incomplete. Use remap only if a grounded baseline
excerpt in a mapped read-dependency region establishes a required change outside the write obligation.
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
    for row in rows:
        obligation = expected[row['id']]
        edit_paths = {t['path'][len(prefix):] for t in obligation['targets']
                      if t['action'] == 'edit' and t['path'].startswith(prefix)}
        changed_cite, baseline_cite = False, False
        remap, grounded = [], []
        for citation in row['evidence']:
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
            if revision == 'candidate':
                changed_cite |= path in edit_paths and any(low <= line <= high for line in changed.get(path, ()))
            else:
                baseline_cite |= any(t['path'] == prefix + path and t['line_start'] <= low <= high <= t['line_end']
                                     for t in obligation['targets'])
                remap.extend(t for t in local_targets if t['path'] == path and t['unit_id'] == obligation['unit_id']
                             and t['action'] == 'read_dependency'
                             and t['line_start'] <= low <= high <= t['line_end'])
        row['evidence'] = grounded
        if row['verdict'] == 'covered':
            valid = changed_cite if obligation['disposition'] == 'edit' else baseline_cite
            if not valid:
                raise AssessmentError('covered obligation lacks grounded changed/baseline evidence: ' + row['id'])
        if row['verdict'] == 'remap':
            if not remap:
                raise AssessmentError('remap requires pinned evidence in a mapped read dependency: ' + row['id'])
            row['targets_to_reconsider'] = [{**t, 'path': prefix + t['path']} for t in remap]
    return rows
