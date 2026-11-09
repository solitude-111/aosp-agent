"""Derive location-only Java anchors from pinned source and donor change shape."""
from collections import Counter
from pathlib import Path

from .activation_flow import ts_key, txt, walk
from .discovery import Repository
from .engine import AssessmentError
from .java_regions import FIELDS, TYPE_DECLARATIONS, JavaSource, mapped_name, method_name, owner
from .patches import text_hunks
from .retrieval import LazyTree


def import_changes(patch):
    """Recognize a diff unit made entirely of Java import directives."""
    changes = {'+': [], '-': []}
    for hunk in text_hunks(patch):
        for row in hunk['lines']:
            if row['marker'] != ' ' and row['text'].strip():
                changes[row['marker']].append(row['text'])
    result = {}
    for marker, lines in changes.items():
        if not lines:
            result[marker] = Counter()
            continue
        java = JavaSource('Imports.java', '\n'.join(lines))
        root = java.tree.root_node
        if root.has_error or any(node.type != 'import_declaration' for node in root.named_children):
            return None
        result[marker] = Counter(import_key(node) for node in java.imports)
    return result if any(result.values()) else None


def import_key(node):
    return ' '.join(txt(node).split())


def donor_adds_callable(controller, unit, cache):
    donor = getattr(controller, 'donor', {})
    if donor.get('status') != 'VERIFIED' or not unit['supported']:
        return False
    old, new = unit['old_path'], unit['new_path']
    if not old or not new or not old.endswith('.java') or not new.endswith('.java'):
        return False
    root = Path(donor['donor_git'])
    def read(ref, path):
        key = (ref, path)
        if key not in cache:
            repo = Repository('donor', root, ref, LazyTree(root, ref, getattr(controller, 'object_cache', None)))
            cache[key] = JavaSource(path, repo.read(path))
        return cache[key]
    before = read(donor['source_parent'], old)
    after = read(donor['source_commit'], new)
    if before.tree.root_node.has_error or after.tree.root_node.has_error:
        return False
    added = {row['new_line'] for h in text_hunks(unit['patch']) for row in h['lines'] if row['marker'] == '+'}
    old_keys = {ts_key(node) for node in before.callables}
    return any(after.first(node) in added and ts_key(node) not in old_keys for node in after.callables)


def type_path(node):
    names = []
    while node is not None:
        if node.type in TYPE_DECLARATIONS:
            names.append(method_name(node))
        node = node.parent
    return list(reversed(names))


def normalize_java_target(unit, target, lines, java_sources, import_only, adds_callable):
    path = target['path']
    if not path.endswith('.java'):
        return
    if path not in java_sources:
        source = JavaSource(path, '\n'.join(lines))
        java_sources[path] = None if source.tree.root_node.has_error else source
    source = java_sources[path]
    if source is None:
        return  # Keep the existing exact-source validator for unsupported syntax.
    start, end = target['line_start'], target['line_end']
    quoted = [(e['line_start'], e['line_end']) for e in unit['evidence']
              if e['origin'] == 'target' and e['path'] == path
              and start <= e['line_start'] <= e['line_end'] <= end]
    if import_only:
        bounds = source.import_bounds()
        if bounds:
            first, last = max(start, bounds[0]), min(end, bounds[1], len(lines))
            if any(first <= a <= b <= last for a, b in quoted):
                target.update(line_start=first, line_end=last, symbol='Java import declarations',
                              relationship='data_or_configuration', region_kind='imports')
                return

    callables = source.overlapping_callables(start, end)
    if len(callables) == 1 and source.first(callables[0]) <= start <= end <= source.last(callables[0]):
        declaration = callables[0]
        if any(n != declaration and source.first(n) <= start <= end <= source.last(n) for n in source.callables):
            raise AssessmentError('ambiguous nested Java callable; identify the pinned declaration separately')
        target.update(symbol=method_name(declaration),
                      region_kind='method' if declaration.type == 'method_declaration' else 'constructor')
        if target['action'] == 'edit' and target['relationship'] in ('dependency', 'data_or_configuration'):
            target['relationship'] = 'same_function'
        return
    if len(callables) == 2 and callables[0].parent == callables[1].parent:
        left, right = callables
        closing, opening = source.last(left), source.first(right)
        enclosing = owner(left, TYPE_DECLARATIONS)
        if (enclosing is not None and start == closing < opening <= end
                and any(a <= closing < opening <= b for a, b in quoted) and adds_callable()):
            target.update(symbol=method_name(enclosing), relationship='data_or_configuration',
                          region_kind='member_insertion', insertion_lines=[closing + 1, opening],
                          type_path=type_path(enclosing))
            return
    if callables and target['action'] == 'edit':
        raise AssessmentError('Java edit crosses callable boundaries; map each pinned declaration separately')

    for node in walk(source.tree.root_node):
        if node.type in FIELDS and source.first(node) <= start <= end <= source.last(node):
            declarations = [method_name(n) for n in node.named_children if n.type == 'variable_declarator']
            names = [name for name in declarations if name == mapped_name(target['symbol'])]
            enclosing = owner(node, TYPE_DECLARATIONS)
            if enclosing and len(names or declarations) == 1:
                target.update(symbol=f'{method_name(enclosing)}.{(names or declarations)[0]}',
                              relationship='data_or_configuration', region_kind='field')
                return
        if node.type in TYPE_DECLARATIONS and (bounds := source.header_bounds(node)):
            if not callables and bounds[0] <= start <= end <= bounds[1]:
                target.update(symbol=method_name(node), relationship='data_or_configuration', region_kind='type_header')
                return
