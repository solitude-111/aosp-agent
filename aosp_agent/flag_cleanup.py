"""Ground deletion-only aconfig support against pinned targets and the linked repair."""
from bisect import bisect_right
from pathlib import Path
import re
import subprocess

from .activation_binding import parse_source
from .activation_flow import compact, txt, walk
from .discovery import Repository, RepositoryReadConstraintError
from .engine import AssessmentError
from .patches import text_hunks
from .retrieval import LazyTree


_CPP_SOURCES = ('.cc', '.cpp', '.cxx')
_ACONFIG_PACKAGE = re.compile(r'\s*package:[ \t]*"([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)"[ \t]*(?:\r?\n|$)', re.ASCII)
_UNLINKED = 'no_target_edit must cite the linked removal of the flag consumer'


def _deleted_flag(unit):
    path = unit['old_path']
    if not path or path != unit['new_path'] or not path.endswith('.aconfig') or unit['kind'] != 'hunk':
        raise AssessmentError('no_target_edit is limited to a deleted aconfig flag declaration')
    lines = text_hunks(unit['patch'])[0]['lines']
    removed = [line for line in lines if line['marker'] == '-']
    content = '\n'.join(line['text'] for line in removed).strip()
    # Accept a single complete declaration, with optional flat metadata.
    # Reject replacements, unrelated deletions, and ambiguous syntax.
    shape = r'flag\s*\{(?:[^{}"]|"(?:\\.|[^"\\])*"|metadata\s*\{[^{}]*\})*\}'
    names = [(line['old_line'], match[1]) for line in removed
             if (match := re.fullmatch(r'\s*name:\s*"([a-z][a-z0-9]*(?:_[a-z0-9]+)*)"\s*', line['text']))]
    positions = [i for i, line in enumerate(lines) if line['marker'] == '-']
    if (any(line['marker'] == '+' and line['text'].strip() for line in lines)
            or len(names) != 1 or positions != list(range(positions[0], positions[-1] + 1))
            or not re.fullmatch(shape, content)):
        raise AssessmentError('no_target_edit must remove exactly one complete aconfig flag declaration')
    return names[0]


def _donor_repositories(controller, unit):
    donor = getattr(controller, 'donor', {})
    source_id = unit.get('source_id')
    if donor.get('status') == 'VERIFIED' and source_id is None:
        step = donor
    elif donor.get('status') == 'VERIFIED_SEQUENCE' and source_id:
        steps = [step for step in donor['steps'] if step['id'] == source_id]
        if len(steps) != 1:
            raise AssessmentError('C++ flag cleanup requires the verified donor step for its declaration')
        step = steps[0]
    else:
        raise AssessmentError('C++ flag cleanup requires a verified donor declaration')
    root = Path(step['donor_git'])
    return tuple(Repository('donor', root, pin, LazyTree(root, pin, getattr(controller, 'object_cache', None)))
                 for pin in (step['source_parent'], step['source_commit']))


def _pinned_read(repo, path):
    try:
        return repo.read(path)
    except (OSError, subprocess.SubprocessError, RepositoryReadConstraintError) as exc:
        raise AssessmentError(f'could not read pinned donor flag source: {path}') from exc


def _cpp_flag_binding(controller, source, flag):
    parent, fix = _donor_repositories(controller, source)
    path = source['old_path']
    old_declaration, new_declaration = _pinned_read(parent, path), _pinned_read(fix, path)
    package = _ACONFIG_PACKAGE.match(old_declaration)
    fixed_package = _ACONFIG_PACKAGE.match(new_declaration)
    if not package or not fixed_package or package[1] != fixed_package[1]:
        raise AssessmentError('C++ flag cleanup needs the same explicit aconfig package at both donor pins')
    if re.search(r'\b' + re.escape(flag) + r'\b', new_declaration):
        raise AssessmentError('deleted C++ flag name is still present in the donor declaration file')
    return parent, fix, package[1]


def _leftmost_conjunct(node):
    while node is not None:
        if node.type == 'binary_expression' and txt(node.child_by_field_name('operator')) == '&&':
            node = node.child_by_field_name('left')
        elif node.type == 'parenthesized_expression' and len(node.named_children) == 1:
            node = node.named_children[0]
        else:
            return node
    return None


def _removed_cpp_calls(unit, flag, binding, lines):
    parent, fix, package = binding
    path = unit['old_path']
    if unit['new_path'] != path:
        raise AssessmentError('C++ flag cleanup requires a same-path production consumer')
    old_source = _pinned_read(parent, path)
    if re.search(r'\b' + re.escape(flag) + r'\b', _pinned_read(fix, path)):
        raise AssessmentError('C++ flag name is still present in the linked donor consumer after the fix')
    try:
        _, tree = parse_source(path, old_source)
    except (ImportError, ValueError) as exc:
        raise AssessmentError('could not parse pinned C++ flag consumer') from exc
    include = package.replace('.', '_') + '.h'
    if not any(node.type == 'preproc_include'
               and txt(node.child_by_field_name('path')) in (f'<{include}>', f'"{include}"')
               for node in walk(tree.root_node)):
        raise AssessmentError('C++ flag consumer does not include the aconfig package header')
    accessor = package.replace('.', '::') + '::' + flag
    removed = {line['old_line'] for line in lines if line['marker'] == '-'}
    line_starts = [0, *(m.end() for m in re.finditer(b'\n', old_source.encode()))]
    calls = []
    for node in walk(tree.root_node):
        if node.type != 'if_statement':
            continue
        condition = node.child_by_field_name('condition')
        if condition is None or condition.has_error:
            continue
        call = _leftmost_conjunct(condition.child_by_field_name('value'))
        if (call is None or call.type != 'call_expression'
                or compact(call.child_by_field_name('function')) not in (accessor, '::' + accessor)
                or compact(call.child_by_field_name('arguments')) != '()'):
            continue
        first = bisect_right(line_starts, call.start_byte)
        last = bisect_right(line_starts, call.end_byte - 1)
        if all(line in removed for line in range(first, last + 1)):
            calls.append((first, last))
    return calls


def check_flag_cleanup(controller, source, linked_sources, entries):
    """Check one admitted group; nonzero Git errors never establish absence."""
    name_line, flag = _deleted_flag(source)
    words = flag.split('_')
    accessor = words[0] + ''.join(word[0].upper() + word[1:] for word in words[1:])
    call = re.compile(r'\bFlags\s*\.\s*' + re.escape(accessor) + r'\s*\(')
    before = [e for e in entries if e['revision'] == 'source_parent']
    if not any(e['unit_id'] == source['id'] and e['line_start'] <= name_line <= e['line_end'] for e in before):
        raise AssessmentError('no_target_edit support evidence must cite the deleted flag name')
    if not linked_sources:
        raise AssessmentError('no_target_edit requires a linked production flag consumer')
    cpp_binding = None
    for primary in linked_sources:
        if primary.get('source_id') != source.get('source_id'):
            raise AssessmentError(_UNLINKED)
        path = primary['old_path'] or ''
        lines = [line for hunk in text_hunks(primary['patch']) for line in hunk['lines']]
        if path.endswith(_CPP_SOURCES):
            cpp_binding = cpp_binding or _cpp_flag_binding(controller, source, flag)
            removed_calls = _removed_cpp_calls(primary, flag, cpp_binding, lines)
        elif path.endswith(('.java', '.kt')):
            if any(call.search(line['text']) for line in lines if line['marker'] != '-'):
                raise AssessmentError(_UNLINKED)
            removed_calls = [(line['old_line'], line['old_line']) for line in lines
                             if line['marker'] == '-' and re.match(r'\s*if\s*\(', line['text'])
                             and call.search(line['text'])]
        else:
            raise AssessmentError('no_target_edit requires a linked production flag consumer')
        if not any(e['unit_id'] == primary['id'] and any(
                e['line_start'] <= start <= end <= e['line_end'] for start, end in removed_calls) for e in before):
            raise AssessmentError(_UNLINKED)
    if controller.inventory_issues:
        raise AssessmentError('cannot establish no_target_edit with unavailable target repositories')
    terms = [flag] if accessor == flag else [flag, accessor]
    for repo in controller.repos:
        result = repo.object_query('grep', '--no-textconv', '-I', '-q', '-F', '-w',
                                   *(arg for term in terms for arg in ('-e', term)),
                                   repo.head, '--', stage='identifier_search', check=False)
        if result.returncode == 0:
            raise AssessmentError(f'target project {repo.key} still references {flag} or {accessor}')
        if result.returncode != 1 or result.stderr:
            raise AssessmentError(f'could not check target flag references in {repo.key}')
    return {'unit_id': source['id'], 'flag': flag,
            'repositories_checked': [repo.key for repo in controller.repos]}
