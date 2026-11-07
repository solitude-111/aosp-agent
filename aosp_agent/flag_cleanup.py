"""Ground deletion-only aconfig support against pinned targets and the linked repair."""
import re

from .engine import AssessmentError
from .patches import text_hunks


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


def check_flag_cleanup(controller, source, linked_sources, entries):
    """Check one admitted group; nonzero Git errors never establish absence."""
    name_line, flag = _deleted_flag(source)
    words = flag.split('_')
    accessor = words[0] + ''.join(word[0].upper() + word[1:] for word in words[1:])
    call = re.compile(r'\bFlags\s*\.\s*' + re.escape(accessor) + r'\s*\(')
    before = [e for e in entries if e['revision'] == 'source_parent']
    if not any(e['unit_id'] == source['id'] and e['line_start'] <= name_line <= e['line_end'] for e in before):
        raise AssessmentError('no_target_edit support evidence must cite the deleted flag name')
    for primary in linked_sources:
        if not (primary['old_path'] or '').endswith(('.java', '.kt')):
            raise AssessmentError('no_target_edit requires a linked production flag consumer')
        lines = [line for hunk in text_hunks(primary['patch']) for line in hunk['lines']]
        removed_calls = [line['old_line'] for line in lines
                         if line['marker'] == '-' and re.match(r'\s*if\s*\(', line['text'])
                         and call.search(line['text'])]
        if (primary.get('source_id') != source.get('source_id')
                or any(call.search(line['text']) for line in lines if line['marker'] != '-')
                or not any(e['unit_id'] == primary['id'] and any(
                    e['line_start'] <= n <= e['line_end'] for n in removed_calls) for e in before)):
            raise AssessmentError('no_target_edit must cite the linked removal of the flag consumer')
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
