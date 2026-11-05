"""Lossless review batches; lexical labels never authorize hunk exclusion."""
import hashlib
import re
from collections import Counter


HINTS = {
    'permissions_or_identity': re.compile(r'permission|callingUid|clearCallingIdentity|\buid\b', re.I),
    'bounds_or_validation': re.compile(r'\bif\s*\(|\bassert\b|overflow|\blimit\b|\bsize\b', re.I),
    'locking_or_lifetime': re.compile(r'mutex|synchronized|\batomic\b|\bfree\s*\(|refcount', re.I),
}


def review_groups(hunks, batch_size=8):
    if not 1 <= batch_size <= 32:
        raise ValueError('review batch size must be between 1 and 32')
    ids = [h['id'] for h in hunks]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate hunk identity')
    entries, buckets = [], {}
    for hunk in hunks:
        path = hunk.get('new_path') or hunk.get('old_path') or hunk['path']
        text = hunk['patch']
        changed = [(n, line) for n, line in enumerate(text.splitlines(), 1)
                   if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))]
        labels = [label for label, pattern in HINTS.items() if any(pattern.search(line[1:]) for _, line in changed)]
        role = ('build_configuration' if path.rsplit('/', 1)[-1] in ('Android.bp', 'Android.mk', 'CMakeLists.txt') else
                'test_candidate' if re.search(r'(^|/)(tests?|testdata)(/|$)|Test\.[^.]+$', path) else
                'other_source_or_data')
        operation = ('unsupported' if not hunk['supported'] else 'addition' if not hunk.get('old_path') else
                     'deletion' if not hunk.get('new_path') else 'file_operation' if hunk['kind'] == 'whole_file' else 'edit')
        entries.append({'id': hunk['id'], 'path': path, 'operation': operation, 'role_hint': role,
            'lexical_hints': labels or ['unclassified'],
            'hint_evidence': [{'label': label, 'patch_line': n, 'text': line}
                              for label in labels for n, line in changed if HINTS[label].search(line[1:])],
            'patch_sha256': hashlib.sha256(text.encode()).hexdigest(), 'requires_individual_review': True})
        # File-local batches help follow a refactor without treating shared
        # tokens in different hunks as shared semantic evidence.
        buckets.setdefault((hunk['file_index'], path), []).append(hunk['id'])
    groups = []
    for (_, path), members in buckets.items():
        for start in range(0, len(members), batch_size):
            groups.append({'id': f'group-{len(groups) + 1:03d}', 'path': path,
                           'hunk_ids': members[start:start + batch_size]})
    return {'version': 1, 'scope': 'review_navigation_only', 'exclusion_authority': False,
            'total_hunks': len(ids), 'required_hunk_ids': ids, 'entries': entries, 'groups': groups,
            'operation_counts': dict(Counter(e['operation'] for e in entries)),
            'limitations': ['Labels are lexical hints, not applicability or security judgments.',
                            'Every original hunk still needs its own grounded ledger declaration.']}


def review_prompt(report):
    import json
    compact = {k: report[k] for k in ('scope', 'total_hunks', 'groups', 'operation_counts', 'limitations')}
    return ('\nController review batches (navigation only; no hunk is waived, including tests/build/metadata):\n'
            + json.dumps(compact, ensure_ascii=False) + '\n')
