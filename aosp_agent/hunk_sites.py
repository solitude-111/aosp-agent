"""Bind donor change blocks to unchanged target text before crediting edits.

This is a textual site check, not a proof of semantic equivalence. When version
drift prevents binding, the caller still needs its independently grounded
mapping; matching tokens elsewhere in a file cannot replace a known site.
"""
import re
from .patches import text_hunks


def normalized(line):
    return ' '.join(line.split())


def old_chunks(patch):
    chunks = []
    for hunk in text_hunks(patch):
        chunk = {'old': [], 'blocks': []}; chunks.append(chunk); block = None
        for line in hunk['lines']:
            if line['marker'] == ' ':
                chunk['old'].append(line['text']); block = None
            else:
                if block is None:
                    block = {'offset': len(chunk['old']), 'removed': [], 'added': []}
                    chunk['blocks'].append(block)
                block['removed' if line['marker'] == '-' else 'added'].append(line['text'])
                if line['marker'] == '-': chunk['old'].append(line['text'])
    return chunks


def index_baseline(baseline):
    lines, occurrences = [normalized(line) for line in baseline], {}
    for index, line in enumerate(lines):
        occurrences.setdefault(line, []).append(index)
    return lines, occurrences


def bind_changes(patch, baseline, *, start=1, end=None, indexed=None):
    """Return exact unique old-text sites, or explicit unresolved/ambiguous.

    Context lines establish identity but do not themselves get edit credit.
    Offsets retain blank lines and insertion positions. A declared mapping can
    disambiguate repeated text; it cannot move a uniquely known site elsewhere.
    """
    target, occurrences = indexed if indexed is not None else index_baseline(baseline)
    end = len(target) + 1 if end is None else end
    chunks = old_chunks(patch)
    if not chunks: return {'status': 'UNRESOLVED', 'blocks': []}
    result = []
    for chunk in chunks:
        old = [normalized(line) for line in chunk['old']]
        if not old or not any(re.search(r'\w', line) for line in old):
            return {'status': 'UNRESOLVED', 'blocks': []}
        # Anchor the search on the rarest nonblank old line. Reusing this
        # immutable index avoids a whole-file scan for each sibling hunk.
        anchor = min((i for i, line in enumerate(old) if line), key=lambda i: len(occurrences.get(old[i], ())))
        matches = [hit - anchor for hit in occurrences.get(old[anchor], ())
                   if hit >= anchor and target[hit - anchor:hit - anchor + len(old)] == old]
        if not matches: return {'status': 'UNRESOLVED', 'blocks': []}
        candidates = []
        for index in matches:
            blocks = []
            for block in chunk['blocks']:
                first = index + block['offset'] + 1
                last = first + max(1, len(block['removed'])) - 1
                blocks.append({'line_start': first, 'line_end': last,
                               'patch': f"@@ -1,{len(block['removed'])} +1,{len(block['added'])} @@\n"
                                        + ''.join('-' + s + '\n' for s in block['removed'])
                                        + ''.join('+' + s + '\n' for s in block['added'])})
            if blocks and all(start <= b['line_start'] <= b['line_end'] <= end for b in blocks):
                candidates.append(blocks)
        if not candidates: return {'status': 'OUTSIDE_MAPPING', 'blocks': []}
        if len(candidates) != 1: return {'status': 'AMBIGUOUS', 'blocks': []}
        result.extend(candidates[0])
    return {'status': 'BOUND', 'blocks': result}


def matches_additions(lines, expected):
    """Require a precisely mapped ordered addition, not unrelated extra sites."""
    actual = [normalized(line) for line in lines if line.strip()]
    wanted = [normalized(line) for line in expected if line.strip()]
    return bool(wanted) and actual == wanted


def sequence_sites(lines, expected):
    """Return original line indexes for complete ordered code sequences."""
    indexed = [(i, normalized(line)) for i, line in enumerate(lines) if line.strip()]
    actual = [line for _, line in indexed]
    wanted = [normalized(line) for line in expected if line.strip()]
    if not wanted: return []
    return [(indexed[i][0], indexed[i + len(wanted) - 1][0])
            for i in range(len(actual) - len(wanted) + 1)
            if actual[i:i + len(wanted)] == wanted]
