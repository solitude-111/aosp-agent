"""Select candidate change blocks wholly inside one pinned mapping region."""
from .patches import text_hunks


def changed_lines_in_region(patch, start, end, *, added, touching=None):
    result, block, old_line = [], [], None
    block_start = None
    def flush():
        if not block:
            return
        removed = sum(line.startswith('-') for line in block)
        last = block_start + max(1, removed) - 1
        # A replacement spanning several mapped regions cannot be attributed
        # separately by a lexical checker. Require a narrower candidate diff.
        touches = touching is None or block_start <= touching[1] and last >= touching[0]
        if start <= block_start <= last <= end and touches:
            prefix = '+' if added else '-'
            result.extend(line[1:].strip() for line in block if line.startswith(prefix))
        block.clear()
    for hunk in text_hunks(patch):
        flush()
        old_line = hunk['old_start'] + (hunk['old_count'] == 0)
        for line in hunk['lines']:
            if line['marker'] in ('+', '-'):
                if not block:
                    block_start = old_line
                block.append(line['marker'] + line['text'])
                old_line += line['marker'] == '-'
            else:
                flush()
                old_line += 1
    flush()
    return result
