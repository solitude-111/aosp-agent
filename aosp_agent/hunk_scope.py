"""Select candidate change blocks wholly inside one pinned mapping region."""
from .patches import text_hunks


def change_blocks(patch):
    """Yield each contiguous diff block with its pinned old-line range."""
    for hunk in text_hunks(patch):
        old = hunk['old_start'] + (hunk['old_count'] == 0)
        start, block = old, []
        for row in hunk['lines']:
            if row['marker'] == ' ':
                if block:
                    yield start, max(start, old - 1), block
                old += 1
                start, block = old, []
            else:
                block.append(row)
                old += row['marker'] == '-'
        if block:
            yield start, max(start, old - 1), block


def changed_lines_in_region(patch, start, end, *, added, touching=None):
    result = []
    for first, last, block in change_blocks(patch):
        # Attribute only complete blocks contained by the mapped region.
        touches = touching is None or first <= touching[1] and last >= touching[0]
        if start <= first <= last <= end and touches:
            marker = '+' if added else '-'
            result.extend(row['text'].strip() for row in block if row['marker'] == marker)
    return result
