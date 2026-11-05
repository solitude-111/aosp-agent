"""Select candidate change blocks wholly inside one pinned mapping region."""
import re


def changed_lines_in_region(patch, start, end, *, added):
    result, block, old_line = [], [], None
    block_start = None
    def flush():
        if not block:
            return
        removed = sum(line.startswith('-') for line in block)
        last = block_start + max(1, removed) - 1
        # A replacement spanning several mapped regions cannot be attributed
        # separately by a lexical checker. Require a narrower candidate diff.
        if start <= block_start <= last <= end:
            prefix = '+' if added else '-'
            result.extend(line[1:].strip() for line in block if line.startswith(prefix))
        block.clear()
    for line in patch.splitlines():
        match = re.match(r'^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', line)
        if match:
            flush()
            old_line = int(match[1])
        elif old_line is not None and line.startswith(('+', '-')):
            if not block:
                block_start = old_line
            block.append(line)
            old_line += line.startswith('-')
        elif old_line is not None and line.startswith(' '):
            flush()
            old_line += 1
    flush()
    return result
