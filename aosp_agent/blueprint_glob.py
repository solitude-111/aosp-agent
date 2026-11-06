"""Bounded POSIX Blueprint glob matching for pinned relative file paths.

Character classes/escapes follow Go filepath.Match; a single ** may consume
whole directories, as in Android 12 Blueprint pathtools. Unsupported/invalid
patterns raise ValueError: they must never silently remove a possible consumer
or an exclusion. This is filename matching, not product build evaluation.
"""
from functools import lru_cache
import posixpath

MAX_LENGTH = 4096
MAX_WORK = 1_000_000


def _checked(value):
    if not isinstance(value, str) or not value or len(value) > MAX_LENGTH:
        raise ValueError('empty or over-limit Blueprint glob/path')
    if '\0' in value or value.startswith('/') or '..' in value.split('/'):
        raise ValueError('Blueprint glob/path must stay within its relative project')
    value.encode('utf-8')


def _segment(pattern):
    tokens, i = [], 0
    def character(index):
        if index >= len(pattern) or pattern[index] in '-]':
            raise ValueError('invalid Blueprint glob character class')
        if pattern[index] == '\\':
            index += 1
        if index >= len(pattern):
            raise ValueError('unfinished Blueprint glob escape')
        return pattern[index], index + 1
    while i < len(pattern):
        char = pattern[i]; i += 1
        if char == '[':
            negated = i < len(pattern) and pattern[i] == '^'
            i += negated
            ranges = []
            while True:
                if i < len(pattern) and pattern[i] == ']' and ranges:
                    i += 1
                    break
                low, i = character(i)
                high = low
                if i < len(pattern) and pattern[i] == '-':
                    high, i = character(i + 1)
                ranges.append((low, high))
            tokens.append(('class', negated, tuple(ranges)))
        elif char == '\\':
            if i == len(pattern):
                raise ValueError('unfinished Blueprint glob escape')
            tokens.append(('literal', pattern[i])); i += 1
        elif char in '*?':
            tokens.append((char,))
        else:
            tokens.append(('literal', char))
    return tuple(tokens)


@lru_cache(maxsize=256)
def _compile(pattern):
    parts = posixpath.normpath(pattern).split('/')
    if parts[-1] == '**' or parts.count('**') > 1:
        raise ValueError('Blueprint glob allows one non-final ** path segment')
    result = []
    for part in parts:
        if part == '**':
            result.append(None)
        elif '**' in part:
            raise ValueError('Blueprint ** must be a complete path segment')
        else:
            result.append(_segment(part))
    return tuple(result)


def _matches(tokens, name):
    if all(token[0] == 'literal' for token in tokens):
        return ''.join(token[1] for token in tokens) == name
    data = name.encode('utf-8')
    # Go's star advances byte-by-byte; ?/classes decode runes, including a
    # width-one RuneError when starting inside a multibyte encoding.
    runes = [('\ufffd', 1)] * len(data)
    offset = 0
    for char in name:
        width = len(char.encode('utf-8'))
        runes[offset] = (char, width)
        offset += width
    def consume(chunk, position):
        for token in chunk:
            if position == len(data):
                return None
            char, width = runes[position]
            if token[0] == 'literal':
                literal = token[1].encode('utf-8')
                if not data.startswith(literal, position):
                    return None
                width = len(literal)
            elif token[0] == 'class':
                if any(low <= char <= high for low, high in token[2]) == token[1]:
                    return None
            position += width
        return position
    # Preserve filepath.Match's earliest-chunk choice, including its UTF-8
    # boundary behavior. No recursive or regular-expression backtracking.
    index, position = 0, 0
    while index < len(tokens):
        star = tokens[index][0] == '*'
        index += star
        start = index
        while index < len(tokens) and tokens[index][0] != '*':
            index += 1
        chunk = tokens[start:index]
        if star and not chunk:
            return True
        stops = range(position, len(data) + 1) if star else (position,)
        for candidate in stops:
            end = consume(chunk, candidate)
            if end is not None and (index < len(tokens) or end == len(data)):
                position = end
                break
        else:
            return False
    return position == len(data)


def glob_matches(pattern, path):
    _checked(pattern); _checked(path)
    segments = _compile(pattern)
    if pattern.endswith('/') != path.endswith('/'):
        return False
    names = posixpath.normpath(path).split('/')
    recursive = next((i for i, s in enumerate(segments) if s is None), None)
    if recursive is None:
        if len(segments) != len(names):
            return False
        pairs = list(zip(segments, names))
    else:
        if len(names) < len(segments) - 1:
            return False
        tail = len(segments) - recursive - 1
        pairs = list(zip(segments[:recursive], names[:recursive]))
        pairs.extend(zip(segments[recursive + 1:], names[-tail:]))
    work = sum((len(name.encode('utf-8')) + 1) * sum(len(t[2]) if t[0] == 'class' else 1 for t in tokens)
               for tokens, name in pairs)
    if work > MAX_WORK:
        raise ValueError('Blueprint glob matching work limit exceeded')
    return all(_matches(tokens, name) for tokens, name in pairs)
