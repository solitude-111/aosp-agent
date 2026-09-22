"""Pure parsing of donor diffs for independent textual applicability checks.

This module does not apply patches or decide whether a security fix is correct.
``supported`` only means that the record is a textual/metadata Git patch which a
caller can send to its own checker. Even an applicable hunk may miss dependencies
on other hunks, so callers must also check the complete candidate patch.
"""
from __future__ import annotations

import re
from typing import Any


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:[^\r\n]*)[\r\n]*$")
_FILE_PREFIXES = ("diff --git ", "diff --cc ", "diff --combined ")
_NO_NEWLINE = "\\ No newline at end of file"
_FILE_OPERATIONS = ("old mode ", "new mode ", "rename from ", "rename to ",
                    "copy from ", "copy to ")


def split_hunks(diff: str) -> list[dict[str, Any]]:
    """Return independent text hunks, or explicit whole-file/unsupported records.

    Each record has ``id``, ``path``, ``header``, ``patch``, ``kind``,
    ``supported``, ``reason``, file/hunk indices, source/destination paths and
    old/new line counts. Indices are one-based; whole-file records use a null
    hunk index. Text hunks retain their original range and body, including
    no-newline markers. Their file headers are repeated, excluding ``index``
    object hashes, which describe the whole donor file rather than one hunk.

    Mode changes, renames/copies and multipart additions/deletions remain one
    ``whole_file`` record. Binary and combined diffs are ``unsupported`` with a
    reason; they never masquerade as empty successful text hunks. Malformed
    unified hunks raise ``ValueError`` instead of silently losing content.

    Git's standard a/b prefixes and ordinary unprefixed unified diffs are
    accepted. This parser does not authorize paths; the caller must enforce its
    repository path policy before passing any patch to Git.
    """
    if not isinstance(diff, str):
        raise TypeError("diff must be a string")
    if not diff.strip():
        return []
    if "\x00" in diff:
        raise ValueError("diff contains a NUL byte")
    lines = diff.splitlines(keepends=True)
    records: list[dict[str, Any]] = []
    for file_index, block in enumerate(_file_blocks(lines), 1):
        records.extend(_parse_file(block, file_index))
    return records


def _file_blocks(lines: list[str]) -> list[list[str]]:
    starts = [i for i, line in enumerate(lines) if line.startswith(_FILE_PREFIXES)]
    if starts:
        # A format-patch mail/commit preamble is not part of an applicable diff.
        return [lines[start:end] for start, end in zip(starts, starts[1:] + [len(lines)])]
    starts = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("@@ "):
            _, index = _consume_hunk(lines, index)
        elif (line.startswith("--- ") and index + 1 < len(lines)
              and lines[index + 1].startswith("+++ ")):
            starts.append(index)
            index += 2
        elif not line.strip():
            index += 1
        else:
            raise ValueError(f"unrecognized unified diff line {index + 1}")
    if not starts:
        raise ValueError("diff contains no file headers")
    return [lines[start:end] for start, end in zip(starts, starts[1:] + [len(lines)])]


def _parse_file(lines: list[str], file_index: int) -> list[dict[str, Any]]:
    combined = lines[0].startswith(("diff --cc ", "diff --combined "))
    binary = any(line.startswith(("GIT binary patch", "Binary files ")) for line in lines)
    first_hunk = next((i for i, line in enumerate(lines) if line.startswith("@@ ")), len(lines))
    metadata = lines[:first_hunk]
    old_path, new_path = _paths(metadata)
    # Empty file creation/deletion can omit ---/+++ entirely.
    if any(line.startswith("new file mode ") for line in metadata):
        old_path = None
    if any(line.startswith("deleted file mode ") for line in metadata):
        new_path = None
    path = new_path or old_path
    if path is None:
        raise ValueError(f"cannot identify path for file {file_index}")
    base = {"file_index": file_index, "path": path, "old_path": old_path,
            "new_path": new_path}
    if combined or binary:
        reason = "combined_diff" if combined else "binary_diff"
        return [{**base, "id": f"f{file_index:03d}-unsupported", "header": lines[0].rstrip("\r\n"),
                 "patch": "".join(lines), "kind": "unsupported", "supported": False,
                 "reason": reason, "hunk_index": None, "hunk_count": 0,
                 "old_start": None, "new_start": None, "old_count": None, "new_count": None}]
    prefix = "".join(line for line in metadata if not line.startswith("index "))
    hunks = []
    index = first_hunk
    while index < len(lines):
        if not lines[index].strip():
            index += 1
            continue
        if lines[index].rstrip("\r\n") == "-- ":
            # Standard git format-patch signature/version trailer.
            break
        hunk, index = _consume_hunk(lines, index)
        hunks.append(hunk)
    if hunks:
        old_headers = [line for line in metadata if line.startswith("--- ")]
        new_headers = [line for line in metadata if line.startswith("+++ ")]
        if len(old_headers) != 1 or len(new_headers) != 1:
            raise ValueError(f"file {file_index} must have one ---/+++ header pair")
        if old_path is None and any(hunk["old_count"] for hunk in hunks):
            raise ValueError("new-file hunk contains old-file lines")
        if new_path is None and any(hunk["new_count"] for hunk in hunks):
            raise ValueError("deleted-file hunk contains new-file lines")
    operations = [line for line in metadata if line.startswith(_FILE_OPERATIONS)]
    whole_file = bool(operations) or ((old_path is None or new_path is None) and len(hunks) > 1)
    if not hunks:
        if not any(line.startswith((*_FILE_OPERATIONS, "new file mode ", "deleted file mode "))
                   for line in metadata):
            raise ValueError(f"file {file_index} contains neither text hunks nor supported metadata")
        whole_file = True
    if whole_file:
        return [{**base, "id": f"f{file_index:03d}-whole", "header": lines[0].rstrip("\r\n"),
                 "patch": prefix + "".join(hunk["body"] for hunk in hunks),
                 "kind": "whole_file", "supported": True,
                 "reason": "file_metadata_or_lifecycle_change", "hunk_index": None,
                 "hunk_count": len(hunks), "hunk_headers": [hunk["header"] for hunk in hunks],
                 "old_start": None, "new_start": None,
                 "old_count": sum(hunk["old_count"] for hunk in hunks),
                 "new_count": sum(hunk["new_count"] for hunk in hunks)}]
    result = []
    for hunk_index, hunk in enumerate(hunks, 1):
        result.append({**base, "id": f"f{file_index:03d}-h{hunk_index:03d}",
                       "hunk_index": hunk_index, "hunk_count": 1,
                       "kind": "hunk", "supported": True, "reason": None,
                       "patch": prefix + hunk["body"],
                       **{key: value for key, value in hunk.items() if key != "body"}})
    return result


def _consume_hunk(lines: list[str], index: int) -> tuple[dict[str, Any], int]:
    start = index
    match = _HUNK.fullmatch(lines[index])
    if match is None:
        raise ValueError(f"invalid hunk header at line {index + 1}")
    old_start, old_count, new_start, new_count = (int(value) if value is not None else 1
                                               for value in match.groups())
    old_left, new_left = old_count, new_count
    index += 1
    previous_was_content = False
    additions = removals = context = 0
    while old_left or new_left:
        if index >= len(lines):
            raise ValueError(f"truncated hunk at line {start + 1}")
        line = lines[index]
        if line.rstrip("\r\n") == _NO_NEWLINE:
            if not previous_was_content:
                raise ValueError("no-newline marker must follow a content line")
            previous_was_content = False
            index += 1
            continue
        prefix = line[:1]
        if prefix == " ":
            old_left -= 1
            new_left -= 1
            context += 1
        elif prefix == "-":
            old_left -= 1
            removals += 1
        elif prefix == "+":
            new_left -= 1
            additions += 1
        else:
            raise ValueError(f"invalid hunk content at line {index + 1}")
        if old_left < 0 or new_left < 0:
            raise ValueError(f"hunk line counts exceeded at line {index + 1}")
        previous_was_content = True
        index += 1
    if index < len(lines) and lines[index].rstrip("\r\n") == _NO_NEWLINE:
        if not previous_was_content:
            raise ValueError("no-newline marker must follow a content line")
        index += 1
    return {"header": lines[start].rstrip("\r\n"), "body": "".join(lines[start:index]),
            "old_start": old_start, "old_count": old_count,
            "new_start": new_start, "new_count": new_count,
            "added_lines": additions, "removed_lines": removals, "context_lines": context}, index


def _paths(metadata: list[str]) -> tuple[str | None, str | None]:
    old_header = next((line[4:].rstrip("\r\n") for line in metadata if line.startswith("--- ")), None)
    new_header = next((line[4:].rstrip("\r\n") for line in metadata if line.startswith("+++ ")), None)
    if old_header is not None and new_header is not None:
        return _header_path(old_header), _header_path(new_header)
    for operation in ("rename", "copy"):
        old = next((line[len(operation) + 6:].rstrip("\r\n") for line in metadata
                    if line.startswith(operation + " from ")), None)
        new = next((line[len(operation) + 4:].rstrip("\r\n") for line in metadata
                    if line.startswith(operation + " to ")), None)
        if old is not None and new is not None:
            return _unquote(old), _unquote(new)
    first = metadata[0].rstrip("\r\n")
    if first.startswith(("diff --cc ", "diff --combined ")):
        path = _unquote(first.split(" ", 2)[2])
        return path, path
    if not first.startswith("diff --git "):
        return None, None
    rest = first[len("diff --git "):]
    # Ordinary mode-only paths may contain unquoted spaces. Matching both
    # sides avoids guessing at an embedded " b/" inside the actual filename.
    if rest.startswith("a/"):
        for boundary in (match.start() for match in re.finditer(r" b/", rest)):
            old, new = rest[2:boundary], rest[boundary + 3:]
            if old == new:
                return old, new
    token = r'"(?:[^"\\]|\\.)*"|\S+'
    parts = re.findall(token, rest)
    if len(parts) != 2:
        return None, None
    return _header_path(parts[0]), _header_path(parts[1])


def _header_path(value: str) -> str | None:
    # Unified-diff timestamps are tab-delimited. Quoted Git paths escape tabs.
    path = _unquote(value.split("\t", 1)[0])
    if path == "/dev/null":
        return None
    return path[2:] if path.startswith(("a/", "b/")) else path


def _unquote(value: str) -> str:
    if not value.startswith('"'):
        return value
    if len(value) < 2 or not value.endswith('"'):
        raise ValueError("unterminated quoted Git path")
    result = bytearray()
    escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13,
               "\\": 92, '"': 34}
    index = 1
    while index < len(value) - 1:
        char = value[index]
        if char != "\\":
            result.extend(char.encode("utf-8"))
            index += 1
            continue
        index += 1
        if index >= len(value) - 1:
            raise ValueError("invalid Git path escape")
        char = value[index]
        if char in escapes:
            result.append(escapes[char])
            index += 1
        elif char in "01234567":
            end = index + 1
            while end < min(index + 3, len(value) - 1) and value[end] in "01234567":
                end += 1
            number = int(value[index:end], 8)
            if number > 255:
                raise ValueError("invalid Git path octal escape")
            result.append(number)
            index = end
        else:
            raise ValueError("invalid Git path escape")
    return result.decode("utf-8", errors="surrogateescape")
