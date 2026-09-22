"""RetroPatch R3 port: mechanical donor-hunk repair before applying.

Ported from RetroPatch src/tools/utils.py::revise_patch (L137-285) and
find_most_similar_block (L64-109), with three deliberate differences
recorded per the adaptation plan:

1. Levenshtein is replaced by a difflib.SequenceMatcher proxy distance
   (matched-character based, monotone for ranking); RetroPatch's window
   scan and offset-alignment logic are preserved.
2. The ``revise_context=True`` forced context rewrite is NOT ported (it
   would mask model errors); mechanical repair only ever touches donor
   hunks before any model involvement, and every repair is recorded.
3. RetroPatch's ``'s ' -> '->'`` replacement on '+' lines (a quirk of its
   model-generated patches) is not ported: donor hunks are well-formed.

Repairs are never silent: repair_hunk returns the full list of fixes.
"""
from __future__ import annotations

import difflib
import re
from typing import Any

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
NO_NEWLINE = "\\ No newline at end of file"
_CONTEXT_STRIP = re.compile(r"\s+")


def _distance(a: str, b: str) -> int:
    """Levenshtein-proxy: total length minus twice the matched characters."""
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    matched = sum(block.size for block in matcher.get_matching_blocks())
    return len(a) + len(b) - 2 * matched


def find_most_similar_block(pattern: list[str], main: list[str],
                            p_len: int) -> tuple[int, int]:
    """Find the window of ``p_len`` lines in ``main`` closest to ``pattern``.

    Returns (1-based start line, distance), mirroring RetroPatch
    utils.find_most_similar_block including the offset-alignment pass that
    snaps the window onto an exactly matching (whitespace-stripped) line.
    """
    if p_len <= 0 or len(main) < p_len:
        return 1, 0 if p_len <= 0 else _distance("\n".join(pattern), "\n".join(main[:p_len]))
    joined_pattern = "\n".join(pattern)
    min_distance = None
    best_start_index = 1
    for index in range(len(main) - p_len + 1):
        candidate = "\n".join(main[index:index + p_len])
        distance = _distance(candidate, joined_pattern)
        if min_distance is None or distance < min_distance:
            min_distance = distance
            best_start_index = index + 1
    # Ported offset alignment (RetroPatch utils.py L89-108): a pattern line
    # exactly matching (whitespace-stripped) near the window start snaps the
    # window by the measured offset j - i.
    offset_flag = False
    offset = float("inf")
    lineno = best_start_index
    for i in range(p_len):
        if len(pattern[i].strip()) < 3:
            continue
        for j in range(-5, 6):
            position = lineno - 1 + j
            if 0 <= position < len(main) and pattern[i].strip() == main[position].strip():
                offset_flag = True
                if abs(j - i) < abs(offset):
                    offset = j - i
        if offset_flag:
            best_start_index += int(offset)
            break
    return best_start_index, int(min_distance)


def extract_context(lines: list[str]) -> tuple[list[str], list[str]]:
    """Split diff body lines into (context+removed text, added text).

    Port of RetroPatch utils.extract_context.
    """
    contexts: list[str] = []
    added: list[str] = []
    for line in lines:
        if line.startswith((" ", "-")):
            contexts.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
    return contexts, added


def repair_hunk(hunk: dict[str, Any], target_lines: list[str]) -> tuple[str, list[dict[str, Any]]]:
    """Mechanically repair one donor hunk against the target file.

    Returns (patch_text, repairs); repairs is a list of
    {"what": "line_numbers"|"prefix"|"indent", "detail": str} and is
    complete — every applied fix is recorded.
    """
    repairs: list[dict[str, str]] = []
    lines = hunk.get("patch", "").splitlines()
    header_index = next((i for i, line in enumerate(lines) if line.startswith("@@ ")),
                        None)
    if header_index is None or hunk.get("kind") != "hunk":
        return "\n".join(lines) + ("\n" if lines else ""), repairs
    prefix_lines, body = lines[:header_index], lines[header_index + 1:]
    match = HUNK_HEADER.fullmatch(lines[header_index])
    if match is None:
        return "\n".join(lines) + "\n", repairs
    old_start = match.group(1)
    new_start = match.group(3)
    section = match.group(5) or ""

    # 1. Prefix repair: content lines must start with '+', '-' or ' '.
    fixed_body: list[str] = []
    for line in body:
        if line.rstrip("\r\n") == NO_NEWLINE:
            fixed_body.append(line)
        elif not line.startswith(("+", "-", " ")):
            fixed_body.append(" " + line)
            repairs.append({"what": "prefix", "detail": f"added missing diff prefix to: {line[:120]}"})
        else:
            fixed_body.append(line)

    # 2. Locate the context block in the target file (RetroPatch uses the
    # same find_most_similar_block call before touching indentation).
    contexts, _ = extract_context(fixed_body)
    lineno, _distance_value = find_most_similar_block(contexts, target_lines, len(contexts))

    # 3. Indentation repair: only when whitespace-normalized text matches
    # (RetroPatch revise_hunk's re.sub(r"\s+","",...) equality check).
    repaired_body: list[str] = []
    context_index = 0
    for line in fixed_body:
        if line.rstrip("\r\n") == NO_NEWLINE:
            repaired_body.append(line)
            continue
        if line.startswith((" ", "-")):
            position = lineno - 1 + context_index
            if 0 <= position < len(target_lines):
                target_line = target_lines[position]
                if (_CONTEXT_STRIP.sub("", line[1:]) == _CONTEXT_STRIP.sub("", target_line)
                        and line[1:] != target_line):
                    repairs.append({"what": "indent",
                                    "detail": f"line aligned to target {position + 1}: {line[1:][:80]!r} -> {target_line[:80]!r}"})
                    line = line[0] + target_line
            context_index += 1
        repaired_body.append(line)

    # 4. Line-number repair: recount the hunk from its actual body.
    old_count = sum(1 for line in repaired_body
                    if line.rstrip("\r\n") != NO_NEWLINE and not line.startswith("+"))
    new_count = sum(1 for line in repaired_body
                    if line.rstrip("\r\n") != NO_NEWLINE and not line.startswith("-"))
    declared_old, declared_new = match.group(2), match.group(4)
    if str(old_count) != declared_old or str(new_count) != declared_new:
        repairs.append({"what": "line_numbers",
                        "detail": f"header counts corrected: -{old_start},{declared_old} "
                                  f"+{new_start},{declared_new} -> -{old_start},{old_count} "
                                  f"+{new_start},{new_count}"})
    header = f"@@ -{old_start},{old_count} +{new_start},{new_count} @@{section}"
    patch_text = "\n".join([*prefix_lines, header, *repaired_body]) + "\n"
    return patch_text, repairs
