"""RetroPatch R5/R6/R13 port: structured diagnosis of apply and verify failures.

apply_diagnosis ports RetroPatch src/tools/project.py::_apply_error_handling
(context mismatch: most-similar block + per-line context diff; file missing:
top-5 similar files via difflib). verification_diagnosis ports the
error-line extraction of _compile_patch/_run_testcase (only error lines,
templated failure explanation), with the r2 fallback: a failed command
whose log yields no error lines contributes its log tail instead of an
empty diagnosis.
"""
from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

from .patch_repair import extract_context, find_most_similar_block

_ERROR_LINE_RE = re.compile(
    r"error:|ERROR:|FAILED:|FAILED\b|cannot find symbol|does not exist|undefined reference",
    re.IGNORECASE)
_SYMBOL_RE = re.compile(r"symbol:\s+(?:class|variable|method|interface|enum|location:)?\s*([\w.$]+)")
_LOG_TAIL_LINES = 80
_SIMILAR_FILES = 5


def _hunk_body_lines(hunk: dict[str, Any]) -> list[str]:
    lines = hunk.get("patch", "").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("@@ ")), None)
    return lines[start + 1:] if start is not None else []


def similar_files(missing_path: str, candidate_files: list[str],
                  top: int = _SIMILAR_FILES) -> list[str]:
    """Top-N most similar paths (R5 port of find_most_similar_files, difflib)."""
    basename = missing_path.rsplit("/", 1)[-1]
    ranked = sorted(candidate_files,
                    key=lambda path: (difflib.SequenceMatcher(None, basename,
                                                             path.rsplit("/", 1)[-1]).ratio(),
                                      difflib.SequenceMatcher(None, missing_path, path).ratio()),
                    reverse=True)
    return ranked[:top]


def apply_diagnosis(hunk: dict[str, Any], worktree_error: str,
                    target_lines: list[str] | None,
                    candidate_files: list[str] | None = None) -> dict[str, Any]:
    """Diagnose one failed hunk application (R6/R5 port).

    {"kind": "context_mismatch"|"file_missing"|"corrupt",
     "similar_block": {"path", "start", "end", "lines"},
     "line_diffs": [{"patch_line", "patch_text", "target_text"}],
     "hint": str}
    For file_missing, similar_block is replaced by the top-5 similar files.
    """
    error = worktree_error or ""
    path = hunk.get("path") or ""
    if "No such file" in error or target_lines is None:
        candidates = candidate_files or []
        return {"kind": "file_missing", "path": path,
                "similar_files": similar_files(path, candidates) if candidates else [],
                "hint": ("The target file does not exist at the baseline; check the similar "
                         "files above or whether the code moved (use hunk-history).")}
    if "corrupt patch" in error:
        return {"kind": "corrupt", "path": path, "similar_block": None, "line_diffs": [],
                "hint": "Malformed hunk text; the hunk body is not a valid unified diff."}
    body = _hunk_body_lines(hunk)
    contexts, _ = extract_context(body)
    lineno, _distance = find_most_similar_block(contexts, target_lines, len(contexts))
    start = max(lineno - 1, 1)
    end = min(lineno + max(len(contexts) - 1, 0), len(target_lines))
    block = {"path": path, "start": start, "end": end,
             "lines": target_lines[start - 1:end]}
    line_diffs = []
    target_index = 0
    for position, line in enumerate(body, 1):
        if not line.startswith((" ", "-")):
            continue
        target_position = lineno - 1 + target_index
        if 0 <= target_position < len(target_lines):
            patch_text, target_text = line[1:], target_lines[target_position]
            if patch_text != target_text:
                line_diffs.append({"patch_line": position, "patch_text": patch_text,
                                   "target_text": target_text})
        else:
            line_diffs.append({"patch_line": position, "patch_text": line[1:],
                               "target_text": None})
        target_index += 1
    if line_diffs:
        hint = ("Context lines differ from the target text; eliminate these diffs so every "
                "context line matches the target exactly.")
    else:
        hint = ("Context text matches the target block, so the failure is positional: keep at "
                "least 3 lines of exact context at the beginning and end of the hunk and "
                "re-anchor the line numbers to the located block.")
    return {"kind": "context_mismatch", "path": path, "similar_block": block,
            "line_diffs": line_diffs, "hint": hint, "located_start": lineno}


def verification_diagnosis(checks: list[dict[str, Any]]) -> dict[str, Any]:
    """Distill verify() command results into a structured diagnosis (R13 port).

    {"stage_results": [{"stage", "returncode", "error_lines", "log_tail",
                        "missing_artifacts", "symbols"}],
     "summary": str}
    """
    stage_results = []
    all_symbols: list[str] = []
    sentences: list[str] = []
    for check in checks:
        code = check.get("returncode", 0)
        stage = check.get("stage", "configured")
        combined = ((check.get("stdout") or "") + "\n" + (check.get("stderr") or "")).splitlines()
        error_lines = [line for line in combined if _ERROR_LINE_RE.search(line)][:40]
        symbols = []
        for line in combined:
            match = _SYMBOL_RE.search(line)
            if match:
                name = match.group(1).split(".")[-1]
                if name and name not in symbols:
                    symbols.append(name)
        missing_artifacts = [item["path"] for item in check.get("artifacts", [])
                             if not item.get("exists")]
        entry = {"stage": stage, "returncode": code, "error_lines": error_lines,
                 "missing_artifacts": missing_artifacts, "symbols": symbols}
        if code and not error_lines and not missing_artifacts:
            # r2 revision 5: never hand the model an empty diagnosis.
            entry["log_tail"] = "\n".join(combined[-_LOG_TAIL_LINES:])
        stage_results.append(entry)
        if code:
            all_symbols.extend(symbols)
            detail = error_lines[0] if error_lines else (
                f"missing artifacts: {', '.join(missing_artifacts)}" if missing_artifacts
                else "see the log tail excerpt")
            sentences.append(f"Stage '{stage}' failed (exit {code}): {detail[:200]}.")
    failed = [entry for entry in stage_results if entry["returncode"]]
    if not failed:
        sentences.append("All configured checks passed.")
    else:
        if all_symbols:
            unique = sorted(set(all_symbols))[:10]
            sentences.append(f"Symbols reported missing by the compiler: {', '.join(unique)}.")
        missing = sorted({path for entry in failed for path in entry["missing_artifacts"]})
        if missing:
            sentences.append(f"Expected artifacts not produced: {', '.join(missing[:10])}.")
    return {"stage_results": stage_results,
            "summary": " ".join(sentences[:10])}
