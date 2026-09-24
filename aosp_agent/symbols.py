"""RetroPatch R4 port: extract API references from donor hunks and locate
them at a target revision with git grep, suggesting nearest names on miss.

The RetroPatch original (src/tools/project.py::_locate_symbol and
::_locate_similar_symbol) uses ctags + Levenshtein. This port uses bounded
git grep plus difflib (no ctags dependency, no third-party packages),
keeping the observable behavior: exact location first, nearest-name hints
when the symbol is absent. All Git access is read-only with lazy fetch
disabled.
"""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .discovery import local_git

DEFAULT_PATHSPECS = ("*.java", "*.kt", "*.aidl", "*.py")
IMPORT_RE = re.compile(r"\bimport\s+(?:static\s+)?([\w.]+)\s*;")
ANNOTATION_RE = re.compile(r"@([A-Z]\w*)")
NEW_RE = re.compile(r"\bnew\s+([A-Z]\w*)\s*\(")
EXTENDS_RE = re.compile(r"\b(?:extends|implements)\s+([A-Z]\w*)")
STATIC_CALL_RE = re.compile(r"\b([A-Z]\w*)\.\w+\s*\(")
BARE_CALL_RE = re.compile(r"(?<![\w.$])([a-z]\w{2,})\s*\(")

# Tokens that never indicate an API reference when followed by "(".
_CONTROL_WORDS = frozenset(
    "if else for while switch case catch synchronized return new super this assert "
    "throw do try yield sizeof typeof in of not and or await delete".split())
# Preceding tokens that make "name(" look like a local definition, not a call.
_DECL_PRECEDERS_OK = re.compile(r"^[\w\]\>$]+$")

KIND_PRIORITY = {"import": 0, "type_ref": 1, "annotation": 2, "method_call": 3}
MAX_SYMBOLS = 40
MAX_MATCHES = 20
MAX_REPORT_BYTES = 8192


def _added_lines(hunk: dict[str, Any]) -> Iterable[tuple[int, str]]:
    """Yield (1-based patch line number, text) for '+' body lines of a hunk."""
    for number, line in enumerate(hunk.get("patch", "").splitlines(), 1):
        if line.startswith("+") and not line.startswith("+++"):
            yield number, line


def _defined_in_hunk(hunk: dict[str, Any], name: str) -> bool:
    pattern = re.compile(rf"\b([\w\]\>$]+)\s+{re.escape(name)}\s*\(")
    for line in hunk.get("patch", "").splitlines():
        match = pattern.search(line)
        if match and match.group(1) not in _CONTROL_WORDS and _DECL_PRECEDERS_OK.match(match.group(1)):
            return True
    return False


def extract_referenced_symbols(hunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """From '+' lines of donor hunks extract candidate API references.

    Each entry: {"name", "kind", "origin": {"hunk_id", "line"}} with kinds
    "import" (import x.y.Z;), "type_ref" (new Z( / Z.staticMethod( /
    extends/implements Z), "annotation" (@Z) and "method_call" (bare name(
    not defined in the same hunk).
    """
    symbols: list[dict[str, Any]] = []
    for hunk in hunks:
        if not hunk.get("supported"):
            continue
        for line_number, text in _added_lines(hunk):
            found: list[tuple[str, str]] = []
            for match in IMPORT_RE.finditer(text):
                name = match.group(1).split(".")[-1]
                if name != "*":
                    found.append((name, "import"))
            for match in ANNOTATION_RE.finditer(text):
                found.append((match.group(1), "annotation"))
            for regex in (NEW_RE, EXTENDS_RE, STATIC_CALL_RE):
                for match in regex.finditer(text):
                    found.append((match.group(1), "type_ref"))
            for match in BARE_CALL_RE.finditer(text):
                name = match.group(1)
                if name not in _CONTROL_WORDS and not _defined_in_hunk(hunk, name):
                    found.append((name, "method_call"))
            for name, kind in found:
                symbols.append({"name": name, "kind": kind,
                                "origin": {"hunk_id": hunk.get("id"), "line": line_number}})
    return symbols


def locate_in_revision(repo_args: list[str], revision: str, name: str, limit: int = MAX_MATCHES,
                       *, cwd: Path | None = None, timeout: int = 45,
                       pathspecs: Iterable[str] = DEFAULT_PATHSPECS) -> dict[str, Any]:
    """git grep a symbol at a revision (read-only, no worktree contact).

    repo_args is ["--git-dir", path] for a bare donor store or [] to run in
    the target worktree. Returns {"name", "found", "matches"} where matches
    are "path:line" strings, truncated to ``limit``. A Git failure (bad
    revision, missing objects) is reported, never raised, so one bad lookup
    cannot kill a whole pre-scan.
    """
    if cwd is None and repo_args[:1] == ["--git-dir"] and len(repo_args) > 1:
        candidate = Path(repo_args[1])
        cwd = candidate if candidate.is_dir() else None
    result = local_git(cwd or Path.cwd(), *repo_args, "grep", "-n", "-I", "-w", "-F",
                       "-e", name, revision, "--", *pathspecs, check=False, timeout=timeout)
    if result.returncode not in (0, 1):
        return {"name": name, "found": False, "matches": [], "error": result.stderr[-400:]}
    matches = []
    for line in result.stdout.splitlines():
        if revision and line.startswith(revision + ":"):
            line = line[len(revision) + 1:]
        parts = line.split(":", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            matches.append(f"{parts[0]}:{parts[1]}")
    return {"name": name, "found": bool(matches), "matches": matches[:limit]}


def nearest_symbols(name: str, candidates: Iterable[str], n: int = 3) -> list[str]:
    """difflib-based nearest-name hints (RetroPatch Levenshtein replacement)."""
    return difflib.get_close_matches(name, sorted(set(candidates)), n=n, cutoff=0.5)


def _harvest_candidates(repo_args: list[str], revision: str, name: str, *,
                        cwd: Path | None = None) -> list[str]:
    """Harvest identifier candidates sharing the name's 4-char stem."""
    if len(name) < 4:
        return []
    stem = re.escape(name[:4])
    result = local_git(cwd or Path.cwd(), *repo_args, "grep", "h", "-o", "-I", "-E",
                       "-e", rf"\b{stem}\w+", "--", revision, *DEFAULT_PATHSPECS,
                       check=False, timeout=45)
    if result.returncode not in (0, 1):
        return []
    return result.stdout.split()[:2000]


def existence_report(hunks: list[dict[str, Any]], target_repo: Path,
                     target_commit: str) -> dict[str, Any]:
    """For every referenced symbol, locate it in the target baseline.

    Returns {"missing": [...], "found": [...], "summary": str}. Import-kind
    symbols are checked through their package-mapped path first, falling
    back to a tree-wide word search. The report is capped at 8 KB.
    """
    symbols = extract_referenced_symbols(hunks)
    merged: dict[str, dict[str, Any]] = {}
    for symbol in symbols:
        entry = merged.setdefault(symbol["name"], {"name": symbol["name"], "kinds": [],
                                                   "origins": []})
        if symbol["kind"] not in entry["kinds"]:
            entry["kinds"].append(symbol["kind"])
        if len(entry["origins"]) < 5:
            entry["origins"].append(symbol["origin"])
    ordered = sorted(merged.values(),
                     key=lambda item: (min(KIND_PRIORITY.get(kind, 9) for kind in item["kinds"]),
                                       item["name"]))[:MAX_SYMBOLS]
    import_paths = {}
    for hunk in hunks:
        for _, text in _added_lines(hunk):
            match = IMPORT_RE.search(text)
            if match and "." in match.group(1):
                name = match.group(1).split(".")[-1]
                package = match.group(1).rsplit(".", 1)[0].replace(".", "/")
                import_paths.setdefault(name, package)
    found_entries, missing_entries = [], []
    for entry in ordered:
        name = entry["name"]
        located: dict[str, Any] | None = None
        if "import" in entry["kinds"] and name in import_paths:
            package = import_paths[name]
            located = locate_in_revision(
                [], target_commit, name, cwd=target_repo,
                pathspecs=(f"{package}/{name}.java", f"{package}/{name}.kt",
                           f"*{name}.java", f"*{name}.kt"))
        if located is None or not located["found"]:
            located = locate_in_revision([], target_commit, name, cwd=target_repo)
        record = {key: value for key, value in entry.items() if key != "origins"}
        if located.get("error"):
            record["error"] = located["error"]
        if located["found"]:
            record["matches"] = located["matches"]
            found_entries.append(record)
        else:
            record["origins"] = entry["origins"]
            candidates = _harvest_candidates([], target_commit, name, cwd=target_repo)
            hints = nearest_symbols(name, candidates)
            if hints:
                record["nearest"] = hints
            missing_entries.append(record)
    missing_names = [item["name"] for item in missing_entries]
    summary = (f"{len(found_entries) + len(missing_entries)} referenced symbols checked at the "
               f"target baseline: {len(found_entries)} found, {len(missing_entries)} missing"
               + (f" ({', '.join(missing_names[:10])})." if missing_names else "."))
    report = {"missing": missing_entries, "found": found_entries, "summary": summary}
    for allowed in (MAX_MATCHES, 5, 2, 0):
        for entry in report["found"]:
            entry["matches"] = entry["matches"][:allowed]
        if len(json.dumps(report, ensure_ascii=False)) <= MAX_REPORT_BYTES:
            break
    return report
