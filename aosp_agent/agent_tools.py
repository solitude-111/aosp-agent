"""Controlled read-only tools for model turns (R4/R7/R8/R9 ports).

Usage: python -m aosp_agent.agent_tools <cmd> --run-dir <dir> [params]

Four subcommands mirroring RetroPatch's tool surface (locate_symbol,
viewcode, git_history, git_show), exposed to the model as wrapper scripts
under <run_dir>/bin/. Hard constraints enforced inside every command:

- Git runs with --git-dir (donor bare store), inside the target worktree, or
  inside a declared read-only dependency repository, always with
  GIT_NO_LAZY_FETCH=1 / GIT_TERMINAL_PROMPT=0 / protocol.allow=never; no
  network access ever happens.
- --ref/--sha whitelists: only the commits recorded in run.json
  (target_commit / source_parent / source_commit) plus SHAs recorded by
  hunk-history in history-commits.jsonl.
- Paths must pass case.validate_relative_path.
- Output is truncated per command (<= 6 KB) with a trailing guidance note.
- Every invocation appends one JSON line to <run_dir>/tool-usage.jsonl.
"""
from __future__ import annotations

import argparse
from array import array
from collections import OrderedDict
import errno
from itertools import islice
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .case import validate_relative_path
from .git_policy import OFFLINE_GIT_ENV
from .patch_repair import extract_context, find_most_similar_block
from . import symbols

MAX_OUTPUT_BYTES = 6144
MAX_VIEW_LINES = 400
HISTORY_TAIL_BYTES = 5000
STAT_LIMIT = 3000
USAGE_MARKER = "AOSP-TOOL-USAGE "
DEEPEN_HINT = ("NOT_AVAILABLE: donor history does not cover the target..source_parent range "
               "for this hunk. Ask the operator to run scripts/deepen_donor.sh once "
               "(user-manual step; the agent never fetches).")


def _git(repo_args: list[str], *args: str, cwd: Path | None = None,
         check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    from .retrieval import ACTIVE_BUDGET
    budget = ACTIVE_BUDGET.get()
    if budget is not None:
        timeout = budget.command_timeout(timeout)
    env = {**OFFLINE_GIT_ENV, "PATH": "/usr/bin:/bin",
           "HOME": str(Path.home()), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    if sys.platform == 'darwin' and os.environ.get('AOSP_AGENT_GIT_LIBRARY_PATH'):
        env['DYLD_LIBRARY_PATH'] = os.environ['AOSP_AGENT_GIT_LIBRARY_PATH']
    git_binary = os.environ.get('AOSP_AGENT_GIT_BIN') or shutil.which('git')
    if not git_binary:
        raise ToolError('Git executable is unavailable')
    from .tool_io import ACTIVE_TOOL_IO
    io = ACTIVE_TOOL_IO.get()
    run = io.run if io is not None else subprocess.run
    return run([git_binary, "-c", "protocol.allow=never", "-c", "core.hooksPath=/dev/null",
                           *repo_args, *args], cwd=cwd, text=True, capture_output=True,
                          check=check, env=env, timeout=timeout)


class ToolError(Exception):
    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


def _optional_log(path, text):
    """Legacy readonly wrappers report markers when sandbox forbids logs.

    Only a permission denial or read-only mount permits this fallback. Exhaustion, corruption and
    other storage failures must still stop work; the controller captures the
    stdout marker under its own output budget.
    """
    from .output_budget import write_text, OutputBudgetUnavailable
    try:
        write_text(path, text, append=True)
    except (OSError, OutputBudgetUnavailable) as exc:
        cause = exc.__cause__ if isinstance(exc, OutputBudgetUnavailable) else exc
        if not (isinstance(cause, PermissionError)
                or isinstance(cause, OSError) and cause.errno == errno.EROFS):
            raise


class RunContext:
    def __init__(self, run_dir: Path, *, record=None, inspection=None, output_sink=None):
        self.run_dir = run_dir.resolve()
        record_path = self.run_dir / "run.json"
        inspection_path = self.run_dir / "inspection.json"
        if (record is None and not record_path.is_file()) or (inspection is None and not inspection_path.is_file()):
            raise ToolError(f"run directory is not prepared: {self.run_dir}")
        self.record = json.loads(record_path.read_text()) if record is None else record
        self.inspection = json.loads(inspection_path.read_text()) if inspection is None else inspection
        self.output_sink = output_sink
        self.worktree = Path(self.record['worktree']) if self.record.get('worktree') else None
        self.target_repositories = self.record.get('tool_target_repositories', {})
        self.donor_git = self.record.get("donor_git")
        self.source_repositories = self.record.get('tool_source_repositories', {})
        self.allowed_refs = {self.record[name] for name in
                             ("target_commit", "source_parent", "source_commit")
                             if self.record.get(name)}
        self.dependency_repositories = self.record.get("dependency_repositories", {})
        self.hunks = {hunk["id"]: hunk for hunk in self.inspection.get("hunks", [])}

    def history_shas(self) -> set[str]:
        path = self.run_dir / "history-commits.jsonl"
        shas = set()
        if path.is_file():
            for line in path.read_text().splitlines():
                try:
                    shas.add(json.loads(line)["sha"])
                except (ValueError, KeyError):
                    continue
        return shas

    def record_history_shas(self, shas: list[str], hunk_id: str) -> None:
        # Best-effort (sandbox may deny); the usage marker carries the SHAs
        # for the controller's post-turn sweep.
        path = self.run_dir / "history-commits.jsonl"
        _optional_log(path, ''.join(json.dumps({"sha": sha, "hunk_id": hunk_id}) + "\n" for sha in shas))

    def repo_selection(self, repo: str) -> tuple[list[str], Path | None]:
        if repo.startswith('donor:'):
            entry = self.source_repositories.get(repo.split(':', 1)[1])
            if entry is None:
                raise ToolError('unknown source step: ' + repo)
            return ['--git-dir', entry['donor_git']], None
        if repo.startswith('target:'):
            key = repo.split(':', 1)[1]
            entry = self.target_repositories.get(key)
            if entry is None:
                raise ToolError('unknown target repository: ' + key)
            root = Path(entry['root'])
            if not root.is_dir():
                raise ToolError('target repository unavailable: ' + key)
            return [], root
        if repo == "target":
            if self.worktree is None:
                raise ToolError('ambiguous target; use target:<repository-key>')
            if not self.worktree.is_dir():
                raise ToolError("target worktree is missing")
            return [], self.worktree
        if repo == "donor":
            if not self.donor_git:
                raise ToolError("this run has no separate donor store")
            return ["--git-dir", self.donor_git], None
        if repo.startswith("dependency:"):
            key = repo.split(":", 1)[1]
            dependency = self.dependency_repositories.get(key)
            if dependency is None:
                raise ToolError(f"unknown read-only dependency repository: {key}")
            root = Path(dependency["root"])
            if not root.is_dir():
                raise ToolError(f"read-only dependency repository is missing: {key}")
            return [], root
        raise ToolError("--repo must be target:<repository-key>, target, donor, or dependency:<repository-path>")

    def bind_history_target(self, key=None):
        """History ranges must belong to the explicitly selected target project."""
        if key is None:
            if self.target_repositories and len(self.target_repositories) > 1:
                raise ToolError('multi-repository history requires --target-repo <repository-key>')
            return
        entry = self.target_repositories.get(key)
        if entry is None:
            raise ToolError('unknown history target repository: ' + key)
        self.worktree = Path(entry['root'])
        self.record['target_commit'] = entry['head']
        self.allowed_refs.add(entry['head'])

    def bind_source(self, source_id=None, hunk_id=None):
        if not self.source_repositories:
            return
        if hunk_id in self.hunks:
            expected = self.hunks[hunk_id].get('source_id')
            if source_id and source_id != expected:
                raise ToolError('source step does not own the requested hunk')
            source_id = expected
        entry = self.source_repositories.get(source_id)
        if entry is None:
            raise ToolError('multi-source history requires --source-step or a source-owned hunk ID')
        self.donor_git = entry['donor_git']
        self.record.update({k: entry[k] for k in ('source_commit', 'source_parent', 'donor_git')})
        self.allowed_refs.update((entry['source_commit'], entry['source_parent']))

    def check_ref(self, ref: str, repo: str = "target") -> str:
        if repo.startswith('donor:'):
            entry = self.source_repositories.get(repo.split(':', 1)[1])
            if entry is None or ref not in (entry['source_commit'], entry['source_parent']):
                raise ToolError('ref is not pinned for source step ' + repo)
            return ref
        if repo.startswith('target:'):
            entry = self.target_repositories.get(repo.split(':', 1)[1])
            if entry is None or ref != entry['head']:
                raise ToolError('ref is not the pinned commit for ' + repo)
            return ref
        if repo == 'target' and self.target_repositories:
            if len(self.target_repositories) != 1:
                raise ToolError('ambiguous target; use target:<repository-key>')
            if ref != next(iter(self.target_repositories.values()))['head']:
                raise ToolError('ref is not the pinned target commit')
            return ref
        if repo.startswith("dependency:"):
            key = repo.split(":", 1)[1]
            dependency = self.dependency_repositories.get(key)
            allowed = {dependency["head"]} if dependency else set()
            if ref not in allowed:
                raise ToolError(f"--ref is not the pinned HEAD for {key}: {ref}")
            return ref
        if repo not in ("target", "donor"):
            raise ToolError("invalid repository selector")
        if ref not in self.allowed_refs and ref not in self.history_shas():
            raise ToolError(f"--ref is not whitelisted for this run: {ref}")
        return ref

    def check_sha(self, sha: str) -> str:
        if sha in self.allowed_refs or sha in self.history_shas():
            return sha
        # The Codex sandbox blocks cross-process file writes inside a turn,
        # so SHAs reported by hunk-history in the SAME turn cannot reach
        # history-commits.jsonl before show-commit runs. Range-bounded
        # acceptance keeps the chain usable without enabling free history
        # roaming: only commits inside the donor's own target..fix window
        # (or ancestors of the fix parent when the target is not present)
        # are accepted, verified read-only against the donor store.
        if self._in_donor_range(sha):
            return sha
        raise ToolError(f"--sha is not whitelisted for this run: {sha}")

    def _in_donor_range(self, sha: str) -> bool:
        if not self.donor_git or not re.fullmatch(r"[0-9a-f]{4,64}", sha):
            return False
        exists = _git(["--git-dir", self.donor_git], "cat-file", "-e", f"{sha}^{{commit}}",
                      check=False)
        if exists.returncode != 0:
            return False
        parent = self.record.get("source_parent")
        ancestor = _git(["--git-dir", self.donor_git], "merge-base", "--is-ancestor",
                        sha, parent, check=False)
        if ancestor.returncode != 0:
            return False
        target = self.record.get("target_commit")
        has_target = _git(["--git-dir", self.donor_git], "cat-file", "-e",
                          f"{target}^{{commit}}", check=False)
        if has_target.returncode != 0:
            return True
        before_target = _git(["--git-dir", self.donor_git], "merge-base", "--is-ancestor",
                             sha, target, check=False)
        return before_target.returncode != 0

    def hunk_paths(self) -> set[str]:
        return {hunk.get("path") for hunk in self.hunks.values() if hunk.get("path")}


def _truncate_head(text: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    if len(text) <= limit:
        return text
    return text[:limit - 120] + f"\n...[output truncated, {len(text) - limit + 120} characters omitted]\n"


def _truncate_tail(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return "...[output truncated, oldest entries kept]\n" + text[-limit:]


def _finish(ctx: RunContext, cmd: str, args, output: str, code: int = 0,
            extra: dict | None = None) -> int:
    if ctx.output_sink is None:
        sys.stdout.write(output if output.endswith("\n") or not output else output + "\n")
    entry = {"time": time.time(), "cmd": cmd, "uid": uuid.uuid4().hex[:12],
             "args": {key: str(value) for key, value in args._get_kwargs()
                      if value is not None and key != "run_dir"},
             "returncode": code, "bytes_out": len(output.encode(errors="replace"))}
    if extra:
        entry.update(extra)
    # Best-effort durable log. Under the Codex sandbox this write is denied
    # (run_dir lies outside the sandboxed workspace); the stdout marker below
    # is always emitted and the controller sweeps it from sdk-events into
    # tool-usage.jsonl after the turn, so no invocation goes unlogged.
    if ctx.output_sink is None:
        _optional_log(ctx.run_dir / "tool-usage.jsonl", json.dumps(entry, ensure_ascii=False) + "\n")
        sys.stdout.write(USAGE_MARKER + json.dumps(entry, ensure_ascii=False) + "\n")
    else:
        ctx.output_sink(output, entry)
    return code


def cmd_locate_symbol(ctx: RunContext, args, *, pathspecs=None, timeout=45) -> int:
    ref = ctx.check_ref(args.ref, args.repo)
    validate_symbol = re.fullmatch(r"[A-Za-z_$][\w$]*", args.symbol or "")
    if not validate_symbol:
        raise ToolError("--symbol must be a plain identifier")
    repo_args, cwd = ctx.repo_selection(args.repo)
    scoped = pathspecs is not None
    if not scoped:
        languages = getattr(args, 'language', None)
        pathspecs = (tuple(dict.fromkeys(p for lang in languages for p in symbols.LANGUAGE_PATHSPECS[lang]))
                     if languages else symbols.DEFAULT_PATHSPECS)
    located = symbols.locate_in_revision(repo_args, ref, args.symbol, cwd=cwd,
                                         pathspecs=pathspecs, timeout=timeout)
    scope = 'Search scope: ' + ', '.join(pathspecs) + '; lexical identifiers at the pinned revision.\n'
    if located['status'] == 'READ_FAILED':
        status = 'SEARCH_INCOMPLETE' if scoped and located.get('reason') == 'TIMEOUT' else 'READ_FAILED'
        output = (f"{status} at {args.repo} {ref}:\n{located['error']}\n" + scope +
                  "Symbol and operation existence remain unknown.")
        return _finish(ctx, "locate-symbol", args, output, code=3,
                       extra={'read_status': 'READ_FAILED', 'reason': located.get('reason'),
                              'search_scope': located['scope']})
    if located["found"]:
        output = (f"Symbol {args.symbol} at {args.repo}/{ref}:\n"
                  + "\n".join(located["matches"][:20])
                  + "\nUse view-code to read any of these locations before editing.\n")
    else:
        output = (f"NOT_FOUND_IN_SCOPE: {args.symbol} at {args.repo}/{ref}.\n"
                  "This is not proof that the symbol or equivalent operation is absent.\n")
        if scoped:
            output += 'If needed, use a specific wider directory or hunk-history.\n'
            return _finish(ctx, "locate-symbol", args, output + scope, code=0,
                           extra={'read_status': located['status'], 'search_scope': located['scope']})
        try:
            candidates = symbols._harvest_candidates(repo_args, ref, args.symbol, cwd=cwd, pathspecs=pathspecs)
        except (OSError, subprocess.SubprocessError):
            candidates = []  # Optional spelling hints do not change the primary lookup.
        nearest = symbols.nearest_symbols(args.symbol, candidates)
        if nearest:
            output += ("Nearest existing names (check carefully whether one is the "
                       f"renamed counterpart): {', '.join(nearest)}.\n")
        else:
            output += "No similarly named symbol was found nearby.\n"
        output += "If the code was renamed or moved, use hunk-history to trace it.\n"
    return _finish(ctx, "locate-symbol", args, output + scope,
                   extra={'read_status': located['status'], 'search_scope': located['scope']})


class _SourceLines:
    _stride = 128

    def __init__(self, text: str):
        self.text = text
        self.line_count = text.count("\n") + 1
        self.offsets = array('I', [0])
        # Store a character offset every 128 lines, including for dense files.
        boundaries = islice(re.finditer("\n", text), self._stride - 1, None, self._stride)
        self.offsets.extend(match.end() for match in boundaries)

    def _offset(self, line: int) -> int:
        block, remaining = divmod(line - 1, self._stride)
        offset = self.offsets[block]
        for _ in range(remaining):
            offset = self.text.index("\n", offset) + 1
        return offset

    def slice(self, start: int, end: int) -> str:
        stop = self._offset(end + 1) - 1 if end < self.line_count else len(self.text)
        return self.text[self._offset(start):stop]


class SourceViewCache:
    """Bounded in-memory line index for successful pinned source views."""

    def __init__(self, max_bytes: int = 32 * 1024 * 1024, max_entries: int = 128):
        self.max_bytes = max_bytes
        self.max_entries = max_entries
        self._bytes = 0
        self._entries = OrderedDict()

    def get(self, key) -> _SourceLines | None:
        if key not in self._entries:
            return None
        self._entries.move_to_end(key)
        return self._entries[key][0]

    def add(self, key, text: str) -> _SourceLines | None:
        size = sys.getsizeof(text)
        if size >= self.max_bytes:
            return None
        source = _SourceLines(text)
        size += sys.getsizeof(source.offsets)
        if size > self.max_bytes:
            return None
        while self._bytes + size > self.max_bytes or len(self._entries) >= self.max_entries:
            _, (_, removed_size) = self._entries.popitem(last=False)
            self._bytes -= removed_size
        self._entries[key] = (source, size)
        self._bytes += size
        return source

    def clear(self) -> None:
        self._entries.clear()
        self._bytes = 0


def cmd_view_code(ctx: RunContext, args, *, cache: SourceViewCache | None = None) -> int:
    ref = ctx.check_ref(args.ref, args.repo)
    try:
        path = validate_relative_path(args.path)
    except ValueError as exc:
        raise ToolError(str(exc)) from exc
    if args.start < 1 or args.end < args.start:
        raise ToolError("--start/--end must describe a 1-based ascending range")
    repo_args, cwd = ctx.repo_selection(args.repo)
    source = None
    if cache is not None:
        root = cwd if cwd is not None else Path(repo_args[1])
        key = (cwd is None, root.resolve(), ref, path)
        source = cache.get(key)
    if source is None:
        blob = _read_view_blob(ctx, args, repo_args, cwd, ref, path)
        if isinstance(blob, int):
            return blob
        if cache is not None:
            source = cache.add(key, blob)
        if source is None:
            lines = blob.split("\n")
    line_count = source.line_count if source is not None else len(lines)
    start, end = args.start, args.end
    notes = []
    if end - start + 1 > MAX_VIEW_LINES:
        end = start + MAX_VIEW_LINES - 1
        notes.append(f"range clamped to {MAX_VIEW_LINES} lines per call")
    if end > line_count:
        start = max(1, start - (end - line_count))
        end = line_count
        notes.append(f"this file only has {line_count} lines; window moved up to lines {start}-{end}")
    body = source.slice(start, end) if source is not None else "\n".join(lines[start - 1:end])
    header = f"Here are lines {start} through {end} of {path} at {args.repo}/{ref}."
    if notes:
        header += " (" + "; ".join(notes) + ")"
    output = (header + "\n" + body + "\n"
              "Based on the previous information, think carefully: do you see the target code? "
              "Keep checking with further calls if not.\n")
    return _finish(ctx, "view-code", args, _truncate_head(output))


def _read_view_blob(ctx, args, repo_args, cwd, ref, path) -> str | int:
    try:
        blob = _git(repo_args, "show", f"{ref}:{path}", cwd=cwd, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return _finish(ctx, 'view-code', args, 'READ_FAILED: ' + type(exc).__name__
                       + '; file existence and affectedness remain unknown.', 3,
                       extra={'read_status': 'READ_FAILED'})
    if blob.returncode != 0:
        try:
            tree = _git(repo_args, 'ls-tree', '-z', ref, '--', path, cwd=cwd, check=False)
        except (OSError, subprocess.SubprocessError):
            tree = None
        if tree is not None and tree.returncode == 0 and not tree.stdout:
            return _finish(ctx, 'view-code', args,
                f'PATH_ABSENT: {args.repo}/{ref}:{path}. The pinned tree has no such path.\n'
                'This does not establish absence of the operation; inspect moved/equivalent implementations.',
                extra={'read_status': 'PATH_ABSENT'})
        return _finish(ctx, 'view-code', args,
            'READ_FAILED: Git could not read the requested object. File existence and affectedness remain unknown.\n'
            + blob.stderr[-1000:], 3, extra={'read_status': 'READ_FAILED'})
    return blob.stdout


def _line_range_log(ctx: RunContext, hunk: dict) -> subprocess.CompletedProcess:
    """git log -L over the donor hunk's old line range (R7)."""
    start = hunk.get("old_start") or 1
    count = hunk.get("old_count") or 0
    if count <= 0:
        raise ToolError("hunk has no old lines to trace")
    end = start + count - 1
    return _git(["--git-dir", ctx.donor_git], "log", f"--format=%H", "-L",
                f"{start},{end}:{hunk['path']}",
                f"{ctx.record['target_commit']}..{ctx.record['source_parent']}",
                check=False)


def _add_percent_of_last_block(log_text: str) -> float:
    """Ratio of added lines in the LAST diff block of a git log -L output (R7)."""
    blocks = re.split(r"(?m)^[0-9a-f]{40}$", log_text)
    last = blocks[-1] if blocks else ""
    contexts, added = extract_context(
        [line for line in last.splitlines()
         if line.startswith((" ", "-", "+")) and not line.startswith(("---", "+++"))])
    total = len(contexts) + len(added)
    return len(added) / total if total else 0.0


def _hunk_history_data(ctx: RunContext, hunk_id: str) -> tuple[dict, str, list[str], float]:
    hunk = ctx.hunks.get(hunk_id)
    if hunk is None or not hunk.get("path"):
        raise ToolError(f"unknown hunk id: {hunk_id}")
    if hunk["path"] not in ctx.hunk_paths() | set(ctx.inspection.get("case_files", [])):
        raise ToolError("hunk path is outside the case scope")
    if not ctx.donor_git:
        raise ToolError("this run has no donor store for history")
    has_target = _git(["--git-dir", ctx.donor_git], "cat-file", "-e",
                      f"{ctx.record['target_commit']}^{{commit}}", check=False)
    log = _line_range_log(ctx, hunk) if has_target.returncode == 0 else None
    if log is None or log.returncode != 0 or not log.stdout.strip():
        raise ToolError(DEEPEN_HINT, code=0)
    shas = re.findall(r"(?m)^([0-9a-f]{40})$", log.stdout)
    if shas:
        _metadata, _parents, boundary = _history_commit_metadata(ctx, shas[-1])
        if boundary:
            raise ToolError('HISTORY_INCOMPLETE: line history reaches a shallow/grafted boundary. '
                            'Its apparent additions do not establish code introduction or target absence. '
                            'Use pinned source views; additional history requires operator action.', code=0)
    add_percent = _add_percent_of_last_block(log.stdout)
    return hunk, log.stdout, shas, add_percent


def cmd_hunk_history(ctx: RunContext, args) -> int:
    hunk, log_text, shas, add_percent = _hunk_history_data(ctx, args.hunk_id)
    if shas:
        ctx.record_history_shas(shas, args.hunk_id)
    body = _truncate_tail(log_text, HISTORY_TAIL_BYTES)
    output = (f"Change history of donor hunk {args.hunk_id} ({hunk['path']}) between the "
              f"target baseline and the donor fix parent:\n{body}\n"
              f"Commits touching this range (newest first): {', '.join(shas[:10])}\n"
              f"Added-line ratio in the last change: {add_percent:.2f}\n"
              "You need to analyze the last commit above:\n"
              "- If the code logic already existed before it, the patch context stays in a "
              "similar location; confirm with locate-symbol and view-code.\n"
              "- If the code was added in it, use show-commit for further details.\n")
    return _finish(ctx, "hunk-history", args, _truncate_head(output),
                   extra={"hunk_path": hunk["path"], "history_shas": shas[:20]})


def _history_commit_metadata(ctx, sha):
    """Read actual parents, independently of Git's shallow traversal view."""
    raw = _git(["--git-dir", ctx.donor_git], "cat-file", "commit", sha, check=False)
    if raw.returncode:
        raise ToolError(f"cannot read commit metadata for {sha}: {raw.stderr[-200:]}")
    header, _, message = raw.stdout.partition("\n\n")
    parents = [line.split()[1] for line in header.splitlines() if line.startswith('parent ')]
    traversal = _git(["--git-dir", ctx.donor_git], 'rev-list', '--parents', '-n', '1', sha, check=False)
    if traversal.returncode:
        raise ToolError('cannot establish commit history boundary')
    boundary = traversal.stdout.split()[1:] != parents
    subject = message.splitlines()[0] if message.splitlines() else ''
    text = f"commit {sha}\nParents: {', '.join(parents) or '(root)'}\nSubject: {subject[:STAT_LIMIT]}\n"
    return text, parents, boundary


def cmd_show_commit(ctx: RunContext, args) -> int:
    sha = ctx.check_sha(args.sha)
    if not ctx.donor_git:
        raise ToolError("this run has no donor store for history")
    hunk = None
    if args.hunk_id:
        hunk = ctx.hunks.get(args.hunk_id)
        if not hunk or hunk.get('path') not in ctx.hunk_paths() | set(ctx.inspection.get('case_files', [])):
            raise ToolError(f"unknown or out-of-scope hunk id: {args.hunk_id}")
        validate_relative_path(hunk['path'])
    text, parents, boundary = _history_commit_metadata(ctx, sha)
    extra = {'commit_parents': parents, 'history_boundary': boundary, 'absence_proven': False}
    if boundary:
        # A shallow commit can look like a repository-wide addition even when
        # its parent objects exist locally. Never use that synthetic diff as
        # evidence of when code was introduced, and never fetch automatically.
        extra['read_status'] = 'HISTORY_INCOMPLETE'
        return _finish(ctx, 'show-commit', args, _truncate_head(text +
            'HISTORY_INCOMPLETE: Git traversal stops at this shallow/grafted boundary. '
            'No introduction or absence conclusion is justified. Use view-code at the pinned '
            'commit for file contents; missing history requires operator action.\n'), extra=extra)
    if hunk is None:
        extra['read_status'] = 'METADATA_ONLY'
        return _finish(ctx, 'show-commit', args, _truncate_head(text +
            'METADATA_ONLY: provide hunk_id for a path-scoped diff; no repository-wide diff was read.\n'), extra=extra)
    path = hunk['path']; extra['path_scope'] = path
    if len(parents) > 1:
        extra['read_status'] = 'MERGE_REQUIRES_PARENT'
        return _finish(ctx, 'show-commit', args, _truncate_head(text +
            'MERGE_REQUIRES_PARENT: this is a merge, not a single-parent change. '
            'No combined diff or introduction inference is supplied. Inspect the pinned file and history.\n'), extra=extra)
    # Bound the input before asking Git to construct a patch, including large
    # single-file changes. The broker's existing process/task limits still apply.
    total = 0
    for revision in [sha, *parents]:
        entry = _git(['--git-dir', ctx.donor_git], 'ls-tree', '-l', revision,
                     '--', ':(literal)' + path, check=False)
        if entry.returncode:
            raise ToolError('cannot inspect scoped historical blob size')
        for row in entry.stdout.splitlines():
            fields = row.split('\t', 1)[0].split()
            if len(fields) != 4 or fields[1] != 'blob' or not fields[3].isdigit():
                raise ToolError('historical hunk path is not an ordinary blob')
            total += int(fields[3])
    if total > 512 * 1024:
        extra['read_status'] = 'SCOPED_DIFF_DEFERRED'
        return _finish(ctx, 'show-commit', args, _truncate_head(text +
            f'SCOPED_DIFF_DEFERRED: {path} exceeds the bounded diff input size. '
            'Use targeted source views; this is not evidence of absence.\n'), extra=extra)
    diff = _git(['--git-dir', ctx.donor_git], 'show', '--format=', '--root', '--no-renames',
                '--no-ext-diff', '--no-textconv', '--unified=3', sha, '--', ':(literal)' + path, check=False)
    if diff.returncode:
        raise ToolError(f'cannot read scoped commit diff: {diff.stderr[-200:]}')
    output = (text + f'Path scope: {path}; other paths were not searched. '
              'A missing match does not prove the operation was absent or newly introduced.\n' + diff.stdout +
              '\nUse view-code for source context. Large replies may be truncated below.\n')
    extra.update(read_status='SCOPED_DIFF', diff_complete=len(output.encode('utf-8')) <= MAX_OUTPUT_BYTES)
    return _finish(ctx, 'show-commit', args, _truncate_head(output), extra=extra)


def _locate_block_in_commit(show_text: str, context_lines: list[str]):
    """Most-similar block of the commit diff for the hunk context (R8)."""
    if not context_lines:
        return None
    best = None
    best_distance = None
    current_path = None
    block_lines: list[str] = []
    old_start = None

    def consider():
        nonlocal best, best_distance
        if current_path is None or not block_lines:
            return
        contexts, _ = extract_context(
            [line for line in block_lines if not line.startswith(("+++", "---"))])
        if len(contexts) < len(context_lines):
            return
        line, distance = find_most_similar_block(context_lines, contexts, len(context_lines))
        if best_distance is None or distance < best_distance:
            best_distance = distance
            best = (current_path, (old_start or 1) + line - 1,
                    "\n".join(contexts[line - 1:line - 1 + len(context_lines)]))

    lines = show_text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("+++ b/"):
            consider()
            current_path = line[6:]
            block_lines = []
            old_start = None
        elif line.startswith("@@") and current_path is not None:
            consider()
            match = re.match(r"@@ -(\d+)", line)
            old_start = int(match.group(1)) if match else None
            block_lines = []
        elif current_path is not None and line.startswith((" ", "+", "-")):
            block_lines.append(line)
        index += 1
    consider()
    return best


def _write_wrappers(run_dir: Path) -> None:
    """Generate the four thin wrapper scripts for model turns (P2.2)."""
    # These read tools depend only on the standard library. Use the actual
    # interpreter executable, avoiding virtualenv launcher symlinks that can
    # traverse unreadable aliases under a restricted filesystem profile.
    python = Path(sys.executable).resolve()
    git_binary = shutil.which('git')
    if not git_binary:
        raise ToolError('Git executable is unavailable')
    git_binary = Path(git_binary).resolve()
    from .sandbox_scope import git_library_path
    library_env = shlex.quote('AOSP_AGENT_GIT_LIBRARY_PATH=' + git_library_path(git_binary))
    # Copy only agent Python modules into this run's readable surface. Importing
    # a package from an otherwise denied project parent can fail, while granting
    # that parent would expose datasets, sibling runs and local documents.
    project_root = run_dir / 'tool-runtime'
    package = project_root / 'aosp_agent'
    package.mkdir(parents=True, exist_ok=True)
    for source in Path(__file__).resolve().parent.glob('*.py'):
        from .output_budget import write_bytes
        write_bytes(package / source.name, source.read_bytes())
    bin_dir = run_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for command in ("locate-symbol", "view-code", "hunk-history", "show-commit"):
        script = (f"#!/usr/bin/env bash\n"
                  f"exec env {shlex.quote('PYTHONPATH=' + str(project_root))} "
                  f"{shlex.quote('AOSP_AGENT_GIT_BIN=' + str(git_binary))} {library_env} "
                  f"{shlex.quote(str(python))} -m aosp_agent.agent_tools "
                  f"--run-dir {shlex.quote(str(run_dir.resolve()))} {command} \"$@\"\n")
        path = bin_dir / command
        from .output_budget import write_text
        write_text(path, script)
        path.chmod(0o755)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aosp_agent.agent_tools",
                                     description="Controlled read-only backport tools")
    parser.add_argument("--run-dir", type=Path, required=True)
    sub = parser.add_subparsers(dest="cmd", required=True)
    locate = sub.add_parser("locate-symbol")
    locate.add_argument("--repo", required=True)
    locate.add_argument("--ref", required=True)
    locate.add_argument("--symbol", required=True)
    locate.add_argument('--language', choices=sorted(symbols.LANGUAGE_PATHSPECS), action='append',
                        help='Limit the searched source languages (repeatable); omitted searches all supported source extensions')
    view = sub.add_parser("view-code")
    view.add_argument("--repo", required=True)
    view.add_argument("--ref", required=True)
    view.add_argument("--path", required=True)
    view.add_argument("--start", type=int, required=True)
    view.add_argument("--end", type=int, required=True)
    history = sub.add_parser("hunk-history")
    history.add_argument("--hunk-id", required=True)
    history.add_argument('--target-repo')
    show = sub.add_parser("show-commit")
    show.add_argument("--sha", required=True)
    show.add_argument("--hunk-id")
    show.add_argument('--target-repo')
    show.add_argument('--source-step')
    args = parser.parse_args(argv)
    ctx = None
    try:
        ctx = RunContext(args.run_dir)
        if args.cmd in ('hunk-history', 'show-commit'):
            ctx.bind_history_target(args.target_repo)
            ctx.bind_source(getattr(args, 'source_step', None), getattr(args, 'hunk_id', None))
        handler = {"locate-symbol": cmd_locate_symbol, "view-code": cmd_view_code,
                   "hunk-history": cmd_hunk_history, "show-commit": cmd_show_commit}[args.cmd]
        return handler(ctx, args)
    except (ToolError, OSError, subprocess.SubprocessError) as exc:
        code = getattr(exc, 'code', 3)
        print(f"error: {exc}", file=sys.stderr)
        if ctx is not None:
            entry = {"time": time.time(), "cmd": args.cmd, "uid": uuid.uuid4().hex[:12],
                     "args": {key: str(value) for key, value in args._get_kwargs()
                              if value is not None and key != "run_dir"},
                     "returncode": code, "bytes_out": 0,
                     "rejected": str(exc)[:200]}
            _optional_log(ctx.run_dir / "tool-usage.jsonl", json.dumps(entry, ensure_ascii=False) + "\n")
            print(USAGE_MARKER + json.dumps(entry, ensure_ascii=False))
        return code


if __name__ == "__main__":
    raise SystemExit(main())
