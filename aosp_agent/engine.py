from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable

from .case import Case, validate_relative_path
from .impact_proof import AssessmentError, CausalityChecks
from .lifecycle import source_guard
from .execution_budget import controller_audit
from .git_policy import OFFLINE_GIT_ENV, offline_git_env
from .diagnosis import apply_diagnosis, verification_diagnosis
from .ladder import ladder_plan, strategy_prompt
from .patch_repair import repair_hunk
from .patches import split_hunks, text_hunks
from .path_mapping import version_normalized_paths as _version_normalized_paths
from .validation_process import run_check
from .prompts import (IMPACT_SCHEMA, POST_FIX_SCHEMA, SYSTEM, backport_prompt,
                      impact_prompt, parse_impact_response, post_fix_prompt)
from . import symbols

_HUNK_RESULT_RE = re.compile(
    r"^\s*HUNK-RESULT\s+(\S+)\s+(implemented|need_not_ported):?\s+(.+?)\s*$", re.MULTILINE)
_VERSION_LINE_RE = re.compile(
    r'^(?:(?:#\s*define\s+(?:SQLITE_VERSION|SQLITE_VERSION_NUMBER|SQLITE_SOURCE_ID)\s+|'
    r'(?:VERSION|PATCHLEVEL)\s*=\s*)(?:[0-9.]+|"[A-Za-z0-9_. :+-]+")|'
    r'(?:static\s+)?(?:const\s+)?char\s+version\s*\[\s*\]\s*=\s*"[A-Za-z0-9_. :+-]+"\s*;)$', re.I)
_SEMANTIC_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)*")
_LINE_COMMENT_RE = re.compile(r"//.*$")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/")
_COMMON_DIFF_TOKENS = {
    "const", "else", "false", "for", "if", "int", "new", "null", "return",
    "static", "true", "void", "while",
}
_TEST_PATH_COMPONENTS = {
    "benchmark", "benchmarks", "fuzz", "fuzzer", "fuzzers", "sample",
    "samples", "test", "testdata", "test_data", "testing", "tests",
}
_DECLARED_SOURCE_IDENTIFIER_RE = re.compile(
    r"\b(?:class|enum|interface|object|record|struct|trait)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)


def _changed_diff_lines(patch: str, added: bool) -> list[str]:
    prefix = "+" if added else "-"
    return [line['text'].strip() for hunk in text_hunks(patch)
            for line in hunk['lines'] if line['marker'] == prefix]


def _normalized_code_line(line: str) -> str:
    return " ".join(line.split())


def _semantic_tokens(lines: list[str]) -> set[str]:
    tokens = {
        match.group(0)
        for line in lines
        for match in _SEMANTIC_TOKEN.finditer(line)
    }
    return {token for token in tokens if token.lower() not in _COMMON_DIFF_TOKENS}


def _context_diff_lines(patch: str) -> list[str]:
    return [line['text'].strip() for hunk in text_hunks(patch)
            for line in hunk['lines'] if line['marker'] == ' ']


def _strip_comments(line: str) -> str:
    return _BLOCK_COMMENT_RE.sub(" ", _LINE_COMMENT_RE.sub("", line))


def _coverage_code_line(line: str) -> str:
    code = _strip_comments(line).strip()
    if code.startswith(('/*', '*', '*/', '<!--', '-->')) or not re.search(r'[\w$]', code):
        return ''
    return _normalized_code_line(code)


def _added_code_lines(patch: str) -> list[str]:
    """Added lines that are not plainly comments or language imports."""
    result = []
    for line in _changed_diff_lines(patch, added=True):
        code = _strip_comments(line).strip()
        if (not code or code.startswith(("/*", "*", "*/", "<!--", "-->"))
                or (code.startswith("#") and not code.startswith("#include"))
                or re.match(r"^(?:import|package)\b|^from\s+\S+\s+import\b", code)):
            continue
        result.append(code)
    return result


def _is_test_or_fixture_path(path: str) -> bool:
    parts = {part.lower() for part in Path(path).parts}
    name = Path(path).name.lower()
    stem = Path(path).stem
    return (bool(parts & _TEST_PATH_COMPONENTS)
            or name.startswith("test_") or Path(path).stem.lower().endswith("_test")
            or stem.endswith(("Test", "Tests")))


def _is_build_only_path(path: str) -> bool:
    name = Path(path).name
    return (name in {"Android.bp", "Android.mk", "BUILD", "BUILD.bazel", "CMakeLists.txt"}
            or name.endswith((".bp", ".mk", ".bzl")))


def _new_source_identities(path: str, patch_chunks: list[dict[str, Any]]) -> set[str]:
    """Stable names an existing live file can use to activate a new source file."""
    identities = {Path(path).stem, Path(path).name}
    for chunk in patch_chunks:
        for line in _added_code_lines(chunk.get("patch", "")):
            match = _DECLARED_SOURCE_IDENTIFIER_RE.search(line)
            if match:
                identities.add(match.group(1))
    return {identity for identity in identities if identity}


_EVIDENCE_TAG_RE = re.compile(r"\b(?:evidence|tools|controller)=\S+")


def _brace_paths(lines: list[str]) -> list[tuple[int, ...]]:
    """Map each line to the chain of 1-based open-brace line numbers around it.

    Two lines share an execution path only when one chain is a prefix of the
    other; sibling chains under the same parent are mutually exclusive
    branches. Braces inside strings can misattribute a path, so callers use
    this only to falsify claims, never to accept them on faith.
    """
    paths: list[tuple[int, ...]] = []
    stack: list[int] = []
    for number, line in enumerate(lines, start=1):
        paths.append(tuple(stack))
        for character in _strip_comments(line):
            if character == "{":
                stack.append(number)
            elif character == "}" and stack:
                stack.pop()
    return paths


def _covers_path(mechanism: tuple[int, ...], anchor: tuple[int, ...]) -> bool:
    return len(mechanism) <= len(anchor) and mechanism == anchor[:len(mechanism)]


def _claim_mechanism_tokens(reason: str, hunk_patch: str) -> set[str]:
    """Identifiers a claim introduces as its equivalent-mechanism evidence."""
    prose = _EVIDENCE_TAG_RE.sub(" ", reason)
    known = _semantic_tokens(
        _changed_diff_lines(hunk_patch, added=True)
        + _changed_diff_lines(hunk_patch, added=False)
        + _context_diff_lines(hunk_patch))
    return {
        token for token in _semantic_tokens([prose]) - known
        if ("_" in token or any(char.isupper() for char in token[1:])
            or len(token) >= 8)
        and token not in {"implemented", "need_not_ported"}
    }


def _novel_tokens(patch: str) -> set[str]:
    """Tokens the hunk introduces beyond its own removed and context lines.

    Re-wrapped or re-indented lines contribute only tokens that already exist
    elsewhere in the hunk, so they cancel out; what remains is the semantic
    content the hunk actually adds. Returns an empty set for hunks without
    added lines or without any new token (pure rewraps, version bumps).
    """
    added = _changed_diff_lines(patch, added=True)
    if not added:
        return set()
    existing = _changed_diff_lines(patch, added=False) + _context_diff_lines(patch)
    return (_semantic_tokens([_strip_comments(line) for line in added])
            - _semantic_tokens([_strip_comments(line) for line in existing]))


def _rewrap_only(patch: str) -> bool:
    # Preserve operators and quoted strings: identical identifier sets do not
    # imply formatting-only changes (e.g. '<' versus '<=' changes a bound).
    pattern = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\w+|\S')
    def lex(lines):
        return [m[0] for m in pattern.finditer('\n'.join(lines)) if not m[0].startswith(('//', '/*'))]
    removed = _changed_diff_lines(patch, added=False)
    added = _changed_diff_lines(patch, added=True)
    return bool(removed and added) and lex(removed) == lex(added)


class CandidateRejected(RuntimeError):
    """A candidate is retryable but must not reach independent validation."""

    kind = "CANDIDATE_REJECTED"

    def __init__(self, message: str, *, feedback: str | None = None):
        super().__init__(message)
        self.feedback = feedback or message


class AospBackportAgent(CausalityChecks):
    """Run independent AOSP impact assessment and a guarded SDK backport."""

    def __init__(self, source_root: Path, run_root: Path, case: Case, model: str | None = None,
                 donor_root: Path | None = None, model_provider: str | None = None,
                 api_base_url: str | None = None, api_key_env: str | None = None, *,
                 runtime_factory: Callable | None = None, turn_timeout: float = 900,
                 source_diff: str | None = None, max_output_bytes: int = 256 * 1024 * 1024):
        if api_base_url or api_key_env:
            raise ValueError("AOSP agent requires Codex SDK; direct API arguments are unsupported")
        self.source_root, self.run_root = source_root.resolve(), run_root.resolve()
        self._source_scope = self.source_root
        self.case, self.model = case, model
        self.input_diff = source_diff
        self.model_provider = model_provider or os.environ.get("AOSP_AGENT_MODEL_PROVIDER")
        self.repo = (self.source_root / validate_relative_path(case.repository)).resolve()
        self.donor_root = donor_root.resolve() if donor_root else None
        donor_repository = case.donor_repository or case.repository
        self.donor_repo = ((self.donor_root / _donor_slug(donor_repository)).resolve()
                           if self.donor_root else self.repo)
        if not self.repo.is_dir() or not self.repo.is_relative_to(self.source_root):
            raise ValueError("repository must be an existing directory below source_root")
        if self.run_root == self.repo or self.run_root.is_relative_to(self.repo):
            raise ValueError("run_root must be outside target repository")
        if not self.donor_repo.is_dir():
            raise ValueError("donor repository is missing")
        [validate_relative_path(path) for path in case.files]
        if turn_timeout <= 0:
            raise ValueError("turn_timeout must be positive")
        self.runtime_factory, self.turn_timeout = runtime_factory, float(turn_timeout)
        # Controller-generated verification artifacts (e.g. compiled jars the
        # r760 build stage copies into the worktree) are exempt from the
        # edit-allowlist audit: they are verification outputs, not model
        # edits, and must not leak into the exported patch.
        self._artifact_paths = {artifact for check in case.validation_checks
                                for artifact in check.get("artifacts", [])}
        self.run_dir, self.worktree = self.run_root / case.cve, self.run_root / case.cve / case.repository
        self._owns_run, self._source_before = False, None
        self.max_output_bytes = max_output_bytes
        self._current_hunks: list[dict[str, Any]] = []
        self.mapping_plan, self.mapping_repository = None, None
        self.selected_hunk_ids = None
        self.mechanical_hunk_ids = None
        self.location_handoff = None
        self._last_audit: dict[str, Any] | None = None
        self._events_swept = 0
        self.record: dict[str, Any] = {"cve": case.cve, "status": "INITIALIZED", "backend": "codex_sdk",
            "model": model or "codex_config_default", "events": [],
            "verification_scope": "configured_commands_only",
            "runtime_security_proven": False,
            "model_execution": "not_run", "impact_decision": "uncertain",
            "source_review": "not_run", "patch_replay": "not_run",
            "source_extracted_jvm": "NOT_CONFIGURED", "android_module_build": "NOT_CONFIGURED",
            "android_runtime": "NOT_CONFIGURED", "poc_execution": "NOT_RUN"}
        self.record["capabilities"] = {
            "multi_repository": ("single_repository" if not case.repositories else
                                 "read_only_dependencies" if all(item.get("role") == "read_only_dependency"
                                                                 for item in case.repositories)
                                 else "declared_not_orchestrated"),
            "read_only_dependencies": len(case.repositories),
            "donor_repository_mapping": "enabled" if case.donor_repository else "same_as_target",
            "repo_manifest": "declared" if case.manifest else "not_configured",
            "device_validation": "not_configured",
        }

    def _git(self, *args: str, cwd: Path | None = None, check: bool = True,
             env: dict[str, str] | None = None, input: str | None = None):
        from .retrieval import capture_git, record_read_activity
        repo = cwd or self.repo
        git_env = offline_git_env(env)
        record_read_activity(operations=1)
        return capture_git(["git", "-c", f"safe.directory={repo}", "-c", "protocol.allow=never",
                               "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args], cwd=repo,
                           check=check, env=git_env, input=input, timeout=180)

    def _source_git(self, *args: str, check: bool = True):
        if self.donor_root:
            from .retrieval import capture_git, record_read_activity
            record_read_activity(operations=1)
            return capture_git(["git", "-c", "protocol.allow=never", "--git-dir", str(self.donor_repo), *args],
                               check=check, timeout=180, env=offline_git_env())
        return self._git(*args, check=check)

    def _event(self, name: str, **data: Any) -> None:
        self.record["events"].append({"event": name, "time": time.time(), **data})
        if self._owns_run:
            self._write_record()

    def _json(self, name: str, value: Any) -> None:
        from .output_budget import write_json
        write_json(self.run_dir / name, value, control=name == 'run.json')

    def _source_state(self) -> dict[str, str]:
        return {"head": self._git("rev-parse", "HEAD").stdout.strip(),
                "status": self._git("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout,
                "diff_sha256": hashlib.sha256(self._git("diff", "--binary", "HEAD").stdout.encode()).hexdigest()}

    @source_guard('_source_scope')
    def prepare(self) -> Path:
        self.run_dir.mkdir(parents=True, exist_ok=False)
        from .output_budget import create_budget
        self.output_budget = create_budget(self.run_dir, self.max_output_bytes)
        self._owns_run = True
        dependencies: dict[str, dict[str, str]] = {}
        unsupported: list[str] = []
        for item in self.case.repositories:
            repository_path = item.get("path", "")
            if repository_path == self.case.repository:
                continue
            if item.get("role") != "read_only_dependency":
                unsupported.append(repository_path)
                continue
            repository_root = (self.source_root / validate_relative_path(repository_path)).resolve()
            if not repository_root.is_dir() or not repository_root.is_relative_to(self.source_root):
                raise ValueError(f"read-only dependency repository must exist below source_root: {repository_path}")
            ref = item.get('target_commit')
            if ref is not None and (not isinstance(ref, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', ref)):
                raise ValueError('read-only dependency target_commit must be a full pinned Git commit ID')
            head = self._git("rev-parse", '--verify', (ref or 'HEAD') + '^{commit}', cwd=repository_root).stdout.strip()
            dependencies[repository_path] = {"root": str(repository_root), "head": head}
        if unsupported:
            self.record["status"] = "FAILED"
            self.record["capabilities"]["multi_repository"] = "declared_not_orchestrated"
            self.record["error"] = {"kind": "UNSUPPORTED_MULTI_REPOSITORY", "type": "ValueError",
                                     "message": "multi-repository cases are declared but not yet orchestrated"}
            self._write_record()
            raise ValueError(self.record["error"]["message"])
        self._source_before = self._source_state()
        if self.input_diff is None:
            for ref in (self.case.source_commit, self.case.source_parent):
                self._source_git("cat-file", "-e", f"{ref}^{{commit}}")
        self._git("cat-file", "-e", f"{self.case.target_commit}^{{commit}}")
        if self.input_diff is None:
            raw = self._source_git("cat-file", "-p", self.case.source_commit).stdout
            parents = [line.split()[1] for line in raw.split("\n\n", 1)[0].splitlines() if line.startswith("parent ")]
            if self._source_git("rev-parse", self.case.source_parent).stdout.strip() not in parents:
                raise ValueError("source_parent is not a parent of source_commit")
        # R1 (RetroPatch split_patch/invoke_llm): the donor commit message is
        # injected with the diff as intent evidence. Diff-input mode has no
        # donor object, so the field stays empty there.
        self.commit_message = ("" if self.input_diff is not None else
                               self._source_git("log", "-1", "--pretty=%B",
                                                self.case.source_commit).stdout)
        target = self._git("rev-parse", self.case.target_commit).stdout.strip()
        target_tree = self._git("rev-parse", f"{target}^{{tree}}").stdout.strip()
        self.worktree.parent.mkdir(parents=True, exist_ok=True)
        self._git("worktree", "prune")
        self._git("worktree", "add", "--detach", str(self.worktree), target)
        self.record.update(status="PREPARED", source_commit=self.case.source_commit,
                           source_parent=self.case.source_parent, target_commit=target,
                           target_tree=target_tree,
                           worktree=str(self.worktree), original_checkout=self._source_before,
                           commit_message=self.commit_message,
                           donor_git=str(self.donor_repo) if self.donor_root else None)
        if dependencies:
            self.record["dependency_repositories"] = dependencies
            self._event("read_only_dependencies_prepared", repositories=dependencies)
        self._event("prepared", target_commit=target, worktree=str(self.worktree))
        self.audit_diff(require_clean=True)
        if self.input_diff is None:
            from .agent_tools import _write_wrappers
            _write_wrappers(self.run_dir)
        return self.worktree

    @source_guard('_source_scope')
    def inspect(self) -> dict[str, Any]:
        if not self.worktree.is_dir():
            raise RuntimeError("prepare() must run before inspect()")
        files = []
        for relative in self.case.files:
            path = self.worktree / relative
            if path.is_symlink() or not path.resolve().is_relative_to(self.worktree):
                raise AssessmentError(f"case path resolves outside worktree: {relative}")
            files.append({"path": relative, "exists": path.is_file(),
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None})
        if self.location_handoff:
            source_diff = self.location_handoff.controller.diff
        else:
            source_diff = (self.input_diff if self.input_diff is not None else
                           self._source_git("diff", "--no-ext-diff", self.case.source_parent, self.case.source_commit).stdout)
        hunks = split_hunks(source_diff)
        if self.selected_hunk_ids is not None:
            hunks = [h for h in hunks if h['id'] in self.selected_hunk_ids]
            source_diff = ''.join(h['patch'] for h in hunks)
        self._source_changed_paths = {h["path"] for h in hunks if h.get("path")}
        from .hunk_groups import review_groups
        review = review_groups(hunks)
        self._json('hunk-review-groups.json', review)
        for hunk in hunks:
            if self.location_handoff:
                hunk["application_check"] = {"status": "DEFERRED_UNTIL_SCOPE"}
            else:
                hunk["application_check"] = (self._check_application(hunk["patch"])
                                              if hunk["supported"] else {"status": "UNSUPPORTED"})
        result = {"target_files": files, "source_diff": source_diff, "source_commit": self.case.source_commit,
                  "target_commit": self.case.target_commit, "hunks": hunks, "review_groups": review,
                  "commit_message": self.commit_message,
                  "whole_patch_application": ({"status": "SCOPED_MIGRATION_ONLY"} if self.location_handoff
                                              else self._check_application(source_diff)),
                  "limitation": "Textual applicability does not establish impact or API compatibility."}
        if self.input_diff is None and not self.location_handoff:
            # Read-only existence pre-scan (R4); runs before any model turn so
            # the impact phase still sees a clean baseline (r2 revision 1).
            try:
                result["symbol_report"] = symbols.existence_report(
                    hunks, self.worktree, self.case.target_commit)
            except Exception as exc:  # a bad pre-scan must never kill the run
                result["symbol_report"] = {"missing": [], "found": [],
                                           "summary": f"symbol pre-scan failed: {exc}"}
            self._event("symbol_prescan", summary=result["symbol_report"].get("summary", ""))
        self._json("inspection.json", result)
        self.record["status"] = "INSPECTED"
        self.record["source_review"] = "pass"
        self._event("inspected", target_files=files, hunks=len(hunks),
                    whole_patch_application=result["whole_patch_application"])
        return result

    def _check_application(self, patch: str) -> dict[str, Any]:
        if not patch.strip():
            return {"status": "EMPTY", "returncode": None}
        with tempfile.TemporaryDirectory(prefix="apply-check-", dir=self.run_dir) as folder:
            env = dict(os.environ, GIT_INDEX_FILE=str(Path(folder) / "index"))
            self._git("read-tree", self.case.target_commit, cwd=self.worktree, env=env)
            check = self._git("apply", "--check", "--cached", "--binary", "-", cwd=self.worktree,
                              env=env, input=patch, check=False)
        return {"status": "APPLIES_TEXTUALLY" if check.returncode == 0 else "CONFLICTS",
                "returncode": check.returncode, "stderr": check.stderr[-5000:]}

    def _ground_assessment(self, text: str) -> dict[str, Any]:
        from .impact_proof import AssessmentGroundingError, require_grounded_behavior
        assessment = parse_impact_response(text)
        if assessment["status"] != "UNKNOWN" and not any(e["revision"] in ("source_parent", "source_fix")
                                                          for e in assessment["evidence"]):
            raise AssessmentError("determinate assessment requires donor evidence")
        refs = {"target": self.case.target_commit, "source_parent": self.case.source_parent,
                "source_fix": self.case.source_commit}
        errors = []
        for evidence_index, evidence in enumerate(assessment["evidence"]):
            try:
                self._ground_impact_evidence(evidence, evidence_index, refs)
            except AssessmentError as exc:
                errors.append(exc)
                if len(errors) == 8:
                    break
        if errors:
            # The declared assumptions are independently visible. The rest of
            # the causal proof must wait until its citations are grounded.
            try:
                require_grounded_behavior(assessment)
            except AssessmentError as exc:
                errors.append(exc)
            raise AssessmentGroundingError(errors)
        self._validate_impact_causality(assessment)
        from .platform_evidence import receipt
        self.record['platform_behavior_evidence'] = receipt(assessment)
        return assessment

    def _ground_impact_evidence(self, evidence, evidence_index, refs):
        from .impact_proof import evidence_error
        if (evidence["revision"] != "target"
                and evidence["path"] not in self.case.files
                and evidence["path"] not in getattr(self, "_source_changed_paths", set())):
            raise evidence_error(f"source evidence path is not in the donor fix diff: {evidence['path']}",
                                 evidence_index, 'path')
        runner = self._git if evidence["revision"] == "target" else self._source_git
        try:
            if self.location_handoff and evidence['revision'] == 'target':
                content = self.location_handoff.target_content(evidence['path'])
            else:
                content = runner("show", f"{refs[evidence['revision']]}:{evidence['path']}").stdout
        except AssessmentError as exc:
            raise evidence_error(str(exc), evidence_index, 'path') from exc
        except subprocess.CalledProcessError as exc:
            raise evidence_error(
                f"evidence file does not exist in {evidence['revision']}:{evidence['path']}",
                evidence_index, 'path') from exc
        lines = content.splitlines()
        start, end = evidence["line_start"], evidence["line_end"]
        if end > len(lines):
            raise evidence_error(f"evidence line range exceeds {evidence['revision']}:{evidence['path']}",
                                 evidence_index, 'line_end')
        excerpt = evidence["excerpt"].strip()
        excerpt_lines = excerpt.splitlines()
        matches = [index for index in range(len(lines) - len(excerpt_lines) + 1)
                   if "\n".join(lines[index:index + len(excerpt_lines)]).strip() == excerpt]
        if not matches:
            raise evidence_error(f"evidence excerpt does not exist in {evidence['revision']}:{evidence['path']}:{start}-{end}",
                                 evidence_index, 'excerpt')
        if self.location_handoff and start - 1 not in matches and len(matches) != 1:
            raise evidence_error(f"ambiguous pinned evidence range: {evidence['path']}:{start}-{end}",
                                 evidence_index, 'line_start')
        actual_start = start if self.location_handoff and start - 1 in matches else matches[0] + 1
        actual_end = actual_start + len(excerpt_lines) - 1
        if actual_start != start or actual_end != end:
            self.record.setdefault("evidence_corrections", []).append(
                {"revision": evidence["revision"], "path": evidence["path"],
                 "requested": [start, end], "grounded": [actual_start, actual_end]})
            evidence["line_start"], evidence["line_end"] = actual_start, actual_end


    def _turn(self, runtime, prompt: str, *, read_only: bool, phase: str, schema=None) -> dict:
        from .execution_budget import model_context
        with model_context(phase, self.case.repository):
            result = runtime.run(prompt, read_only=read_only, output_schema=schema)
        if result.get("status") != "completed":
            raise RuntimeError(f"SDK turn did not complete: {result.get('status')}")
        self._event("codex_turn", phase=phase, thread_id=result.get("thread_id"), turn_id=result.get("turn_id"),
                    status=result["status"], events_path=result.get("events_path"), usage=result.get("usage"))
        self._sweep_tool_usage()
        self.audit_diff(require_clean=read_only)
        return result

    def _sweep_tool_usage(self) -> None:
        """Collect controller source receipts and legacy diagnostic markers.

        The Codex sandbox denies the tools' direct appends to
        tool-usage.jsonl (run_dir is outside the sandboxed workspace), so
        every tool invocation also prints an AOSP-TOOL-USAGE marker on
        stdout; those markers appear in commandExecution events and are
        swept here after each turn. Deduplication is by the marker's uid.
        """
        events_path = self.run_dir / "sdk-events.jsonl"
        if not events_path.is_file():
            return
        with events_path.open(encoding='utf-8', errors='replace') as stream:
            stream.seek(self._events_swept)
            fresh = stream.read()
            self._events_swept = stream.tell()
        marker_re = re.compile(r"^AOSP-TOOL-USAGE (\{.*\})$", re.MULTILINE)
        entries = []
        for line in fresh.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if not isinstance(event, dict):
                continue
            if event.get('event') == 'broker_source_usage':
                # Only top-level receipts emitted by the controller's broker
                # are admitted. Model text containing JSON or a usage marker
                # is not a receipt. Keep failed receipts for diagnostics; the
                # evidence gate still checks success, relevance and semantics.
                if (event.get('cmd') in ('view-code', 'locate-symbol', 'hunk-history', 'show-commit')
                        and isinstance(event.get('uid'), str)
                        and re.fullmatch(r'[0-9a-f]{12}', event['uid'])
                        and isinstance(event.get('args'), dict)
                        and type(event.get('returncode')) is int):
                    entries.append({k: v for k, v in event.items() if k not in ('event', 'sequence', 'timestamp')})
                continue
            item = ((event.get("payload") or {}).get("item") or {}
                    if event.get("method") == "item/completed" else {})
            if not isinstance(item, dict) or item.get("type") != "commandExecution":
                continue
            text = next((item[key] for key in ("aggregatedOutput", "aggregated_output",
                                               "output", "stdout")
                         if isinstance(item.get(key), str)), "")
            for match in marker_re.finditer(text):
                try:
                    entry = json.loads(match.group(1))
                except ValueError:
                    continue
                if isinstance(entry, dict) and entry.get("cmd"):
                    entries.append(entry)
        if not entries:
            return
        usage_path = self.run_dir / "tool-usage.jsonl"
        known = set()
        if usage_path.is_file():
            for line in usage_path.read_text().splitlines():
                try:
                    known.add(json.loads(line).get("uid"))
                except ValueError:
                    continue
        from .output_budget import write_text
        for entry in entries:
            if entry.get("uid") in known:
                continue
            known.add(entry.get("uid"))
            write_text(usage_path, json.dumps(entry, ensure_ascii=False) + '\n', append=True)
            for sha in entry.get("history_shas") or []:
                write_text(self.run_dir / 'history-commits.jsonl', json.dumps({'sha': sha, 'hunk_id': None}) + '\n', append=True)

    def mechanical_migration(self, inspection: dict[str, Any]) -> dict[str, Any]:
        """Try to land donor hunks in the migration worktree without the model.

        R2 port: mechanically applicable hunks are applied directly; each
        failure produces a structured diagnosis instead of raw Git noise.
        Mechanical success is NOT final: hunks referencing symbols missing
        at the target baseline still need model adaptation (CVE-2025-48550
        is exactly "textually applicable but the API does not exist").
        """
        result: dict[str, Any] = {"hunks": [], "applied": [], "failed": [], "skipped": [],
                                  "starting_state": "none"}
        allowlist = set(self.case.files)
        target_lines: dict[str, list[str] | None] = {}
        for hunk in inspection["hunks"]:
            entry = {"id": hunk["id"], "path": hunk.get("path")}
            if self.mechanical_hunk_ids is not None and hunk['id'] not in self.mechanical_hunk_ids:
                entry.update(status="skipped", reason="read_only_donor_context")
            elif not hunk.get("supported") or hunk.get("kind") != "hunk":
                entry.update(status="skipped", reason="unsupported_or_not_text_hunk")
            elif hunk.get("path") not in allowlist:
                entry.update(status="skipped", reason="skipped_out_of_allowlist")
            else:
                path = hunk["path"]
                if path not in target_lines:
                    blob = self._git("show", f"{self.case.target_commit}:{path}",
                                     cwd=self.worktree, check=False)
                    target_lines[path] = blob.stdout.splitlines() if blob.returncode == 0 else None
                lines = target_lines[path]
                if self.location_handoff and not self._mechanical_matches_location(hunk, path, lines):
                    entry.update(status="skipped", reason="outside_grounded_location")
                elif lines is None:
                    candidates = self._target_tree_files()
                    entry.update(status="failed", repair_applied=[],
                                 diagnosis=apply_diagnosis(hunk, "No such file", None, candidates))
                else:
                    patch_text, repairs = (hunk['patch'], []) if self.location_handoff else repair_hunk(hunk, lines)
                    applied = self._git("apply", "-", cwd=self.worktree, check=False, input=patch_text)
                    if applied.returncode == 0:
                        entry.update(status="applied", repair_applied=repairs)
                    else:
                        # git apply is atomic per invocation; defensively undo
                        # any residue inside this disposable worktree only.
                        if not self.location_handoff and self._git("diff", "--quiet", "--", path, cwd=self.worktree,
                                     check=False).returncode != 0:
                            self._git("checkout", "--", path, cwd=self.worktree, check=False)
                        entry.update(status="failed", repair_applied=repairs,
                                     diagnosis=apply_diagnosis(hunk, applied.stderr, lines))
            result[entry["status"] if entry["status"] != "skipped" else "skipped"].append(entry["id"])
            result["hunks"].append(entry)
        try:
            audit = self.audit_diff()
            applied_count, failed_count = len(result["applied"]), len(result["failed"])
            result["starting_state"] = ("full" if applied_count and not failed_count
                                        else "partial" if applied_count else "none")
            result["audit_changed_files"] = audit["changed_files"]
        except RuntimeError as exc:
            # Whitelist violation must not leave a polluted workspace behind.
            for relative in sorted(allowlist | getattr(self, "_source_changed_paths", set())):
                self._git("checkout", "--", relative, cwd=self.worktree, check=False)
            result.update(starting_state="none", audit_error=str(exc))
        self.record["mechanical_migration"] = result
        self._event("mechanical_migration",
                    **{key: value for key, value in result.items() if key != "hunks"})
        return result

    def _mechanical_matches_location(self, hunk, path, baseline):
        if baseline is None:
            return False
        rows = text_hunks(hunk['patch'])[0]['lines']
        old = [row['text'] for row in rows if row['marker'] != '+']
        if not old:
            return False
        # A modified file or repeated context requires the writer to adapt the
        # hunk. Git's offset search alone cannot choose a grounded edit site.
        current = (self.worktree / path).read_text().splitlines()
        if current != baseline:
            return False
        start = None
        for index, line in enumerate(baseline):
            if line == old[0] and baseline[index:index + len(old)] == old:
                if start is not None:
                    return False
                start = index + 1
        return start is not None and any(
            region['action'] == 'edit' and region['path'] == path and region.get('region_kind') != 'member_insertion'
            and region['line_start'] <= start
            and start + len(old) - 1 <= region['line_end']
            for region in self.mapping_plan.targets(self.mapping_repository, unit_id=hunk['id']))

    def _target_tree_files(self) -> list[str]:
        """Bounded listing of source-suffix files at the target baseline."""
        listing = self._git("ls-tree", "-r", "--name-only", self.case.target_commit,
                            cwd=self.worktree, check=False)
        if listing.returncode != 0:
            return []
        suffixes = (".java", ".kt", ".aidl")
        return [line for line in listing.stdout.splitlines() if line.endswith(suffixes)][:20000]

    def _history_available(self) -> bool:
        """Whether donor history covers target..source_parent (P2.1 may deepen it)."""
        if not self.donor_root or self.input_diff is not None:
            return False
        exists = self._source_git("cat-file", "-e", f"{self.case.target_commit}^{{commit}}",
                                  check=False)
        if exists.returncode != 0:
            return False
        log = self._source_git("log", "--oneline",
                               f"{self.case.target_commit}..{self.case.source_parent}",
                               "--", *self.case.files, check=False)
        return bool(log.stdout.strip())

    def _starting_state_text(self, migration: dict[str, Any],
                             inspection: dict[str, Any]) -> str:
        failed = [entry for entry in migration["hunks"] if entry["status"] == "failed"]
        missing = [entry["name"] for entry in inspection.get("symbol_report", {}).get("missing", [])]
        failed_summary = [{"id": entry["id"], "path": entry["path"],
                           "kind": entry.get("diagnosis", {}).get("kind"),
                           "located_start": entry.get("diagnosis", {}).get("located_start"),
                           "hint": entry.get("diagnosis", {}).get("hint"),
                           "line_diffs": entry.get("diagnosis", {}).get("line_diffs", [])[:6]}
                          for entry in failed]
        return ("Starting state produced by the controller (no model edits yet):\n"
                f"- Mechanically applied hunks (landed in the workspace; API references still "
                f"need checking): {', '.join(migration['applied']) or 'none'}\n"
                f"- Skipped by the mechanical pass (whole-file/metadata or out of allowlist): "
                f"{', '.join(migration['skipped']) or 'none'}\n"
                "- Failed to apply mechanically, with diagnosis (adapt these):\n"
                + json.dumps(failed_summary, ensure_ascii=False, indent=1)
                + "\n- Donor identifiers not found by the scoped lexical pre-scan "
                  "(investigate other languages, renamed APIs and equivalent operations; absence is not established): "
                  f"{', '.join(missing) or 'none'}\n")

    def _check_hunk_results(self, response: str,
                            changed_files: list[str],
                            candidate_patch: str | None = None, *,
                            review_mapped=False) -> dict[str, Any]:
        """Require a complete, non-contradictory donor-hunk ledger."""
        guarded = review_mapped and self.mapping_plan and self.mapping_plan.data().get('repair_contract')
        if guarded:
            self.record.pop('repair_obligation_review', None)
        claims = [{"id": match.group(1), "status": match.group(2), "reason": match.group(3)}
                  for match in _HUNK_RESULT_RE.finditer(response or "")]
        expected_ids = {hunk["id"] for hunk in self._current_hunks}
        claimed_ids = [claim["id"] for claim in claims]
        missing = sorted(expected_ids - set(claimed_ids))
        duplicates = sorted({item for item in claimed_ids
                             if claimed_ids.count(item) > 1})
        unexpected = sorted(set(claimed_ids) - {hunk["id"] for hunk in self._current_hunks})
        coverage = {"expected": sorted(expected_ids), "claimed": sorted(set(claimed_ids)),
                    "missing": missing, "duplicate": duplicates, "unexpected": unexpected}
        if not claims:
            return {"ok": False, "claims": [], "contradictions": [], "coverage": coverage,
                    "missing_declaration": True,
                    "feedback": ("Your reply contained no HUNK-RESULT declaration. End your "
                                 "turn with one line per donor hunk:\n"
                                 "HUNK-RESULT <hunk-id> implemented|need_not_ported "
                                 "evidence=<category> <reason>")}

        hunks = {hunk["id"]: hunk for hunk in self._current_hunks}
        contradictions: list[str] = []
        for claim in claims:
            if claim["id"] not in hunks:
                contradictions.append(f"unknown hunk id: {claim['id']}")
            elif claim["status"] == "need_not_ported":
                evidence = self._exclusion_evidence(claim, hunks.get(claim["id"]))
                claim["reason"] = evidence.get("reason", claim["reason"])
                if not evidence["ok"]:
                    contradictions.append(f"{claim['id']}: {evidence['error']}")
                elif evidence.get("category") in ("semantic_equivalence",
                                                  "already_present"):
                    falsified = self._falsify_exclusion_against_target(
                        hunks[claim["id"]], claim, evidence["category"])
                    if falsified:
                        claim["falsified_exclusion"] = True
                        contradictions.append(f"{claim['id']}: {falsified}")
            else:
                target_evidence = self._implemented_hunk_evidence(
                    hunks[claim["id"]], candidate_patch)
                claim["target_evidence"] = target_evidence

        by_path: dict[str, list[str]] = {}
        for claim in claims:
            hunk = hunks.get(claim["id"])
            if hunk:
                by_path.setdefault(hunk["path"], []).append(claim["status"])
        changed = set(changed_files)
        allowlist = set(self.case.files)
        for path, statuses in sorted(by_path.items()):
            donor_targets = self._donor_targets(path)
            if ("implemented" in statuses and donor_targets
                    and not donor_targets.intersection(changed)
                    and (path in allowlist or donor_targets.intersection(allowlist))):
                contradictions.append(
                    f"{path}: declared implemented but no mapped target is changed")
            if (statuses and all(status == "need_not_ported" for status in statuses)
                    and path in changed):
                contradictions.append(
                    f"{path}: declared need_not_ported but the final diff modifies it")

        if missing:
            contradictions.append("missing HUNK-RESULT declarations: " + ", ".join(missing))
        if duplicates:
            contradictions.append("duplicate HUNK-RESULT declarations: " + ", ".join(duplicates))
        if review_mapped and not contradictions and self.mapping_plan:
            from .mapped_coverage import review_regions
            review_regions(self, claims, candidate_patch)
        if guarded:
            receipt = self.record.get('repair_obligation_review', {})
            if receipt.get('status') != 'COVERED':
                unresolved = [f"{r['id']}: {r['reason']}" for r in receipt.get('obligations', [])
                              if r['verdict'] != 'covered']
                contradictions.extend(unresolved or [receipt.get('error', 'guarded repair review is unresolved')])
        for claim in claims:
            evidence = claim.get('target_evidence')
            if not evidence or not evidence['required'] or evidence['ok']:
                continue
            failed = [row for row in evidence.get('regions', []) if not row['ok'] and 'mapping' in row]
            if failed:
                for row in failed:
                    target = row['mapping']
                    contradictions.append(f"{claim['id']}: {target['path']}:{target['line_start']}-"
                                          f"{target['line_end']} ({target['symbol']}): {row['error']}")
            else:
                contradictions.append(f"{claim['id']}: {evidence['error']}")
        ok = not contradictions
        return {"ok": ok, "claims": claims, "contradictions": contradictions,
                "coverage": coverage, "missing_declaration": False,
                "feedback": None if ok else
                ("Your HUNK-RESULT ledger contradicts the supplied donor hunks or exported diff:\n- "
                 + "\n- ".join(contradictions)
                 + "\nProvide exactly one evidence-backed declaration for every donor hunk.")}

    def _implemented_hunk_evidence(self, hunk: dict[str, Any],
                                   candidate_patch: str | None, *, scope=None, site=None) -> dict[str, Any]:
        if self.mapping_plan is not None and scope is None:
            regions = [t for t in self.mapping_plan.targets(self.mapping_repository, unit_id=hunk['id'])
                       if t['action'] == 'edit' and t['status'] == 'AFFECTED']
            evidence = [self._implemented_hunk_evidence(hunk, candidate_patch, scope=region)
                        for region in regions]
            ok = bool(evidence) and all(e['ok'] for e in evidence)
            return {'required': True, 'ok': ok, 'regions': evidence,
                    'targets': sorted({t['path'] for t in regions}),
                    'match': 'evidence in every grounded mapping region' if ok else None,
                    'error': None if ok else 'no mapped target semantic evidence in every required region'}
        targets = [scope['path']] if scope else sorted(self._donor_targets(hunk.get("path", "")))
        result = {"required": bool(targets), "targets": targets,
                  "ok": not targets, "match": None}
        if not targets:
            return result
        if candidate_patch is None:
            result["error"] = "candidate patch evidence is unavailable"
            return result
        if scope and scope.get('region_kind') in ('imports', 'member_insertion'):
            result['error'] = 'Java declaration coverage requires pinned structural evidence'
            return result
        try:
            candidates = split_hunks(candidate_patch)
        except ValueError as exc:
            result["error"] = f"invalid candidate patch: {exc}"
            return result

        by_path: dict[str, list[dict[str, Any]]] = {}
        for candidate in candidates:
            by_path.setdefault(candidate["path"], []).append(candidate)
        donor_additions = _changed_diff_lines(hunk.get("patch", ""), added=True)
        expected_lines = donor_additions or _changed_diff_lines(
            hunk.get("patch", ""), added=False)
        expected_lines = [line for line in expected_lines if line]
        for target in targets:
            target_hunks = by_path.get(target, [])
            if not target_hunks:
                continue
            if target.endswith('.java') and site is None:
                from .continuation_proof import introduced_effects, coverage_gate
                effects = introduced_effects(hunk.get('patch', ''))
                if any(not effect['source_excludes_continuation'] for effect in effects):
                    baseline_text = self._artifact_baseline_text(target)
                    candidate_file = self.worktree / target
                    if (baseline_text is None or candidate_file.is_symlink() or not candidate_file.is_file()
                            or candidate_file.stat().st_size > 4 * 1024 * 1024):
                        flow = {'status': 'UNRESOLVED', 'reason': 'bounded source for conditional continuation is unavailable'}
                    else:
                        flow = coverage_gate(hunk['patch'], baseline_text, candidate_file.read_text(),
                            start=scope['line_start'] if scope else 1, end=scope['line_end'] if scope else None)
                    self.__dict__.setdefault('record', {}).setdefault('continuation_obligations', {})[hunk['id'] + ':' + target] = flow
                    if flow['status'] == 'UNRESOLVED':
                        result.update(control_flow_obligations=flow,
                            error='conditional effects require a grounded continuation postcondition; '
                                  'calls, matching comments and hunk tokens are not a control-flow proof')
                        return result
            if site is None:
                analysis = self._target_baseline_analysis(target)
                if analysis is not None:
                    baseline = analysis['raw']
                    from .hunk_sites import bind_changes, index_baseline
                    if 'site_index' not in analysis:
                        analysis['site_index'] = index_baseline(baseline)
                    binding = bind_changes(hunk.get('patch', ''), baseline,
                        start=scope['line_start'] if scope else 1,
                        end=scope['line_end'] if scope else None, indexed=analysis['site_index'])
                    if binding['status'] in ('AMBIGUOUS', 'OUTSIDE_MAPPING'):
                        result['site_binding'] = binding
                        continue
                    if binding['status'] == 'BOUND':
                        region = scope or {'path': target, 'line_start': 1, 'line_end': len(baseline) + 1}
                        evidence = [self._implemented_hunk_evidence(
                            {**hunk, 'patch': block['patch']}, candidate_patch, scope=region,
                            site=(block['line_start'], block['line_end'])) for block in binding['blocks']]
                        result['site_evidence'] = evidence
                        if evidence and all(e['ok'] for e in evidence):
                            result.update(ok=True, match=f'candidate edits every bound donor change site in {target}')
                            return result
                        continue
            target_lines: list[str] = []
            for target_hunk in target_hunks:
                if scope:
                    from .hunk_scope import changed_lines_in_region
                    target_lines.extend(changed_lines_in_region(target_hunk.get('patch', ''),
                        scope['line_start'], scope['line_end'], added=bool(donor_additions), touching=site))
                else:
                    target_lines.extend(_changed_diff_lines(
                        target_hunk.get("patch", ""), added=bool(donor_additions)))
            target_lines = [line for line in target_lines if line]
            if scope and (expected_lines or site is not None) and not target_lines:
                continue
            if not expected_lines:
                result.update(ok=True, match=f"changed target hunk: {target}")
                return result

            normalized_target = {
                _coverage_code_line(line) for line in target_lines if _coverage_code_line(line)
            }
            exact = sorted(
                line for line in expected_lines
                if _coverage_code_line(line) and _coverage_code_line(line) in normalized_target
            )
            if exact:
                result.update(
                    ok=True, match=f"exact normalized line in {target}: {exact[0]}")
                return result

            donor_tokens = _semantic_tokens(
                [_strip_comments(line) for line in expected_lines])
            target_tokens = _semantic_tokens(
                [_strip_comments(line) for line in target_lines])
            overlap = donor_tokens & target_tokens
            ratio = len(overlap) / len(donor_tokens) if donor_tokens else 0.0
            if donor_tokens and ratio >= 0.5:
                result.update(
                    ok=True,
                    match=(f"token evidence in {target}: "
                           + ", ".join(sorted(overlap)[:8])))
                return result

            if donor_additions:
                novel = _novel_tokens(hunk.get("patch", ""))
                if novel:
                    target_code_tokens = _semantic_tokens(
                        [_strip_comments(line) for line in target_lines])
                    if novel <= target_code_tokens:
                        result.update(
                            ok=True,
                            match=(f"novel tokens in {target}: "
                                   + ", ".join(sorted(novel)[:8])))
                        return result
                elif _rewrap_only(hunk.get('patch', '')):
                    result.update(
                        ok=True,
                        match=(f"no novel tokens in rewrap-only donor hunk; "
                               f"target changed: {target}"))
                    return result
        result["error"] = "no mapped target semantic evidence"
        return result

    def _exclusion_evidence(self, claim: dict[str, Any],
                            hunk: dict[str, Any] | None) -> dict[str, Any]:
        reason = claim.get("reason") or ""
        category_match = re.search(r"\bevidence=([a-z_]+)", reason)
        if not category_match:
            return {"ok": False, "error": "need_not_ported requires evidence=<category>"}
        category = category_match.group(1)
        allowed = {"metadata_only", "already_present", "no_target_counterpart", "semantic_equivalence"}
        if category not in allowed:
            return {"ok": False,
                    "error": f"unsupported exclusion evidence category: {category}"}
        if hunk is None:
            return {"ok": False, "error": "unknown donor hunk"}
        if category == "metadata_only":
            if not self._is_metadata_hunk(hunk):
                return {"ok": False,
                        "error": "metadata_only does not match the donor hunk"}
            return {"ok": True, "category": category, "tool_uids": []}
        if category == "no_target_counterpart":
            if self.location_handoff:
                receipt = self.location_handoff.flag_support.get(hunk['id'])
                if receipt:
                    return {'ok': True, 'category': category, 'tool_uids': [], 'controller_evidence': receipt}
                return {'ok': False, 'category': category,
                        'error': 'target absence has no controller evidence; missing mappings and donor history are insufficient'}
            targets = self._donor_targets(hunk.get("path", ""))
            if targets:
                return {"ok": False, "category": category,
                        "error": ("no_target_counterpart is false: the controller maps "
                                  f"donor path {hunk.get('path', '')} to target file(s) "
                                  f"{', '.join(sorted(targets))}. Port the hunk, or exclude "
                                  "it with already_present/semantic_equivalence backed by "
                                  "target tool evidence (metadata_only for metadata hunks)")}
            application = hunk.get("application_check", {})
            application_error = str(application.get("stderr") or application.get("stdout") or "")
            if "does not exist in index" in application_error:
                reason = re.sub(rf"\bevidence={category}\b",
                                f"evidence={category} controller=missing_target_path",
                                reason, count=1)
                return {"ok": True, "category": category, "tool_uids": [],
                        "controller_evidence": "missing_target_path", "reason": reason}

        tools_match = re.search(r"\btools=([0-9a-f]+(?:\+[0-9a-f]+)*)\b", reason)
        usage = self._tool_usage()
        relevant_uids = [uid for uid, record in usage.items()
                         if record.get("returncode") == 0
                         and self._tool_supports_hunk(record, hunk)]
        if not tools_match:
            if relevant_uids:
                verified = relevant_uids[-1:]
                reason = re.sub(rf"\bevidence={category}\b",
                                f"evidence={category} tools={'+'.join(verified)}",
                                reason, count=1)
                return {"ok": True, "category": category, "tool_uids": verified,
                        "reason": reason}
            return {"ok": False,
                    "error": f"{category} requires tools=<uid>[+<uid>] from controlled tools"}

        tool_uids = tools_match.group(1).split("+")
        verified = [uid for uid in tool_uids
                    if uid in usage
                    and usage[uid].get("returncode") == 0
                    and self._tool_supports_hunk(usage[uid], hunk)]
        if verified:
            unique_verified = list(dict.fromkeys(verified))
            start, end = tools_match.span()
            reason = reason[:start] + "tools=" + "+".join(unique_verified) + reason[end:]
            return {"ok": True, "category": category, "tool_uids": unique_verified,
                    "reason": reason}

        if relevant_uids:
            unique_verified = list(dict.fromkeys(relevant_uids[-1:]))
            start, end = tools_match.span()
            reason = reason[:start] + "tools=" + "+".join(unique_verified) + reason[end:]
            return {"ok": True, "category": category, "tool_uids": unique_verified,
                    "reason": reason}

        available = ", ".join(relevant_uids) or "none"
        for uid in tool_uids:
            record = usage.get(uid)
            if record is None or record.get("returncode") != 0:
                return {"ok": False,
                        "error": (f"missing or unsuccessful tool evidence {uid}; "
                                  f"available relevant successful UIDs: {available}")}
            if not self._tool_supports_hunk(record, hunk):
                return {"ok": False,
                        "error": (f"tool evidence {uid} is not relevant to donor hunk "
                                  f"{hunk['id']}; available relevant successful UIDs: "
                                  f"{available}")}
        return {"ok": False,
                "error": f"no successful relevant tool evidence; available UIDs: {available}"}

    def _tool_usage(self) -> dict[str, dict[str, Any]]:
        path = self.run_dir / "tool-usage.jsonl"
        records: dict[str, dict[str, Any]] = {}
        if not path.is_file():
            return records
        for line in path.read_text(errors="replace").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and record.get("uid"):
                records[str(record["uid"])] = record
        return records

    def _tool_supports_hunk(self, record: dict[str, Any], hunk: dict[str, Any]) -> bool:
        if record.get('rejected') or record.get('read_status') in ('READ_FAILED', 'PATH_ABSENT', 'NOT_FOUND_IN_SCOPE', 'NOT_AVAILABLE'):
            return False
        command = record.get("cmd")
        arguments = record.get("args") or {}
        if self.location_handoff:
            scope = arguments.get('repo', '')
            if command != 'view-code' or (scope != 'target' and not scope.startswith(('target:', 'dependency:'))):
                return False
            key = scope.split(':', 1)[1] if ':' in scope else self.mapping_repository
            regions = self.mapping_plan.targets(key, unit_id=hunk['id'])
            def receipt_line(value):
                if type(value) is int:
                    return value if value > 0 else None
                # agent_tools._finish serializes argv values with str(). Admit
                # only that canonical positive integer spelling, not coercions.
                if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value):
                    try:
                        return int(value)
                    except ValueError:
                        pass
                return None
            start, end = receipt_line(arguments.get('start')), receipt_line(arguments.get('end'))
            if start is None or end is None or start > end:
                return False
            return any(arguments.get('path') == region['path']
                       and start <= region['line_end'] and end >= region['line_start']
                       for region in regions)
        if command == "hunk-history":
            return arguments.get("hunk_id") == hunk["id"]
        if command == "show-commit":
            return arguments.get("hunk_id") == hunk["id"]
        if command == "view-code":
            relevant_paths = self._donor_targets(hunk["path"]) | {hunk["path"]}
            return (arguments.get("repo") == "target"
                    and arguments.get("path") in relevant_paths)
        if command == "locate-symbol":
            symbol = arguments.get("symbol")
            return (arguments.get("repo") == "target"
                    and isinstance(symbol, str) and symbol in hunk.get("patch", ""))
        return False

    def _is_metadata_hunk(self, hunk: dict[str, Any]) -> bool:
        path = hunk.get("path") or ""
        patch_lines = hunk.get("patch", "").splitlines()
        removed = [line[1:] for line in patch_lines
                   if line.startswith("-") and not line.startswith("---")]
        added = [line[1:] for line in patch_lines
                 if line.startswith("+") and not line.startswith("+++")]
        changed_lines = removed + added
        if not changed_lines:
            return False
        # File names alone cannot exempt executable build/configuration edits.
        meaningful = [line.strip() for line in changed_lines if line.strip()]
        comments_removed = re.sub(r'//[^\n]*|/\*[\s\S]*?\*/', '', '\n'.join(meaningful))
        if meaningful and not comments_removed.strip():
            return True
        if meaningful and all(_VERSION_LINE_RE.fullmatch(_strip_comments(line).strip()) for line in meaningful):
            return True
        if Path(path).name == 'OWNERS':
            return bool(meaningful) and all(re.fullmatch(r'[\w.+-]+@[\w.-]+|#.*', line) for line in meaningful)
        if Path(path).name in {'METADATA', 'README.version'}:
            return bool(meaningful) and all(re.fullmatch(
                r'(?:version|date|last_upgrade_date|year|month|day)\s*[:=]\s*[\w.\s"{}:-]+|[{}]', line,
                re.I) for line in meaningful)
        return False

    def _donor_targets(self, donor_path: str) -> set[str]:
        allowed = set(self.case.files)
        if self.mapping_plan is not None:
            return {target['path'] for target in self.mapping_plan.targets(
                self.mapping_repository, donor_path=donor_path)
                if target['action'] == 'edit'} & allowed
        targets = {donor_path} & allowed
        normalized = _version_normalized_paths(donor_path) & allowed
        if len(normalized) == 1:
            targets.update(normalized)
        return targets

    def _target_baseline_lines(self, path: str) -> list[str] | None:
        blob = self._git("show", f"{self.case.target_commit}:{path}",
                         cwd=self.repo, check=False)
        if blob.returncode != 0:
            listing = self._git('--literal-pathspecs', 'ls-tree', '-z', self.case.target_commit, '--', path,
                                cwd=self.repo, check=False)
            if listing.returncode == 0 and not listing.stdout:
                return None
            from .lifecycle import RecoveryBlocked
            raise RecoveryBlocked('cannot read pinned target baseline for hunk evidence: ' + path)
        return blob.stdout.splitlines()

    def _target_baseline_analysis(self, path: str, *, qualified=False) -> dict[str, Any] | None:
        """Comment-stripped lines, brace paths and a token-occurrence index.

        Cached per path: the target commit is immutable for the run, and the
        ledger re-checks the same mapped files for every exclusion claim and
        every retry.
        """
        cache = getattr(self, "_target_analysis_cache", None)
        if cache is None:
            cache = self._target_analysis_cache = {}
        key = (path, qualified)
        if key in cache:
            return cache[key]
        raw = (self.location_handoff.target_content(path).splitlines() if qualified
               else self._target_baseline_lines(path))
        if raw is None:
            cache[key] = None
            return None
        code = [_strip_comments(line) for line in raw]
        analysis = {
            "raw": raw,
            "code": code,
            "paths": _brace_paths(raw),
            "normalized": [_normalized_code_line(line) for line in code],
            "occurrences": {},
        }
        cache[key] = analysis
        return analysis

    def _token_occurrences(self, analysis: dict[str, Any], token: str) -> list[int]:
        occurrences = analysis["occurrences"]
        if token not in occurrences:
            occurrences[token] = [
                index for index, line in enumerate(analysis["code"])
                if re.search(rf"\b{re.escape(token)}\b", line)]
        return occurrences[token]

    def _falsify_exclusion_against_target(self, hunk: dict[str, Any],
                                          claim: dict[str, Any],
                                          category: str) -> str | None:
        """Falsify target-side exclusion claims the controller can check itself.

        When the donor hunk's pre-change line still exists in a mapped target
        file the anchor is present: a semantic_equivalence claim must rest on a
        mechanism that executes on the anchor's path, and an already_present
        claim must find the hunk's added lines in the target. Claims about code
        the target does not contain stay with the tool-UID evidence checks.
        """
        qualified = self.location_handoff is not None
        regions = []
        if qualified:
            regions = [{**region, 'path': f"{key}/{region['path']}"}
                       for key in self.location_handoff.controller.by_key
                       for region in self.mapping_plan.targets(key, unit_id=hunk['id'])]
            targets = sorted({region['path'] for region in regions})
        else:
            targets = sorted(self._donor_targets(hunk.get("path", "")))
        if not targets:
            return None
        patch = hunk.get("patch", "")
        anchors = {line for line in (_normalized_code_line(_strip_comments(item))
                                     for item in
                                     _changed_diff_lines(patch, added=False))
                   if line}
        additions = {line for line in (_normalized_code_line(_strip_comments(item))
                                       for item in
                                       _changed_diff_lines(patch, added=True))
                     if line}
        if not anchors:
            # Pure insertions still need site evidence. Use donor context when
            # present; without any context, an exclusion cannot rest on a UID
            # alone or on the mere existence of the target file.
            anchors = {_normalized_code_line(_strip_comments(line))
                       for line in _context_diff_lines(patch)
                       if _semantic_tokens([_strip_comments(line)])}
            anchors.discard('')
            if not anchors:
                if category == 'already_present':
                    from .hunk_sites import matches_additions, normalized
                    expected = _changed_diff_lines(patch, added=True)
                    for target in targets:
                        analysis = self._target_baseline_analysis(target, qualified=qualified)
                        if analysis is None:
                            continue
                        # With no insertion context, a line elsewhere in the
                        # file is not the requested site. Whole-file identity
                        # or an independently grounded mapping is required.
                        if not qualified and self.mapping_plan is not None:
                            regions = self.mapping_plan.targets(self.mapping_repository, unit_id=hunk['id'])
                        if any(r['path'] == target and (qualified or r['action'] == 'edit')
                               and matches_additions(analysis['raw'][r['line_start']-1:r['line_end']], expected)
                               for r in regions):
                            return None
                        actual = [normalized(line) for line in analysis['raw'] if line.strip()]
                        wanted = [normalized(line) for line in expected if line.strip()]
                        if wanted and wanted == actual:
                            return None
                    return 'already_present is unsupported: unanchored additions lack site-specific evidence in mapped targets'
                return 'semantic_equivalence is unsupported: pure additions have no grounded target anchor'

        if category == "already_present":
            # A pure-reformat hunk introduces no novel semantic tokens; there
            # is nothing site-specific to falsify (mirrors the rewrap-only
            # acceptance in implemented-hunk evidence).
            if _rewrap_only(patch):
                return None
            from .hunk_sites import old_chunks, sequence_sites
            blocks = [block for chunk in old_chunks(patch) for block in chunk['blocks']]
            groups = [{'anchors': {_normalized_code_line(_strip_comments(line)) for line in b['removed']},
                       'added': [_normalized_code_line(_strip_comments(line)) for line in b['added']
                                 if _strip_comments(line).strip()]} for b in blocks]
            for target in targets:
                analysis = self._target_baseline_analysis(target, qualified=qualified)
                if analysis is None:
                    continue
                normalized = analysis["normalized"]
                anchor_hits = [index for index, line in enumerate(normalized)
                               if line in anchors]
                if not anchor_hits:
                    continue
                paths = analysis["paths"]
                for index in anchor_hits:
                    anchor_path = paths[index]
                    if not anchor_path:
                        if re.match(r'^#\s*define\b', normalized[index]):
                            return (f'already_present is false: pre-change macro remains at '
                                    f'{target}:{index + 1}; top-level definitions require site-specific evidence')
                        continue
                    applicable = [g for g in groups if not g['anchors'] or normalized[index] in g['anchors']]
                    for group in applicable:
                        key = tuple(group['added'])
                        cache = analysis.setdefault('addition_sites', {})
                        if key not in cache:
                            cache[key] = sequence_sites(normalized, group['added'])
                        sites = cache[key]
                        if any(paths[first] and _covers_path(paths[first], anchor_path) for first, _ in sites):
                            continue
                        same_function = any(paths[first] and paths[first][0] == anchor_path[0] for first, _ in sites)
                        detail = ('in a different branch that does not cover the anchor path' if same_function
                                  else 'only outside that function or not as a complete ordered change block')
                        return ("already_present is false: the hunk's pre-change "
                                f"line still exists unchanged at {target}:{index + 1} "
                                f"and its complete added code occurs {detail}; port the hunk at this site")
            return None

        mechanisms = _claim_mechanism_tokens(claim.get("reason", ""), patch)
        strongest: tuple[int, str] | None = None
        for target in targets:
            analysis = self._target_baseline_analysis(target, qualified=qualified)
            if analysis is None:
                continue
            paths = analysis["paths"]
            anchor_indexes = [index for index, line
                              in enumerate(analysis["normalized"])
                              if line in anchors]
            for index in anchor_indexes:
                anchor_path = paths[index]
                if not anchor_path:
                    continue
                for token in mechanisms:
                    for hit in self._token_occurrences(analysis, token):
                        hit_path = paths[hit]
                        if not hit_path or hit_path[0] != anchor_path[0]:
                            continue
                        if _covers_path(hit_path, anchor_path):
                            return None
                        message = (f"semantic_equivalence is false: cited mechanism "
                                   f"{token} at {target}:{hit + 1} sits in a branch "
                                   f"that cannot execute on the anchor's path "
                                   f"(anchor at {target}:{index + 1}); port the hunk "
                                   "or cite a mechanism on the anchor's path")
                        if strongest is None or strongest[0] < 2:
                            strongest = (2, message)
            if anchor_indexes:
                absent = sorted(token for token in mechanisms
                                if not self._token_occurrences(analysis, token))
                if strongest is None:
                    if not mechanisms:
                        strongest = (1, "semantic_equivalence is unsupported: the "
                                        "claim names no equivalent target mechanism "
                                        f"while the anchor line still exists unchanged "
                                        f"in {target}")
                    elif absent:
                        strongest = (1, f"semantic_equivalence is unsupported: cited "
                                        f"mechanism(s) {', '.join(absent)} do not occur "
                                        f"in {target}, whose anchor line still exists "
                                        "unchanged")
                    else:
                        strongest = (1, "semantic_equivalence is unsupported: no cited "
                                        "mechanism occurs inside the anchor's function "
                                        f"in {target}; the anchor line still exists "
                                        "unchanged")
        return strongest[1] if strongest else None

    def model_scope(self, read_only=False):
        writable = () if read_only else tuple(self.worktree / p for p in self.case.files)
        if hasattr(self, '_scope_provider'):
            return self._scope_provider(writable)
        from .sandbox_scope import source_scope
        repositories = [self.repo, self.donor_repo]
        repositories.extend(Path(item['root']) for item in self.record.get('dependency_repositories', {}).values())
        return source_scope(self.run_dir, repositories, writable=writable, extra_readable=(self.worktree,),
                            denied=(self.source_root,))

    def _codex_workflow(self, inspection: dict[str, Any], verify: bool, max_attempts: int,
                        mechanical: bool = True, impact_only: bool = False) -> None:
        if self.runtime_factory is None:
            from .sdk_runtime import CodexRuntime
            factory = CodexRuntime
        else:
            factory = self.runtime_factory
        tools_context = ""
        if self.input_diff is None:
            bin_dir = self.run_dir / "bin"
            tools_context = (
                "Controlled tools (the ONLY sanctioned way to search history or locate code), "
                f"executable scripts in {bin_dir}:\n"
                f"  {bin_dir}/locate-symbol --repo target|donor --ref SHA --symbol NAME\n"
                f"  {bin_dir}/view-code --repo target|donor --ref SHA --path P --start N --end M\n"
                f"  {bin_dir}/hunk-history --hunk-id ID\n"
                f"  {bin_dir}/show-commit --sha SHA [--hunk-id ID]\n"
                "Whitelisted refs are the commits recorded in run.json plus SHAs that "
                "hunk-history reports. A tool may answer NOT_AVAILABLE (for example donor "
                "history not deepened); treat that as a hard fact, never fetch anything.\n")
        context = (f"\nTarget workspace: {self.worktree}\n"
                   + (f"Donor objects: git --git-dir={self.donor_repo} show <commit>:<path>.\n" if self.donor_root else "")
                   + tools_context
                   + "Controller runs configured validation. Do not commit, stage, reset, clean, fetch, pull, or run unbounded recursive searches; use the controlled tools instead. Do not read oracles or run PoCs.\n")
        source_diff = inspection["source_diff"]
        from .hunk_groups import review_prompt
        context += review_prompt(inspection['review_groups'])
        self._current_hunks = inspection["hunks"]
        symbol_report = inspection.get("symbol_report")
        symbol_report_text = (symbol_report.get("summary", "") +
                              "\nIdentifiers not found in the searched scope: " +
                              ", ".join(e["name"] for e in symbol_report.get("missing", []))
                              ) if symbol_report else None
        handoff = self.location_handoff
        accepted_impact = None
        impact_schema = IMPACT_SCHEMA
        if handoff:
            from .location_handoff import BACKEND_SCHEMA, EDIT_SCHEMA
            if handoff.accepted_impact is not None:
                accepted_impact = self._ground_assessment(handoff.accepted_impact)
                self.record['backend_impact_reused'] = True
            impact_schema = EDIT_SCHEMA if accepted_impact else BACKEND_SCHEMA
        runtime_options = dict(events_path=self.run_dir / "sdk-events.jsonl", model=self.model,
                               model_provider=self.model_provider, turn_timeout=self.turn_timeout, env=OFFLINE_GIT_ENV)
        analysis_options = runtime_options
        if handoff and handoff.budget:
            analysis_options = {**runtime_options, 'turn_timeout': min(self.turn_timeout, handoff.budget.remaining())}
        with ExitStack() as runtimes:
            analysis_runtime = runtimes.enter_context(ExitStack())
            runtime = analysis_runtime.enter_context(factory(**analysis_options,
                read_scope=self.model_scope(read_only=bool(handoff))))
            self.record["thread_id"] = runtime.start(str(self.worktree), SYSTEM + context)
            # Diff 预处理：版本拷贝型 donor diff 提取安全修复 hunks +
            # 推断漏洞类别，为影响判断提供定向搜索策略
            from .diff_analysis import preprocess_donor_diff
            preprocessed = preprocess_donor_diff(source_diff, self.commit_message)
            if preprocessed["preprocessed"]:
                # Classification is a retrieval hint only. Never remove build,
                # metadata or unfamiliar changes from the causal assessment.
                self.record["donor_diff_preprocessed"] = {
                    "type": preprocessed["type"],
                    "vulnerability_class": preprocessed["vulnerability_class"],
                    "extracted_hunks": preprocessed["extracted_hunks"],
                    "suggested_focus_omissions": preprocessed["filtered_hunks"],
                    "filtered_hunks": 0,
                    "original_diff_lines": preprocessed["original_diff_lines"]}
                self._event("donor_diff_preprocessed", **self.record["donor_diff_preprocessed"])
            impact_request = impact_prompt(self.case, source_diff, self.commit_message,
                                           symbol_report_text,
                                           vulnerability_class=preprocessed.get("vulnerability_class"),
                                           preprocessed=preprocessed["preprocessed"]) + context
            if accepted_impact:
                impact_request = 'Resolve the migration scope using the accepted assessment. Work read-only.\n' + context
            handoff_instructions = handoff.instructions(reused_impact=bool(accepted_impact)) if handoff else ''
            impact_request += handoff_instructions
            assessment = None
            from copy import deepcopy
            from .assessment_repair import (REPAIR_SCHEMA, apply_repair, digest,
                                            repair_prompt, seed_context)
            from .execution_budget import ACTIVE_EXECUTION
            from .impact_proof import AssessmentGroundingError, assessment_diagnostic
            from .sdk_runtime import CodexRuntimeError, charge_report_correction
            from jsonschema import ValidationError, validate
            ledger = ACTIVE_EXECUTION.get()
            # Parsed report errors belong to the local field-repair loop, not
            # the SDK's whole-document format retry. Both charge one ledger.
            runtime.defer_schema_errors = True
            runtime.report_repository = self.case.repository
            raw_report, previous_failure = None, None
            impact_limit = ledger.phase_limit('impact_attempts', max_attempts) if ledger else max_attempts
            for impact_attempt in range(1, impact_limit + 1):
                correction = raw_report is not None
                scope_correction = bool(accepted_impact and handoff.scope_feedback and impact_attempt == 1)
                if correction:
                    charge_report_correction(phase='impact_correction', repository=self.case.repository)
                elif scope_correction:
                    charge_report_correction(phase='backend_scope_correction', repository=self.case.repository)
                diagnostic, grounding_errors = None, None
                try:
                    result = self._turn(runtime, impact_request, read_only=True,
                                        phase=('impact_correction' if correction else
                                               'backend_scope_correction' if scope_correction else 'impact'),
                                        schema=REPAIR_SCHEMA if correction else impact_schema)
                    self.record['impact_report'] = result.get('final_response', '')
                    response = result.get('output', result['final_response'])
                    if isinstance(response, str):
                        response = json.loads(response)
                    if correction:
                        self._json(f'impact-repair-{impact_attempt}.json', response)
                        try:
                            raw_report = apply_repair(raw_report, response, schema=impact_schema)
                        except AssessmentError as exc:
                            exc.diagnostic = {'category': 'REPORT_SCHEMA', 'path': '/',
                                              'message': str(exc)[:1200]}
                            raise
                    else:
                        raw_report = response
                    self._json(f'impact-report-{impact_attempt}.json', raw_report)
                    validate(raw_report, impact_schema)
                    response = deepcopy(raw_report)
                    assessment = accepted_impact or self._ground_assessment(response['impact'] if handoff else response)
                    break
                except CodexRuntimeError as exc:
                    # A syntax failure already spent the one SDK format retry.
                    # Only a parsed schema-invalid *initial* report becomes a
                    # new repair base; malformed corrections never replace it.
                    diagnostic = exc.details.get('output_diagnostic')
                    if exc.kind != 'INVALID_OUTPUT' or not diagnostic or diagnostic['category'] != 'REPORT_SCHEMA':
                        raise
                    self._sweep_tool_usage()
                    self.audit_diff(require_clean=True)
                    if not correction:
                        raw_report = exc.details.get('parsed_output')
                        self.record['impact_report'] = exc.details.get('final_response', '')
                        self._json(f'impact-report-{impact_attempt}.json', raw_report)
                except json.JSONDecodeError:
                    # Test/adaptor runtimes without SDK validation still cannot
                    # invent a repair base for an unparseable document.
                    raise
                except (AssessmentError, ValidationError, ValueError) as exc:
                    diagnostic = assessment_diagnostic(exc, raw_report, wrapped=bool(handoff))
                    if isinstance(exc, AssessmentGroundingError):
                        grounding_errors = [assessment_diagnostic(error, raw_report, wrapped=bool(handoff))
                                            for error in exc.errors]
                if not isinstance(raw_report, dict):
                    raise AssessmentError('impact report must be an object for local correction')
                diagnostics = grounding_errors or [diagnostic]
                self._event('impact_evidence_rejected', attempt=impact_attempt,
                            error=diagnostic['message'], diagnostic=diagnostic, diagnostics=diagnostics)
                self.record.setdefault('impact_report_rejections', []).append(
                    {'attempt': impact_attempt, 'base_sha256': digest(raw_report),
                     'diagnostic': diagnostic, 'diagnostics': diagnostics,
                     'dependent_proof_deferred': grounding_errors is not None})
                self._json(f'impact-rejection-{impact_attempt}.json', self.record['impact_report_rejections'][-1])
                signature = tuple((item['category'], item['path'], item['message']) for item in diagnostics)
                if impact_attempt == impact_limit or (ledger and signature == previous_failure):
                    error = AssessmentError(diagnostic['message'])
                    error.diagnostic = diagnostic
                    error.diagnostics = diagnostics
                    raise error
                previous_failure = signature
                deferred = ('\nChecks that depend on grounded citations will run after these citations are repaired.'
                            if grounding_errors is not None else '')
                impact_request = (repair_prompt(raw_report, json.dumps(diagnostics, ensure_ascii=False)) + deferred
                    + seed_context(raw_report, self.run_dir / f'impact-seed-{impact_attempt}.txt')
                    + '\nThis is a backend report. Preserve all unchanged evidence and its indices. '
                      'An AFFECTED conclusion requires the full pinned-source causal proof. '
                      'Repository-internal behavior belongs in ordinary source evidence and causal '
                      'explanations, never in external_behavior_assumptions to bypass proof. '
                      'A platform API signature must identify the actual definition and overload; '
                      'renaming or removing a behavior claim cannot resolve missing evidence. '
                      'If a material fact remains unresolved, retain that gap and UNKNOWN. '
                    + handoff_instructions)
                if any(item['path'].endswith('/causal_chain/external_behavior_assumptions')
                       for item in diagnostics):
                    impact_request += (
                        '\nFor each reported behavior premise, identify the proof step it affects. '
                        'Starting from existing valid citations and the pinned locations, use the controlled '
                        'read-only source tools within the current budget. Follow only relevant direct callers, '
                        'callees, branch conditions or callbacks. Cite the implementation and the branch '
                        'that applies in the target, and link the citation to the proof. '
                        'If a material premise cannot be grounded, return UNKNOWN, name the unresolved '
                        'proof step and explain the missing evidence. Do not restart repository discovery.')
            runtime.defer_schema_errors = False
            assert assessment is not None
            self.record["assessment"] = assessment
            self.record["impact_decision"] = assessment["status"].lower()
            self.record["model_execution"] = "succeeded"
            self._json("impact.json", assessment)
            self._event("impact_grounded", status=assessment["status"], evidence=len(assessment["evidence"]))
            if handoff:
                analysis_runtime.close()
                migration_scope = handoff.accept(self, assessment, response, impact_only=impact_only)
                if not migration_scope:
                    return
                from .retrieval import suspend_investigation_budget
                if handoff.budget:
                    runtimes.enter_context(handoff.budget.phase('MIGRATION'))
                runtimes.enter_context(suspend_investigation_budget())
                handoff.activate(migration_scope, verify=verify)
                runtime = runtimes.enter_context(factory(**runtime_options, read_scope=self.model_scope()))
                self.record['migration_thread_id'] = runtime.start(str(self.worktree), SYSTEM + context)
            if impact_only:
                self.record["status"] = assessment["status"]
                return
            if assessment["status"] == "UNKNOWN":
                self.record["status"] = "INCONCLUSIVE"; return
            if assessment["status"] in ("NOT_AFFECTED", "ALREADY_FIXED"):
                self.record["status"] = assessment["status"]; return
            # AFFECTED — mechanical migration first (R2; r2 revision 1: only
            # after the impact phase so the assessment saw a clean baseline).
            from .execution_budget import ACTIVE_EXECUTION
            execution = ACTIVE_EXECUTION.get()
            resume_id = (getattr(self, 'resume_candidate_id', None)
                         or (getattr(execution, 'resume_candidates', {}).get(self.mapping_repository or self.case.repository)
                             if execution else None))
            restored_patch = None
            if resume_id:
                from .candidate_store import for_agent
                restored_patch = for_agent(self).restore(self, resume_id)
            if restored_patch:
                migration = {'hunks': [], 'applied': [], 'failed': [], 'skipped': [],
                             'starting_state': 'partial', 'restored_candidate_id': resume_id}
            elif mechanical:
                migration = self.mechanical_migration(inspection)
            else:
                migration = {"hunks": [], "applied": [], "failed": [],
                             "skipped": [h["id"] for h in inspection["hunks"]],
                             "starting_state": "none", "skipped_reason": "no_mechanical"}
            if migration.get('applied'):
                self._begin_candidate_attempt('mechanical')
                self._archive_candidate(self._render_patch(), outcome='MECHANICAL_DRAFT')
                self._finish_candidate_attempt('MECHANICAL_DRAFT')
            ladder_ctx: dict[str, Any] = {
                "applied_hunk_ids": migration["applied"],
                "failed_hunks": [e for e in migration["hunks"] if e["status"] == "failed"],
                "missing_symbols": [e["name"] for e in (symbol_report or {}).get("missing", [])],
                "history_available": self._history_available(),
            }
            candidate_limit = execution.limits['candidate_turns'] if execution else max_attempts
            plan = [level for level in ladder_plan(ladder_ctx)][:max(1, candidate_limit)]
            base_prompt = (backport_prompt(self.case, source_diff, assessment,
                                           commit_message=self.commit_message,
                                           starting_state=self._starting_state_text(migration, inspection))
                           + context
                           + "\nDonor hunk applicability (textual only):\n"
                           + json.dumps([{k: v for k, v in h.items() if k != "patch"}
                                         for h in inspection["hunks"]])
                           + f"\nThe controller will run {len(self.case.validation)} independent configured checks "
                           "after your edits. Their implementation is not part of the model input.")
            if self.mapping_plan:
                regions = [t for t in self.mapping_plan.targets(self.mapping_repository)
                           if t['status'] == 'AFFECTED' and t['action'] == 'edit']
                base_prompt += ("\nPinned edit obligations (one per region):\n"
                                + json.dumps(regions, ensure_ascii=False)
                                + "\nImplement each obligation with executable edits in its mapped region. "
                                  "For an unchanged Java method, only a closed set of directly guarded "
                                  "callers can establish coverage. Check for alternate callers before relying on a guard. "
                                  "Explain the target-specific change and guarded call paths in the HUNK-RESULT.\n")

                contract = self.mapping_plan.data().get('repair_contract', [])
                if contract:
                    base_prompt += ("\nRequired guarded repair behaviors. Implement every edit obligation "
                                    "and preserve existing protection. Verify the same object remains protected "
                                    "during the entire hazardous period, including after a pending transition starts. "
                                    "Ground release and alternate cleanup paths.\n"
                                    + json.dumps(contract, ensure_ascii=False))
            if handoff and handoff.flag_support:
                base_prompt += ('\nThe controller verified these donor flag cleanups have no target counterpart. '
                                'Use evidence=no_target_counterpart for the listed units if they require no edit.\n'
                                + json.dumps(handoff.flag_support, ensure_ascii=False))
            if handoff and handoff.location_gaps:
                base_prompt += ('\nWrite a draft for the pinned edit obligations only. Do not guess at these '
                                'unresolved locations: ' + json.dumps(handoff.location_gaps, ensure_ascii=False))
                plan = plan[:1]
            obligation_failures = 0
            self.record["attempts"] = []
            self.record.setdefault("attempt_verifications", {})
            diagnosis_json: dict[str, Any] | None = None
            claim_feedback: str | None = None
            failing_stages: list[str] = []
            previous_patch_shas: list[str] = []
            for attempt, level in enumerate(plan, 1):
                self._finish_candidate_attempt(self.record.get('status', 'COMPLETED'))
                self.record["attempt"] = attempt
                prompt = base_prompt + "\n" + (strategy_prompt(
                    level["index"], {**ladder_ctx, "diagnosis_json": diagnosis_json,
                                     "claim_feedback": claim_feedback,
                                     "failing_stages": failing_stages}) or "")
                if diagnosis_json is not None:
                    # The structured diagnosis must ride EVERY retry strategy,
                    # not only T2: without it the model never sees which
                    # javac/grep failure to fix and re-exports identical
                    # patches (mb-007 lesson: three byte-identical candidates).
                    rendered = json.dumps(diagnosis_json, ensure_ascii=False)
                    prompt += ("\nStructured diagnosis of the verification failures your LAST "
                               "candidate must fix (controller's independent checks):\n"
                               + (rendered if len(rendered) < 12000 else
                                  json.dumps({"summary": diagnosis_json.get("summary", ""),
                                              "truncated": True}, ensure_ascii=False))
                               + "\n")
                if len(previous_patch_shas) >= 2 and previous_patch_shas[-1] == previous_patch_shas[-2]:
                    prompt += ("\nIMPORTANT: your previous two turns produced byte-identical patches, "
                               "so every failure above is still unfixed. Re-submitting the same files "
                               "cannot pass. You MUST actually change the workspace this turn.\n")
                self.record.setdefault("backport_reports", [])
                self.record["attempts"].append(
                    {"index": attempt, "strategy": level["strategy"], "turn_id": None,
                     "patch_sha256": None})
                self._begin_candidate_attempt('model', strategy=level['strategy'], runtime=runtime)
                try:
                    result = self._turn(runtime, prompt, read_only=False,
                                        phase=f"backport_{level['strategy']}")
                    patch = self.export_patch(attempt)
                except RuntimeError as exc:
                    message = str(exc)
                    # Ordinary wrong-file edits retry with feedback; security
                    # violations (symlink escape, moved HEAD, dirtied source
                    # checkout) stay fatal.
                    retryable = (isinstance(exc, CandidateRejected)
                                 or ("diff audit failed" in message
                                     and "unsafe_paths': []" in message
                                     and "head_unchanged': True" in message
                                     and "original_checkout_unchanged': True" in message))
                    if not retryable:
                        raise
                    # A rejected workspace (wrong file edited) is model
                    # feedback, not a fatal condition: the ladder retries
                    # with the exact audit contradiction.
                    self.record["backport_reports"].append("")
                    self.record["status"] = "VALIDATION_FAILED"
                    self._event("patch_export_rejected", attempt=attempt, error=str(exc))
                    blocked_by = ("NEW_FILE_INTEGRATION" if isinstance(exc, CandidateRejected)
                                  else "PATCH_EXPORT")
                    self.record["attempt_verifications"][str(attempt)] = {
                        "status": "NOT_RUN", "blocked_by": blocked_by,
                        "patch_sha256": None, "commands": []}
                    self.record["final_verification"] = self.record["attempt_verifications"][str(attempt)]
                    claim_feedback = (exc.feedback if isinstance(exc, CandidateRejected) else
                        "Your workspace changes were rejected by the export audit: "
                        f"{exc} Revert every edit outside the allowlisted case files "
                        f"{sorted(self.case.files)} and place the fix in the correct "
                        "allowlisted file.")
                    failing_stages = ["patch_export"]
                    audit = self.record.get('new_file_audits', {}).get(str(attempt), {})
                    subjects = ({'rejected_paths': sorted(row['path'] for row in audit.get('rejected', []))}
                                if isinstance(exc, CandidateRejected) else
                                {'unexpected_paths': json.loads((self.run_dir / 'diff-audit.json').read_text())['unexpected_files']})
                    if self._migration_repeated_error(blocked_by, subjects):
                        return
                    continue
                self.record["backport_reports"].append(result.get("final_response", ""))
                self.record["attempts"][-1]["turn_id"] = result.get("turn_id")
                self.record["attempts"][-1]["patch_sha256"] = self.record["patch_sha256"]
                previous_patch_shas.append(self.record["patch_sha256"])
                if handoff and handoff.location_gaps and patch.strip():
                    self.record.update(status='MIGRATION_INCOMPLETE', final_verification={
                        'status': 'NOT_RUN', 'blocked_by': 'MIGRATION_SCOPE_UNRESOLVED',
                        'patch_sha256': self.record['patch_sha256'], 'commands': []})
                    return
                if not patch.strip():
                    self.record["status"] = "VALIDATION_FAILED"
                    self._event("empty_patch", attempt=attempt,
                                allowlist=list(self.case.files))
                    diagnosis_json = {
                        "summary": "The AFFECTED assessment produced an empty patch.",
                        "allowlist": list(self.case.files),
                        "required_action": (
                            "Modify at least one allowlisted target file with the smallest "
                            "semantically complete security fix; do not submit another "
                            "no-change response."),
                    }
                    claim_feedback = None
                    failing_stages = []
                    self.record["attempt_verifications"][str(attempt)] = {
                        "status": "NOT_RUN", "blocked_by": "EMPTY_PATCH",
                        "patch_sha256": self.record["patch_sha256"], "commands": []}
                    self.record["final_verification"] = self.record["attempt_verifications"][str(attempt)]
                    if self._migration_repeated_error('EMPTY_PATCH', {'allowlist': sorted(self.case.files)}):
                        return
                    continue
                claims = self._check_hunk_results(
                    result.get("final_response", ""),
                    self._last_audit["changed_files"], patch, review_mapped=True)
                self.record["hunk_results"] = claims["claims"]
                self._candidate_evidence('coverage', {
                    'status': 'PASS' if claims['ok'] else 'FAIL',
                    'claims': claims, 'repair_obligation_review': self.record.get('repair_obligation_review'),
                    'patch_sha256': self.record['patch_sha256']})
                self._migration_progress(claims=claims)
                if not claims["ok"]:
                    # P1.6 / r2 revision 6: contradicted or missing declarations
                    # fail the turn; feedback goes to the next ladder level.
                    self.record["status"] = "VALIDATION_FAILED"
                    self._event("hunk_result_check_failed",
                                contradictions=claims["contradictions"],
                                missing_declaration=claims["missing_declaration"])
                    self.record["attempt_verifications"][str(attempt)] = {
                        "status": "NOT_RUN", "blocked_by": "HUNK_LEDGER",
                        "patch_sha256": self.record["patch_sha256"], "commands": []}
                    self.record["final_verification"] = self.record["attempt_verifications"][str(attempt)]
                    claim_feedback = claims["feedback"]
                    diagnosis_json = None
                    obligation_review = self.record.get('repair_obligation_review')
                    if obligation_review and obligation_review.get('status') != 'COVERED':
                        rows = obligation_review.get('obligations', [])
                        if any(row['verdict'] == 'remap' for row in rows):
                            self.record['obligation_remap_required'] = True
                            return
                        obligation_failures += 1
                        repeated = len(previous_patch_shas) >= 2 and previous_patch_shas[-1] == previous_patch_shas[-2]
                        if execution is None and (obligation_failures >= 3 or repeated):
                            self.record['obligation_repairs_exhausted'] = True
                            return
                    subjects = {'coverage': {key: claims['coverage'][key] for key in
                                             ('missing', 'duplicate', 'unexpected')},
                                'missing_declaration': claims['missing_declaration']}
                    if obligation_review:
                        subjects['obligations'] = sorted((row['id'], entry['id'], entry['verdict'])
                            for row in obligation_review.get('obligations', [])
                            for entry in row.get('paths', []) if entry['verdict'] in ('unresolved', 'remap'))
                    else:
                        subjects['contradictions'] = sorted(claims['contradictions'])
                    if self._migration_repeated_error('HUNK_LEDGER', subjects):
                        self.record['obligation_repairs_exhausted'] = bool(obligation_review)
                        return
                    continue
                claim_feedback = None
                if not verify:
                    self.record.update(status="PATCH_UNVERIFIED", final_verification={"status": "NOT_REQUESTED", "commands": []},
                                       post_fix_review={'status': 'NOT_REQUESTED'}); return
                verification = self.verify()
                self.record["final_verification"] = verification
                self.record["attempt_verifications"][str(attempt)] = verification
                self._candidate_evidence('verification', verification)
                self._migration_progress(verification=verification)
                if verification["status"] == "PASS":
                    self.record["status"] = 'VALIDATED' if verification['sufficient_for_validated'] else 'PATCH_UNVERIFIED'
                    if not getattr(self, 'defer_post_fix', False):
                        self.assess_post_fix(runtime, patch, context)
                    return
                if verification["status"] == "NOT_CONFIGURED":
                    self.record["status"] = "PATCH_UNVERIFIED"; return
                self.record["status"] = "VALIDATION_FAILED"
                diagnosis_json = verification_diagnosis(verification["commands"])
                failing_stages = [stage for stage, outcome in verification["stages"].items()
                                  if outcome == "FAIL"]
                failed = [{'stage': row.get('stage'), 'argv': row.get('argv'),
                           'returncode': row.get('returncode'),
                           'output_sha256': hashlib.sha256(json.dumps({key: row.get(key) for key in
                               ('stdout', 'stderr', 'error')}, sort_keys=True).encode()).hexdigest()}
                          for row in verification['commands'] if row.get('returncode') != 0]
                if self._migration_repeated_error('VERIFICATION', {'commands': failed}):
                    return
            # Preserve the candidate and evidence for human review. The run is a
            # completed *attempt* but not a successful security validation.
            self.record["status"] = "VALIDATION_FAILED"
            return

    def _migration_progress(self, *, claims=None, verification=None):
        """Grant progress only for new controller-checked milestones.

        A new patch hash, larger diff or rewritten explanation is not progress.
        Stable source/obligation/check identities deduplicate across resumes.
        """
        from .execution_budget import ACTIVE_EXECUTION
        from .candidate_store import agent_identity
        execution = ACTIVE_EXECUTION.get()
        if execution is None:
            return
        identity = agent_identity(self)
        facts = []
        if self.record.get('patch_replay') == 'pass':
            facts.append({'kind': 'clean_replay', 'identity': identity})
        if claims is not None:
            receipt = self.record.get('repair_obligation_review', {})
            if receipt.get('patch_sha256') == self.record.get('patch_sha256'):
                for row in receipt.get('obligations', []):
                    if row.get('verdict') == 'covered':
                        facts.append({'kind': 'covered_obligation', 'identity': identity, 'id': row['id'],
                                      'paths': sorted(entry['id'] for entry in row.get('paths', []))})
            for claim in claims.get('claims', []):
                evidence = claim.get('target_evidence', {})
                if evidence.get('required') and evidence.get('ok'):
                    facts.append({'kind': 'grounded_hunk_coverage', 'identity': identity, 'id': claim['id']})
        if verification is not None:
            for row in verification.get('commands', []):
                if row.get('returncode') == 0:
                    facts.append({'kind': 'check_pass', 'identity': identity,
                                  'stage': row.get('stage'), 'argv': row.get('argv')})
        execution.record_progress('migration:' + identity['repository'], facts)

    def _migration_repeated_error(self, kind, subjects):
        from .execution_budget import ACTIVE_EXECUTION
        execution = ACTIVE_EXECUTION.get()
        phase = 'migration:' + (self.mapping_repository or self.case.repository)
        if execution is None or not execution.repeated_error(phase, kind, subjects):
            return False
        self.record.update(completion_blocked_by='REPEATED_ERROR_NO_PROGRESS',
            repeated_error={'phase': phase, 'kind': kind, 'subjects': subjects})
        self._event('migration_repeated_error', kind=kind, subjects=subjects)
        return True

    def _begin_candidate_attempt(self, source_kind, strategy=None, runtime=None):
        from .candidate_store import for_agent, agent_identity
        from .execution_budget import ACTIVE_EXECUTION
        execution = ACTIVE_EXECUTION.get()
        operation = execution.current_operation() if execution else None
        recovery = {'writer_policy': 'controller_broker_only' if getattr(runtime, '_broker', None) is not None else 'UNVERIFIED',
            'runtime_child': runtime.recovery_child() if callable(getattr(runtime, 'recovery_child', None)) else None,
            'worktree': str(self.worktree), 'source_root': str(self._source_scope),
            'source_repo': str(self.repo), 'source_state': self._source_before,
            'target_commit': self.record.get('target_commit', self.case.target_commit),
            'allowlist': list(self.case.files), 'artifact_paths': sorted(self._artifact_paths)}
        self._candidate_attempt_id = for_agent(self).begin(agent_identity(self),
            source_record=self.run_dir / 'run.json', source_kind=source_kind,
            strategy=strategy, operation_id=operation.get('id') if operation else None,
            recovery=recovery,
            parent=self.record.get('candidate_id') or (self.record.get('restored_candidate', {}).get('id')
                if self.record.get('restored_candidate', {}).get('status') == 'DRAFT' else None))
        self.record['candidate_attempt_id'] = self._candidate_attempt_id
        self.record['candidate_history'] = for_agent(self).summary(agent_identity(self))
        self._write_record()

    def _archive_candidate(self, patch, *, outcome='EXPORTED', source_kind=None):
        from .candidate_store import for_agent, agent_identity
        if not getattr(self, '_candidate_attempt_id', None):
            self._begin_candidate_attempt(source_kind or 'controller_export')
        ident = for_agent(self).observe(self._candidate_attempt_id, patch,
                                       source_kind=source_kind, outcome=outcome)
        self.record['candidate_id'] = ident
        # A new observation cannot carry the previous attempt's delivery fields.
        # Exact historical receipts remain attached to their archived candidate.
        sha = hashlib.sha256(patch.encode()).hexdigest()
        previous_review = self.record.get('post_fix_review') or {}
        stale_review = ({**previous_review, 'status': 'STALE', 'superseded_by': sha}
                        if previous_review.get('patch_sha256') else {'status': 'NOT_REQUESTED'})
        self.record.update(patch_file=None, patch_sha256=sha, patch_replay='not_run',
            final_verification={'status': 'NOT_RUN', 'commands': []},
            post_fix_review=stale_review, verification_memory={})
        for stale in ('patch_replay_evidence', 'post_fix_impact', 'post_fix_patch_sha256'):
            self.record.pop(stale, None)
        self.record['candidate_history'] = for_agent(self).summary(agent_identity(self))
        return ident

    def _candidate_evidence(self, kind, receipt):
        from .candidate_store import for_agent, agent_identity
        ident = self.record.get('candidate_id')
        if ident:
            for_agent(self).evidence(ident, kind, receipt)
            self.record['candidate_history'] = for_agent(self).summary(agent_identity(self))

    def _finish_candidate_attempt(self, status, error=None):
        from .candidate_store import for_agent, agent_identity
        ident = getattr(self, '_candidate_attempt_id', None)
        if ident:
            for_agent(self).finish(ident, status=status, error=error)
            self._candidate_attempt_id = None
            self.record['candidate_history'] = for_agent(self).summary(agent_identity(self))

    def _preserve_interrupted_candidate(self, exc):
        """Called only after the runtime context has drained its writer processes.

        A failed cleanup or source audit prevents even diagnostic export. Raw
        bytes saved here do not become patch_file, replay, coverage or delivery.
        """
        if not getattr(self, '_candidate_attempt_id', None):
            return
        peer_audit = getattr(self, '_backend_turn_audit', None)
        if (getattr(exc, 'kind', None) in ('BACKGROUND_CLEANUP_FAILED', 'NATIVE_TOOL_BYPASS',
                                          'SOURCE_AUDIT_UNVERIFIED')
                or peer_audit and not peer_audit[1]):
            self.record['candidate_preservation'] = {'status': 'BLOCKED',
                'reason': getattr(exc, 'kind', 'SOURCE_AUDIT_UNVERIFIED')}
            return
        try:
            from .retrieval import suspend_investigation_budget
            with suspend_investigation_budget():
                audit = self.audit_diff()
                patch = self._render_patch(audit)
                from .candidate_store import for_agent
                attempt = for_agent(self).snapshot()['attempts'][self._candidate_attempt_id]
                # Export already persisted these exact bytes before a later
                # coverage/build/report failure; preserve their original state.
                if (attempt.get('candidate_id') and self.record.get('patch_sha256') ==
                        hashlib.sha256(patch.encode()).hexdigest()):
                    ident = attempt['candidate_id']
                else:
                    ident = self._archive_candidate(patch, outcome='INTERRUPTED_DRAFT',
                                                    source_kind='recovered_workspace')
            self.record['candidate_preservation'] = {'status': 'SAVED' if ident else 'NO_NEW_CANDIDATE',
                'candidate_id': ident, 'validation_reused': False}
        except Exception as preservation_error:
            self.record['candidate_preservation'] = {'status': 'BLOCKED',
                'reason': type(preservation_error).__name__, 'message': str(preservation_error)[:500]}

    def assess_post_fix(self, runtime, patch, context=''):
        """Optional analysis may fail, but even a read-only turn must not edit."""
        before = hashlib.sha256(self._render_patch().encode()).hexdigest()
        try:
            verification = self.record.get('final_verification', {})
            evidence = {k: verification[k] for k in ('status', 'stages', 'policy', 'sufficient_for_validated') if k in verification}
            result = runtime.run(post_fix_prompt(self.case, patch) + context +
                                 '\nActual local verification evidence:\n' + json.dumps(evidence),
                                 read_only=True, output_schema=POST_FIX_SCHEMA)
            if result.get('status') != 'completed':
                raise RuntimeError('post-fix assessment did not complete')
            output = result.get('output') or json.loads(result.get('final_response', '{}'))
            from jsonschema import validate
            validate(output, POST_FIX_SCHEMA)
            self.record['post_fix_impact'] = output
            self._json('post-fix-impact.json', output)
            self._event('post_fix_impact_assessed', overall_risk=output.get('overall_risk'))
        except Exception as exc:
            message = re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))[:200]
            self.record['post_fix_impact'] = {'error': message}
            self._event('post_fix_impact_failed', error=message)
        finally:
            self.audit_diff()
            if hashlib.sha256(self._render_patch().encode()).hexdigest() != before:
                raise RuntimeError('post-fix assessment modified the candidate')
        self.record['post_fix_patch_sha256'] = before
        self.record['post_fix_review'] = {
            'status': 'INCOMPLETE' if self.record.get('post_fix_impact', {}).get('error') else 'COMPLETED',
            'patch_sha256': before, 'scope': 'model_business_impact_review', 'runtime_security_proven': False}
        from .delivery import update_delivery
        update_delivery(self.record)

    @source_guard('_source_scope')
    def run(self, *, use_codex: bool = True, verify: bool = False, max_attempts: int = 6,
            mechanical: bool = True, impact_only: bool = False) -> dict[str, Any]:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        try:
            if not self._owns_run: self.prepare()
            inspection = self.inspect()
            if not use_codex:
                self.record.update(status="PREPARED", model_skipped=True)
            else:
                self._codex_workflow(inspection, verify, max_attempts, mechanical=mechanical,
                                     impact_only=impact_only)
            self.audit_diff(require_clean=not use_codex)
            self._write_record()
            if self.record.get('candidate_id') and self.record.get('patch_sha256'):
                self._candidate_evidence('delivery', {key: self.record[key] for key in
                    ('status', 'patch_sha256', 'delivery', 'build_validation', 'review_status') if key in self.record})
            self._finish_candidate_attempt(self.record['status'])
            self._write_record(); return self.record
        except (Exception, KeyboardInterrupt) as exc:
            if self._owns_run:
                self._preserve_interrupted_candidate(exc)
                message = re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED]", str(exc))
                existing_kind = self.record.get("error", {}).get("kind")
                self.record.update(status="CANCELLED" if isinstance(exc, KeyboardInterrupt) else "FAILED", model_execution=("failed" if self.record.get("model_execution") == "not_run" else self.record.get("model_execution")), error={"kind": existing_kind or getattr(exc, "kind", _codex_error_kind(message)),
                               "type": type(exc).__name__, "message": message})
                self._finish_candidate_attempt(self.record['status'], self.record['error'])
                self._event("failed", **self.record["error"])
            raise

    @controller_audit('engine.audit_diff')
    def audit_diff(self, *, require_clean: bool = False, expected_source_head=None) -> dict[str, Any]:
        expected = self._git("rev-parse", self.case.target_commit).stdout.strip()
        head = self._git("rev-parse", "HEAD", cwd=self.worktree).stdout.strip()
        tracked = set(filter(None, self._git("diff", "--name-only", "-z", "--no-renames", self.case.target_commit,
                                             cwd=self.worktree).stdout.rstrip("\0").split("\0")))
        untracked = set(filter(None, self._git("ls-files", "--others", "--exclude-standard", "-z",
                                               cwd=self.worktree).stdout.rstrip("\0").split("\0")))
        untracked -= self._artifact_paths
        # out-artifacts/ is the controller-owned destination the module-build
        # script copies compiled artifacts into; it is never model output.
        untracked = {path for path in untracked if not path.startswith("out-artifacts/")}
        changed = sorted(tracked | untracked); unsafe = []
        for relative in self.case.files:
            path = self.worktree / relative
            if path.is_symlink() or not path.resolve().is_relative_to(self.worktree): unsafe.append(relative)
        check = self._git("diff", "--check", self.case.target_commit, cwd=self.worktree, check=False)
        source_before = self._source_before
        if source_before is not None and expected_source_head is not None:
            source_before = {**source_before, 'head': expected_source_head}
        unchanged = source_before is None or self._source_state() == source_before
        result = {"changed_files": changed, "untracked_files": sorted(untracked),
                  "unexpected_files": sorted(set(changed) - set(self.case.files)), "unsafe_paths": unsafe,
                  "head_unchanged": head == expected, "original_checkout_unchanged": unchanged,
                  "diff_check_returncode": check.returncode}
        self._json("diff-audit.json", result)
        if result["unexpected_files"] or unsafe or check.returncode or head != expected or not unchanged:
            raise RuntimeError(f"diff audit failed: {result}")
        if require_clean and changed: raise RuntimeError("read-only phase modified worktree")
        self._event("diff_audit", **result)
        self._last_audit = result
        return result

    def _artifact_baseline_text(self, path):
        """Exact bounded pinned reads for optional artifact-role evidence.

        Missing tree entries are absence; a failed read is never cached as one.
        The per-controller cache is immutable target metadata, not candidate data.
        """
        validate_relative_path(path)
        cache = self.__dict__.setdefault('_artifact_baseline_cache', {})
        if path not in cache:
            try:
                listing = self._git('--literal-pathspecs', 'ls-tree', '-z', self.case.target_commit, '--', path).stdout
                if not listing:
                    cache[path] = None
                else:
                    if not listing.startswith(('100644 blob ', '100755 blob ')):
                        raise ValueError('artifact metadata is not a regular blob: ' + path)
                    ref = f'{self.case.target_commit}:{path}'
                    if int(self._git('cat-file', '-s', ref).stdout) > 4 * 1024 * 1024:
                        raise ValueError('artifact metadata exceeds 4 MiB: ' + path)
                    cache[path] = self._git('show', '--no-ext-diff', '--no-textconv', ref).stdout
            except subprocess.SubprocessError as exc:
                raise RuntimeError('artifact metadata read failed: ' + path) from exc
        return cache[path]

    def _new_file_integration_audit(self, audit: dict[str, Any],
                                    candidate_patch: str) -> dict[str, Any]:
        """Reject invented production files that are not connected to live target code.

        Test/fixture additions are recorded but do not need a production
        reachability claim. Every new production source file needs an added call
        in a baseline-existing function or a manifest component registration. Build inclusion alone
        is deliberately insufficient: it proved unable to distinguish dead classes
        from real backports in the new16 batch.
        """
        result: dict[str, Any] = {"status": "PASS", "new_files": [], "rejected": [],
                                  'scope': 'local_source_integration', 'production_reachability_proven': False}
        try:
            candidate_hunks = split_hunks(candidate_patch)
        except ValueError as exc:
            return {"status": "FAIL", "new_files": [],
                    "rejected": [{"path": None, "reason": f"invalid candidate patch: {exc}"}]}
        # The exported diff includes staged additions too. ls-files --others alone
        # misses a new source as soon as a model stages it.
        new_paths = sorted({h['new_path'] for h in candidate_hunks
                            if h.get('old_path') is None and h.get('new_path')})
        if not new_paths:
            return result
        source_hunks = self._current_hunks
        if not source_hunks and self.input_diff:
            source_hunks = split_hunks(self.input_diff)
        donor_added_paths = {
            hunk.get("new_path") for hunk in source_hunks
            if hunk.get("old_path") is None and hunk.get("new_path")
        }
        by_path: dict[str, list[dict[str, Any]]] = {}
        for hunk in candidate_hunks:
            by_path.setdefault(hunk["path"], []).append(hunk)

        from .artifact_roles import artifact_kind, classify, python_test_shape, donor_test_definition
        # The assertion-script adapter binds to an actually changed preexisting
        # implementation, not a class/function invented alongside the test.
        changed_sources = {}
        caller_roles = {}
        for path in by_path:
            candidate = self.worktree / path
            if (path not in new_paths and Path(path).suffix == '.py' and candidate.is_file()
                    and candidate.stat().st_size <= 4 * 1024 * 1024):
                baseline = self._artifact_baseline_text(path)
                if baseline is not None and not python_test_shape(baseline):
                    changed_sources[path] = candidate.read_text()

        for path in new_paths:
            entry: dict[str, Any] = {"path": path, "status": "PASS"}
            candidate = self.worktree / path
            text = None
            if candidate.is_file() and candidate.stat().st_size <= 4 * 1024 * 1024:
                try:
                    text = candidate.read_text()
                except UnicodeError:
                    pass
            if text is None:
                role = {'role': 'unknown', 'production_repair_credit': False}
            else:
                role = classify(path, text, baseline_read=self._artifact_baseline_text,
                                changed_sources=changed_sources, executable=bool(candidate.stat().st_mode & 0o111))
            entry['classification'] = role
            if role['role'] == 'unknown':
                entry.update(status='FAIL', basis='unsupported_new_artifact',
                             reason='unknown artifact type or size; no implicit non-source exemption')
            elif role['role'] != 'source':
                entry['basis'] = role['role']
                # Auxiliary tests/docs/configuration cannot stand in for a
                # production source obligation merely by carrying its tokens.
                for source in source_hunks:
                    if path not in self._donor_targets(source.get('path', '')):
                        continue
                    source_kind = artifact_kind(source.get('path', ''))
                    source_test = False
                    if role['role'] == 'supplementary_test':
                        added = '\n'.join(line[1:] for line in source.get('patch', '').splitlines()
                                          if line.startswith('+') and not line.startswith('+++'))
                        source_test = (source.get('old_path') is None
                                       and donor_test_definition(source['path'], added))
                    if source_kind in ('source', 'unknown') and not source_test:
                        entry.update(status='FAIL', basis='auxiliary_artifact_cannot_implement_source',
                                     reason='supplementary artifact cannot satisfy production/unknown source unit ' + source['id'])
                        break
            else:
                entry['donor_created'] = path in donor_added_paths
                identities = _new_source_identities(path, by_path.get(path, []))
                activation = None
                for target_path, hunks in sorted(by_path.items()):
                    if (target_path == path or _is_build_only_path(target_path)
                            or _is_test_or_fixture_path(target_path)):
                        continue
                    baseline = self._target_baseline_lines(target_path)
                    if baseline is None:
                        continue
                    baseline_text = '\n'.join(baseline)
                    if len(baseline_text.encode()) > 4 * 1024 * 1024:
                        continue
                    if target_path not in caller_roles:
                        if donor_test_definition(target_path, baseline_text):
                            caller_roles[target_path] = {'role': 'supplementary_test',
                                'evidence': {'basis': 'baseline_test_definition'}}
                        else:
                            caller_roles[target_path] = classify(target_path, baseline_text,
                                baseline_read=self._artifact_baseline_text, changed_sources={})
                    if caller_roles[target_path]['role'] == 'supplementary_test':
                        result.setdefault('excluded_test_callers', {})[target_path] = caller_roles[target_path]
                        continue
                    from .integration import activation as find_activation
                    candidate = self.worktree / target_path
                    if not candidate.is_file():
                        continue
                    activation = find_activation(target_path, baseline_text,
                                                 candidate.read_text(), hunks, identities,
                                                 new_source={'path': path, 'text': (self.worktree / path).read_text()})
                    if (activation and activation.get('binding', {}).get('status') == 'RESOLVED_LEXICALLY'
                            and activation['binding'].get('target_source') == path):
                        break
                    activation = None
                if activation:
                    entry.update(basis="existing_target_integration", activation=activation)
                else:
                    entry.update(
                        status="FAIL",
                        basis="unintegrated_new_source",
                        reason=("no eligible locally reachable, lexically bound call in a baseline-existing function "
                                "or enabled exact-class manifest registration connects this new source; "
                                "dead/deferred calls, shadowed names and unsupported binding/structure do not count"),
                        identities=sorted(identities),
                    )
            if entry['status'] == 'FAIL':
                result['rejected'].append(entry)
            result["new_files"].append(entry)
        if result["rejected"]:
            result["status"] = "FAIL"
        return result

    @source_guard('_source_scope')
    def export_patch(self, attempt: int) -> str:
        audit = self.audit_diff()
        patch = self._render_patch(audit)
        self._archive_candidate(patch, outcome='EXPORTED_DRAFT')
        new_file_audit = self._new_file_integration_audit(audit, patch)
        self.record.setdefault("new_file_audits", {})[str(attempt)] = new_file_audit
        self._json(f"new-file-audit-{attempt}.json", new_file_audit)
        self._candidate_evidence('source_integration', {**new_file_audit,
            'patch_sha256': hashlib.sha256(patch.encode()).hexdigest()})
        if new_file_audit["status"] != "PASS":
            # Preserve rejected bytes separately and invalidate stale evidence from
            # a previously exported candidate. The final patch path is not a receipt.
            rejected_path = self.run_dir / f'rejected-candidate-{attempt}.patch'
            from .output_budget import write_text
            write_text(rejected_path, patch)
            self.record.update(patch_file=None, patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
                               patch_replay='not_run', rejected_patch_file=str(rejected_path),
                               verification_memory={})
            rejected = [entry["path"] for entry in new_file_audit["rejected"]]
            self._event("new_file_integration_rejected", attempt=attempt,
                        rejected_files=rejected)
            raise CandidateRejected(
                "new-file integration audit failed: " + ", ".join(str(p) for p in rejected),
                feedback=("The candidate created source files that do not exist at the target "
                          f"baseline and are not integrated by live target code: {rejected}. "
                          "Do not recreate a newer-version class merely because it is allowlisted. "
                          "Locate and edit the older target implementation instead. If a new helper "
                          "is genuinely required, also connect it from a baseline-existing source, "
                          "manifest, or registration file. Names alone do not establish a test role, "
                          "and supplementary tests/data cannot replace production source obligations. "
                          + json.dumps(new_file_audit['rejected'], ensure_ascii=False)),
            )
        from .output_budget import write_text
        write_text(self.run_dir / f"candidate-{attempt}.patch", patch)
        write_text(self.run_dir / "backport.patch", patch)
        check = self._check_application(patch)
        self.record.update(patch_file=str(self.run_dir / "backport.patch") if patch.strip() else None,
                           patch_sha256=hashlib.sha256(patch.encode()).hexdigest(), patch_application=check)
        self._event("patch_exported", attempt=attempt, sha256=self.record["patch_sha256"], application=check)
        replay = self._replay_clean_target(patch, attempt)
        self.record["patch_replay"] = replay["status"]
        self.record["patch_replay_evidence"] = replay
        self._candidate_evidence('replay', {**replay, 'patch_sha256': self.record['patch_sha256']})
        self.record["candidate_file_hashes"] = {
            relative: (hashlib.sha256((self.worktree / relative).read_bytes()).hexdigest()
                       if (self.worktree / relative).is_file() else None)
            for relative in audit["changed_files"]
        }
        if patch.strip() and check["status"] != "APPLIES_TEXTUALLY": raise RuntimeError("candidate does not apply cleanly")
        if patch.strip() and replay["status"] != "pass":
            raise RuntimeError("candidate failed independent clean-target replay")
        return patch

    def _replay_clean_target(self, patch: str, attempt: int) -> dict[str, Any]:
        """Apply the exported bytes in a fresh detached worktree and record provenance."""
        replay_dir = self.run_dir / f"replay-{attempt}"
        result: dict[str, Any] = {"status": "not_run", "worktree": str(replay_dir),
                                  "target_commit": self.record.get("target_commit", self.case.target_commit)}
        if not patch.strip():
            result["status"] = "fail"
            result["error"] = "empty patch"
            return result
        try:
            self._git("worktree", "add", "--detach", str(replay_dir), self.case.target_commit)
            applied = self._git("apply", "--check", "--binary", "-", cwd=replay_dir,
                                input=patch, check=False)
            result.update(returncode=applied.returncode, stderr=applied.stderr[-5000:])
            if applied.returncode == 0:
                applied = self._git("apply", "--binary", "-", cwd=replay_dir,
                                    input=patch, check=False)
                result.update(apply_returncode=applied.returncode, apply_stderr=applied.stderr[-5000:])
            result["status"] = "pass" if applied.returncode == 0 else "fail"
            if result["status"] == "pass":
                tracked = self._git("diff", "--name-only", self.case.target_commit,
                                    cwd=replay_dir).stdout.splitlines()
                untracked = self._git("ls-files", "--others", "--exclude-standard",
                                      cwd=replay_dir).stdout.splitlines()
                result["changed_files"] = sorted(set(tracked + untracked))
                result["untracked_files"] = sorted(untracked)
                result["allowlist_ok"] = set(result["changed_files"]).issubset(set(self.case.files))
                if not result["allowlist_ok"]:
                    result["status"] = "fail"
        except (OSError, subprocess.CalledProcessError) as exc:
            result.update(status="fail", error=str(exc))
        finally:
            if replay_dir.exists():
                self._git("worktree", "remove", "--force", str(replay_dir), check=False)
        return result

    def _render_patch(self, audit: dict[str, Any] | None = None) -> str:
        audit = audit or self.audit_diff()
        patch = self._git("diff", "--binary", "--no-ext-diff", "--no-renames", self.case.target_commit,
                          cwd=self.worktree).stdout
        for relative in audit["untracked_files"]:
            addition = self._git("diff", "--no-index", "--binary", "--", "/dev/null", relative,
                                 cwd=self.worktree, check=False)
            if addition.returncode not in (0, 1):
                raise RuntimeError(f"cannot export {relative}: {addition.stderr}")
            patch += addition.stdout
        return patch

    @source_guard('_source_scope')
    def verify(self) -> dict[str, Any]:
        from .output_budget import require_output_record
        require_output_record(self.run_dir / 'run.json')
        audit = self.audit_diff()
        before = self.record.get("patch_sha256")
        contract = self.mapping_plan.data().get('repair_contract') if self.mapping_plan else None
        if contract:
            from .guarded_repair import review_covers_contract
            receipt = self.record.get('repair_obligation_review', {})
            if (not review_covers_contract(receipt, contract) or receipt.get('patch_sha256') != before
                    or receipt.get('mapping_plan_sha256') != self.mapping_plan.sha256
                    or hashlib.sha256(self._render_patch(audit).encode()).hexdigest() != before):
                return {'status': 'FAIL', 'blocked_by': 'GUARDED_REPAIR_REVIEW',
                        'patch_sha256': before, 'sufficient_for_validated': False, 'commands': [], 'stages': {}}
        results = []
        checks = self.case.validation_checks or tuple(
            {"stage": "configured", "argv": list(argv), "artifacts": []}
            for argv in self.case.validation)
        from .verification_evidence import check_identity, archive_artifacts, successful_build_receipt, validation_policy
        # Cache completed checks, never stage names (a stage may have several
        # commands, including commands not reached before an earlier failure).
        memory = self.record.get("verification_memory") or {}
        cached = memory.get('checks', {}) if memory.get('version') == 2 else {}
        completed, skipped = {}, set()
        invocation = self.record.get('validation_invocation', 0) + 1
        self.record['validation_invocation'] = invocation
        target = self.record.get('target_commit', self.case.target_commit)
        base_env = _safe_env()
        for number, check_spec in enumerate(checks, 1):
            require_output_record(self.run_dir / 'run.json')
            argv = tuple(check_spec["argv"])
            stage = check_spec.get("stage", "configured")
            identity, cacheable = check_identity(dict(check_spec, stage=stage), number,
                cwd=self.worktree, env=base_env, patch_sha256=before, target_commit=target,
                context=self.record.get('verification_context'), dependencies=self.record.get('dependency_repositories', {}))
            if cacheable and identity in cached:
                result = {**cached[identity], 'skipped_passed': True, 'elapsed_seconds': 0.0}
                results.append(result)
                completed[identity] = cached[identity]
                skipped.add(stage)
                continue
            for artifact in check_spec.get('artifacts', []):
                if self._git('ls-files', '--error-unmatch', '--', artifact, cwd=self.worktree, check=False).returncode == 0:
                    raise RuntimeError('validation artifact overlaps tracked source: ' + artifact)
            archive_artifacts(check_spec, self.worktree, self.run_dir, invocation, number)
            nonce = f'{before}:{invocation}:{number}:{identity}'
            start = time.monotonic()
            try:
                verification_env = dict(base_env)
                for key in ('AOSP_AGENT_PATCH_BUNDLE', 'AOSP_AGENT_BUNDLE_SHA256', 'AOSP_AGENT_ARTIFACT_DIR'):
                    verification_env.pop(key, None)
                # Explicit controller contract: neither a model nor cwd ancestry
                # chooses which original checkout a build is allowed to mutate.
                verification_env.update({
                    'AOSP_AGENT_PATCH_FILE': str(self.run_dir / 'backport.patch'),
                    'AOSP_AGENT_PATCH_SHA256': before or '',
                    'AOSP_AGENT_TARGET_REPO': str(self.repo),
                    'AOSP_AGENT_TARGET_COMMIT': self.record.get('target_commit', self.case.target_commit),
                    'AOSP_AGENT_WORKTREE': str(self.worktree),
                    'AOSP_AGENT_RUN_DIR': str(self.run_dir),
                    'AOSP_AGENT_PYTHON': sys.executable,
                    'AOSP_AGENT_VALIDATION_ID': nonce,
                })
                stdout, stderr, code = run_check(list(argv), self.worktree, verification_env)
            except subprocess.TimeoutExpired as exc:
                stdout, stderr, code = _decoded(exc.stdout), "validation timed out after 1800 seconds", 124
            except OSError as exc:
                stdout, stderr, code = "", str(exc), 127
            build_receipt_verified = (stage == 'android_module_build' and code == 0 and successful_build_receipt(
                    self.run_dir, nonce=nonce, patch_sha256=before, target_commit=target, target_repo=self.repo))
            if stage == 'android_module_build' and code == 0 and not build_receipt_verified:
                code = 125
                stderr += '\nmissing fresh successful build/apply/restore receipt for this exact candidate'
            stem = f"validation-{self.record.get('attempt', 0)}-{invocation}-{number}"
            from .output_budget import write_text
            write_text(self.run_dir / (stem + ".stdout"), stdout)
            write_text(self.run_dir / (stem + ".stderr"), stderr)
            artifacts = []
            for artifact in check_spec.get("artifacts", []):
                path = self.worktree / artifact
                exists = path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(self.worktree)
                artifacts.append({"path": artifact, "exists": exists,
                                  "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if exists else None})
                if not exists and code == 0:
                    code = 125
                    stderr = (stderr + "\nmissing expected artifact: " + artifact).strip()
            results.append({"stage": stage, "argv": list(argv), "returncode": code, "stdout": stdout[-10000:], "stderr": stderr[-10000:],
                            "stdout_log": stem + ".stdout", "stderr_log": stem + ".stderr",
                            "elapsed_seconds": round(time.monotonic() - start, 3), "artifacts": artifacts,
                            "check_id": identity, "validation_id": nonce,
                            "covers": [self.case.repository], 'build_receipt_verified': build_receipt_verified,
                            **({'coverage': 'partial'} if check_spec.get('coverage') == 'partial' else {})})
            if not code and cacheable:
                completed[identity] = results[-1]
            if code: break
        self.audit_diff()
        if before is not None:
            after = self._render_patch()
            if hashlib.sha256(after.encode()).hexdigest() != before:
                raise RuntimeError("validation mutated the candidate patch")
        status = "NOT_CONFIGURED" if not results else ("PASS" if all(x["returncode"] == 0 for x in results) else "FAIL")
        stages = {stage: ("PASS" if all(item["returncode"] == 0 for item in results if item["stage"] == stage)
                          else "FAIL") for stage in {item["stage"] for item in results}}
        complete_stages = {stage for stage in stages if stages[stage] == 'PASS' and
                           sum(c.get('stage', 'configured') == stage for c in checks) ==
                           sum(c['stage'] == stage for c in results)}
        self.record["verification_memory"] = {"version": 2, "checks": completed, "patch_sha256": before,
                                              "context": self.record.get('verification_context'),
                                              "passed_stages": sorted(complete_stages)}
        policy = validation_policy(results, [self.case.repository], expected_checks=len(checks))
        result = {"commands": results, "stages": stages, "status": status, 'policy': policy,
                  "scope": "configured_commands_only",
                  "sufficient_for_validated": policy['satisfied'],
                  "runtime_security_proven": False,
                  "patch_sha256": self.record.get("patch_sha256"),
                  "skipped_stages": sorted(skipped)}
        for layer in ("source_extracted_jvm", "android_module_build", "android_runtime"):
            if layer in stages:
                self.record[layer] = "pass" if stages[layer] == "PASS" else "fail"
        self._json("verification.json", result); self._event("verification", **result); return result

    def _write_record(self) -> None:
        from .delivery import update_delivery
        update_delivery(self.record)
        if hasattr(self, 'output_budget'):
            self.record['output_budget'] = self.output_budget.data()
        self._json("run.json", self.record)


def _decoded(value: str | bytes | None) -> str: return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")

def _safe_env() -> dict[str, str]:
    env = dict(os.environ); env.pop("LD_PRELOAD", None); env["PYTHONDONTWRITEBYTECODE"] = "1"
    for key in list(env):
        if re.search(r"API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|SECRET", key, re.I): env.pop(key)
    return env

def _donor_slug(repository: str) -> str: return repository.replace("/", "-") + ".git"

def _codex_error_kind(message: str) -> str:
    return "AUTH_REQUIRED" if "401 Unauthorized" in message or "403 Forbidden" in message else "CODEX_ERROR"

def _extract_unified_diff(response: str) -> str:
    text = response.strip()
    if "```" in text:
        candidates = [chunk for chunk in text.split("```") if "diff --git " in chunk or "--- a/" in chunk]
        if candidates: text = candidates[0].strip()
    for marker in ("diff --git ", "--- a/"):
        offset = text.find(marker)
        if offset >= 0: return text[offset:].strip()
    raise RuntimeError("model response did not contain a unified diff")

def _assert_patch_paths(patch: str, allowed: set[str]) -> None:
    paths = {h[key] for h in split_hunks(patch) for key in ("old_path", "new_path") if h.get(key)}
    if not paths: raise RuntimeError("unified diff contains no file paths")
    unexpected = sorted(paths - allowed)
    if unexpected: raise RuntimeError(f"model patch contains unexpected paths: {unexpected}")
