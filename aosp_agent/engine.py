from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from .case import Case, validate_relative_path
from .diagnosis import apply_diagnosis, verification_diagnosis
from .ladder import ladder_plan, strategy_prompt
from .patch_repair import repair_hunk
from .patches import split_hunks
from .prompts import IMPACT_SCHEMA, SYSTEM, backport_prompt, impact_prompt, parse_impact_response
from . import symbols

_HUNK_RESULT_RE = re.compile(
    r"^\s*HUNK-RESULT\s+(\S+)\s+(implemented|need_not_ported)\s+(.+?)\s*$", re.MULTILINE)


class AssessmentError(ValueError):
    """The model's assessment could not be grounded in immutable Git blobs."""

    kind = "ASSESSMENT_INVALID"


class AospBackportAgent:
    """Run independent AOSP impact assessment and a guarded SDK backport."""

    def __init__(self, source_root: Path, run_root: Path, case: Case, model: str = "gpt-5.6-sol",
                 donor_root: Path | None = None, model_provider: str | None = None,
                 api_base_url: str | None = None, api_key_env: str | None = None, *,
                 runtime_factory: Callable | None = None, turn_timeout: float = 900,
                 source_diff: str | None = None):
        if api_base_url or api_key_env:
            raise ValueError("AOSP agent requires Codex SDK; direct API arguments are unsupported")
        self.source_root, self.run_root = source_root.resolve(), run_root.resolve()
        self.case, self.model = case, model
        self.input_diff = source_diff
        self.model_provider = model_provider or os.environ.get("AOSP_AGENT_MODEL_PROVIDER")
        self.repo = (self.source_root / validate_relative_path(case.repository)).resolve()
        self.donor_root = donor_root.resolve() if donor_root else None
        self.donor_repo = ((self.donor_root / _donor_slug(case.repository)).resolve()
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
        self._current_hunks: list[dict[str, Any]] = []
        self._last_audit: dict[str, Any] | None = None
        self._events_swept = 0
        self.record: dict[str, Any] = {"cve": case.cve, "status": "INITIALIZED", "backend": "codex_sdk",
            "model": model, "events": [], "verification_scope": "configured_commands_only",
            "runtime_security_proven": False,
            "model_execution": "not_run", "impact_decision": "uncertain",
            "source_review": "not_run", "patch_replay": "not_run",
            "source_extracted_jvm": "NOT_CONFIGURED", "android_module_build": "NOT_CONFIGURED",
            "android_runtime": "NOT_CONFIGURED", "poc_execution": "NOT_RUN"}
        self.record["capabilities"] = {
            "multi_repository": "single_repository" if not case.repositories else "declared_not_orchestrated",
            "repo_manifest": "declared" if case.manifest else "not_configured",
            "device_validation": "not_configured",
        }

    def _git(self, *args: str, cwd: Path | None = None, check: bool = True,
             env: dict[str, str] | None = None, input: str | None = None):
        repo = cwd or self.repo
        git_env = dict(os.environ if env is None else env, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0")
        return subprocess.run(["git", "-c", f"safe.directory={repo}", "-c", "protocol.allow=never",
                               "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args], cwd=repo,
                              text=True, capture_output=True, check=check, env=git_env, input=input, timeout=180)

    def _source_git(self, *args: str, check: bool = True):
        if self.donor_root:
            return subprocess.run(["git", "-c", "protocol.allow=never", "--git-dir", str(self.donor_repo), *args],
                                  text=True, capture_output=True, check=check, timeout=180,
                                  env=dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0"))
        return self._git(*args, check=check)

    def _event(self, name: str, **data: Any) -> None:
        self.record["events"].append({"event": name, "time": time.time(), **data})
        if self._owns_run:
            self._write_record()

    def _json(self, name: str, value: Any) -> None:
        destination = self.run_dir / name
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(destination)

    def _source_state(self) -> dict[str, str]:
        return {"head": self._git("rev-parse", "HEAD").stdout.strip(),
                "status": self._git("status", "--porcelain=v1", "-z", "--untracked-files=all").stdout,
                "diff_sha256": hashlib.sha256(self._git("diff", "--binary", "HEAD").stdout.encode()).hexdigest()}

    def prepare(self) -> Path:
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self._owns_run = True
        extra_repositories = [item.get("path") for item in self.case.repositories
                              if item.get("path") != self.case.repository]
        if extra_repositories:
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
        self._git("worktree", "add", "--detach", str(self.worktree), target)
        self.record.update(status="PREPARED", source_commit=self.case.source_commit,
                           source_parent=self.case.source_parent, target_commit=target,
                           target_tree=target_tree,
                           worktree=str(self.worktree), original_checkout=self._source_before,
                           commit_message=self.commit_message,
                           donor_git=str(self.donor_repo) if self.donor_root else None)
        self._event("prepared", target_commit=target, worktree=str(self.worktree))
        self.audit_diff(require_clean=True)
        if self.input_diff is None:
            from .agent_tools import _write_wrappers
            _write_wrappers(self.run_dir)
        return self.worktree

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
        source_diff = (self.input_diff if self.input_diff is not None else
                       self._source_git("diff", "--no-ext-diff", self.case.source_parent, self.case.source_commit).stdout)
        hunks = split_hunks(source_diff)
        self._source_changed_paths = {h["path"] for h in hunks if h.get("path")}
        for hunk in hunks:
            hunk["application_check"] = (self._check_application(hunk["patch"])
                                          if hunk["supported"] else {"status": "UNSUPPORTED"})
        result = {"target_files": files, "source_diff": source_diff, "source_commit": self.case.source_commit,
                  "target_commit": self.case.target_commit, "hunks": hunks,
                  "commit_message": self.commit_message,
                  "whole_patch_application": self._check_application(source_diff),
                  "limitation": "Textual applicability does not establish impact or API compatibility."}
        if self.input_diff is None:
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
        assessment = parse_impact_response(text)
        if assessment["status"] != "UNKNOWN" and not any(e["revision"] in ("source_parent", "source_fix")
                                                          for e in assessment["evidence"]):
            raise AssessmentError("determinate assessment requires donor evidence")
        refs = {"target": self.case.target_commit, "source_parent": self.case.source_parent,
                "source_fix": self.case.source_commit}
        for evidence in assessment["evidence"]:
            if evidence["revision"] == "target" and evidence["path"] not in self.case.files:
                raise AssessmentError(f"target evidence path is outside the case allowlist: {evidence['path']}")
            if (evidence["revision"] != "target"
                    and evidence["path"] not in self.case.files
                    and evidence["path"] not in getattr(self, "_source_changed_paths", set())):
                raise AssessmentError(f"source evidence path is not in the donor fix diff: {evidence['path']}")
            runner = self._git if evidence["revision"] == "target" else self._source_git
            try:
                content = runner("show", f"{refs[evidence['revision']]}:{evidence['path']}").stdout
            except subprocess.CalledProcessError as exc:
                raise AssessmentError(
                    f"evidence file does not exist in {evidence['revision']}:{evidence['path']}") from exc
            lines = content.splitlines()
            start, end = evidence["line_start"], evidence["line_end"]
            if end > len(lines):
                raise AssessmentError(f"evidence line range exceeds {evidence['revision']}:{evidence['path']}")
            excerpt = evidence["excerpt"].strip()
            excerpt_lines = excerpt.splitlines()
            matches = [index for index in range(len(lines) - len(excerpt_lines) + 1)
                       if "\n".join(lines[index:index + len(excerpt_lines)]).strip() == excerpt]
            if not matches:
                raise AssessmentError(f"evidence excerpt does not exist in {evidence['revision']}:{evidence['path']}:{start}-{end}")
            actual_start = matches[0] + 1
            actual_end = actual_start + len(excerpt_lines) - 1
            if actual_start != start or actual_end != end:
                self.record.setdefault("evidence_corrections", []).append(
                    {"revision": evidence["revision"], "path": evidence["path"],
                     "requested": [start, end], "grounded": [actual_start, actual_end]})
                evidence["line_start"], evidence["line_end"] = actual_start, actual_end
        return assessment

    def _turn(self, runtime, prompt: str, *, read_only: bool, phase: str, schema=None) -> dict:
        result = runtime.run(prompt, read_only=read_only, output_schema=schema)
        if result.get("status") != "completed":
            raise RuntimeError(f"SDK turn did not complete: {result.get('status')}")
        self._event("codex_turn", phase=phase, thread_id=result.get("thread_id"), turn_id=result.get("turn_id"),
                    status=result["status"], events_path=result.get("events_path"), usage=result.get("usage"))
        self._sweep_tool_usage()
        self.audit_diff(require_clean=read_only)
        return result

    def _sweep_tool_usage(self) -> None:
        """Recover tool-usage markers from sdk-events into run-dir logs.

        The Codex sandbox denies the tools' direct appends to
        tool-usage.jsonl (run_dir is outside the sandboxed workspace), so
        every tool invocation also prints an AOSP-TOOL-USAGE marker on
        stdout; those markers appear in commandExecution events and are
        swept here after each turn. Deduplication is by the marker's uid.
        """
        events_path = self.run_dir / "sdk-events.jsonl"
        if not events_path.is_file():
            return
        data = events_path.read_text(errors="replace")
        fresh = data[self._events_swept:]
        self._events_swept = len(data)
        marker_re = re.compile(r"^AOSP-TOOL-USAGE (\{.*\})$", re.MULTILINE)
        entries = []
        for line in fresh.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
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
        with usage_path.open("a") as stream:
            for entry in entries:
                if entry.get("uid") in known:
                    continue
                known.add(entry.get("uid"))
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
                for sha in entry.get("history_shas") or []:
                    with (self.run_dir / "history-commits.jsonl").open("a") as history:
                        history.write(json.dumps({"sha": sha, "hunk_id": None}) + "\n")

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
            if not hunk.get("supported") or hunk.get("kind") != "hunk":
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
                if lines is None:
                    candidates = self._target_tree_files()
                    entry.update(status="failed", repair_applied=[],
                                 diagnosis=apply_diagnosis(hunk, "No such file", None, candidates))
                else:
                    patch_text, repairs = repair_hunk(hunk, lines)
                    applied = self._git("apply", "-", cwd=self.worktree, check=False, input=patch_text)
                    if applied.returncode == 0:
                        entry.update(status="applied", repair_applied=repairs)
                    else:
                        # git apply is atomic per invocation; defensively undo
                        # any residue inside this disposable worktree only.
                        if self._git("diff", "--quiet", "--", path, cwd=self.worktree,
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
                + "\n- Symbols referenced by the donor fix that are MISSING at the target "
                  "baseline (must be adapted to target APIs or an equivalent): "
                  f"{', '.join(missing) or 'none'}\n")

    def _check_hunk_results(self, response: str,
                            changed_files: list[str]) -> dict[str, Any]:
        """Validate the model's HUNK-RESULT declarations against the diff (P1.6).

        Fail-closed (r2 revision 6): a response without any declaration is a
        failed turn, not a silent pass.
        """
        claims = [{"id": match.group(1), "status": match.group(2), "reason": match.group(3)}
                  for match in _HUNK_RESULT_RE.finditer(response or "")]
        if not claims:
            return {"ok": False, "claims": [], "contradictions": [],
                    "missing_declaration": True,
                    "feedback": ("Your reply contained no HUNK-RESULT declaration. End your "
                                 "turn with one line per donor hunk:\n"
                                 "HUNK-RESULT <hunk-id> implemented|need_not_ported <reason>")}
        hunks = {hunk["id"]: hunk for hunk in self._current_hunks}
        contradictions = []
        for claim in claims:
            if claim["id"] not in hunks:
                contradictions.append(f"unknown hunk id: {claim['id']}")
        by_path: dict[str, list[str]] = {}
        for claim in claims:
            hunk = hunks.get(claim["id"])
            if hunk:
                by_path.setdefault(hunk["path"], []).append(claim["status"])
        changed = set(changed_files)
        for path, statuses in sorted(by_path.items()):
            if "implemented" in statuses and path not in changed:
                contradictions.append(
                    f"{path}: declared implemented but the final diff does not touch it")
            if statuses and all(s == "need_not_ported" for s in statuses) and path in changed:
                contradictions.append(
                    f"{path}: declared need_not_ported but the final diff modifies it")
        ok = not contradictions
        return {"ok": ok, "claims": claims, "contradictions": contradictions,
                "missing_declaration": False,
                "feedback": None if ok else
                ("Your HUNK-RESULT claims contradict the exported diff:\n- "
                 + "\n- ".join(contradictions)
                 + "\nReconcile the declarations with the actual diff in your next turn.")}

    def _codex_workflow(self, inspection: dict[str, Any], verify: bool, max_attempts: int,
                        mechanical: bool = True) -> None:
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
        self._current_hunks = inspection["hunks"]
        symbol_report = inspection.get("symbol_report")
        symbol_report_text = (symbol_report.get("summary", "") +
                              "\nMissing symbols: " +
                              ", ".join(e["name"] for e in symbol_report.get("missing", []))
                              ) if symbol_report else None
        with factory(events_path=self.run_dir / "sdk-events.jsonl", model=self.model,
                     model_provider=self.model_provider, turn_timeout=self.turn_timeout,
                     env={"GIT_NO_LAZY_FETCH": "1"}) as runtime:
            self.record["thread_id"] = runtime.start(str(self.worktree), SYSTEM + context)
            impact_request = impact_prompt(self.case, source_diff, self.commit_message,
                                           symbol_report_text) + context
            assessment = None
            for impact_attempt in range(1, max_attempts + 1):
                result = self._turn(runtime, impact_request, read_only=True,
                                    phase="impact" if impact_attempt == 1 else "impact_correction",
                                    schema=IMPACT_SCHEMA)
                self.record["impact_report"] = result.get("final_response", "")
                try:
                    assessment = self._ground_assessment(result["final_response"])
                    break
                except AssessmentError as exc:
                    self._event("impact_evidence_rejected", attempt=impact_attempt, error=str(exc))
                    if impact_attempt == max_attempts:
                        raise
                    impact_request = ("Your previous JSON assessment failed deterministic Git evidence "
                                      "grounding with this error:\n" + str(exc) +
                                      "\nRe-read the exact blobs and line ranges. Return only the same "
                                      "JSON schema with corrected contiguous excerpts; do not edit files.\n" + context)
            assert assessment is not None
            self.record["assessment"] = assessment
            self.record["impact_decision"] = assessment["status"].lower()
            self.record["model_execution"] = "succeeded"
            self._json("impact.json", assessment)
            self._event("impact_grounded", status=assessment["status"], evidence=len(assessment["evidence"]))
            if assessment["status"] == "UNKNOWN":
                self.record["status"] = "INCONCLUSIVE"; return
            if assessment["status"] in ("NOT_AFFECTED", "ALREADY_FIXED"):
                self.record["status"] = assessment["status"]; return
            # AFFECTED — mechanical migration first (R2; r2 revision 1: only
            # after the impact phase so the assessment saw a clean baseline).
            if mechanical:
                migration = self.mechanical_migration(inspection)
            else:
                migration = {"hunks": [], "applied": [], "failed": [],
                             "skipped": [h["id"] for h in inspection["hunks"]],
                             "starting_state": "none", "skipped_reason": "no_mechanical"}
            ladder_ctx: dict[str, Any] = {
                "applied_hunk_ids": migration["applied"],
                "failed_hunks": [e for e in migration["hunks"] if e["status"] == "failed"],
                "missing_symbols": [e["name"] for e in (symbol_report or {}).get("missing", [])],
                "history_available": self._history_available(),
            }
            plan = [level for level in ladder_plan(ladder_ctx)][:max(1, max_attempts)]
            base_prompt = (backport_prompt(self.case, source_diff, assessment,
                                           commit_message=self.commit_message,
                                           starting_state=self._starting_state_text(migration, inspection))
                           + context
                           + "\nDonor hunk applicability (textual only):\n"
                           + json.dumps([{k: v for k, v in h.items() if k != "patch"}
                                         for h in inspection["hunks"]])
                           + f"\nThe controller will run {len(self.case.validation)} independent configured checks "
                           "after your edits. Their implementation is not part of the model input.")
            self.record["attempts"] = []
            diagnosis_json: dict[str, Any] | None = None
            claim_feedback: str | None = None
            failing_stages: list[str] = []
            for attempt, level in enumerate(plan, 1):
                self.record["attempt"] = attempt
                prompt = base_prompt + "\n" + (strategy_prompt(
                    level["index"], {**ladder_ctx, "diagnosis_json": diagnosis_json,
                                     "claim_feedback": claim_feedback,
                                     "failing_stages": failing_stages}) or "")
                result = self._turn(runtime, prompt, read_only=False,
                                    phase=f"backport_{level['strategy']}")
                self.record.setdefault("backport_reports", []).append(result.get("final_response", ""))
                self.record["attempts"].append(
                    {"index": attempt, "strategy": level["strategy"], "turn_id": result.get("turn_id"),
                     "patch_sha256": None})
                patch = self.export_patch(attempt)
                self.record["attempts"][-1]["patch_sha256"] = self.record["patch_sha256"]
                if not patch.strip():
                    raise RuntimeError("AFFECTED assessment produced no actual patch")
                claims = self._check_hunk_results(result.get("final_response", ""),
                                                  self._last_audit["changed_files"])
                self.record["hunk_results"] = claims["claims"]
                if not claims["ok"]:
                    # P1.6 / r2 revision 6: contradicted or missing declarations
                    # fail the turn; feedback goes to the next ladder level.
                    self.record["status"] = "VALIDATION_FAILED"
                    self._event("hunk_result_check_failed",
                                contradictions=claims["contradictions"],
                                missing_declaration=claims["missing_declaration"])
                    claim_feedback = claims["feedback"]
                    diagnosis_json = None
                    continue
                claim_feedback = None
                if not verify:
                    self.record.update(status="PATCH_UNVERIFIED", final_verification={"status": "NOT_REQUESTED", "commands": []}); return
                verification = self.verify()
                self.record["final_verification"] = verification
                if verification["status"] == "PASS":
                    self.record["status"] = "VALIDATED"; return
                if verification["status"] == "NOT_CONFIGURED":
                    self.record["status"] = "PATCH_UNVERIFIED"; return
                self.record["status"] = "VALIDATION_FAILED"
                diagnosis_json = verification_diagnosis(verification["commands"])
                failing_stages = [stage for stage, outcome in verification["stages"].items()
                                  if outcome == "FAIL"]
            # Preserve the candidate and evidence for human review. The run is a
            # completed *attempt* but not a successful security validation.
            self.record["status"] = "VALIDATION_FAILED"
            return

    def run(self, *, use_codex: bool = True, verify: bool = False, max_attempts: int = 6,
            mechanical: bool = True) -> dict[str, Any]:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        try:
            if not self._owns_run: self.prepare()
            inspection = self.inspect()
            if not use_codex:
                self.record.update(status="PREPARED", model_skipped=True)
            else:
                self._codex_workflow(inspection, verify, max_attempts, mechanical=mechanical)
            self.audit_diff(require_clean=not use_codex)
            self._write_record(); return self.record
        except Exception as exc:
            if self._owns_run:
                message = re.sub(r"sk-[A-Za-z0-9_-]{16,}", "[REDACTED]", str(exc))
                existing_kind = self.record.get("error", {}).get("kind")
                self.record.update(status="FAILED", model_execution=("failed" if self.record.get("model_execution") == "not_run" else self.record.get("model_execution")), error={"kind": existing_kind or getattr(exc, "kind", _codex_error_kind(message)),
                               "type": type(exc).__name__, "message": message})
                self._event("failed", **self.record["error"])
            raise

    def audit_diff(self, *, require_clean: bool = False) -> dict[str, Any]:
        expected = self._git("rev-parse", self.case.target_commit).stdout.strip()
        head = self._git("rev-parse", "HEAD", cwd=self.worktree).stdout.strip()
        tracked = set(filter(None, self._git("diff", "--name-only", "-z", "--no-renames", self.case.target_commit,
                                             cwd=self.worktree).stdout.rstrip("\0").split("\0")))
        untracked = set(filter(None, self._git("ls-files", "--others", "--exclude-standard", "-z",
                                               cwd=self.worktree).stdout.rstrip("\0").split("\0")))
        untracked -= self._artifact_paths
        changed = sorted(tracked | untracked); unsafe = []
        for relative in self.case.files:
            path = self.worktree / relative
            if path.is_symlink() or not path.resolve().is_relative_to(self.worktree): unsafe.append(relative)
        check = self._git("diff", "--check", self.case.target_commit, cwd=self.worktree, check=False)
        unchanged = self._source_before is None or self._source_state() == self._source_before
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

    def export_patch(self, attempt: int) -> str:
        audit = self.audit_diff()
        patch = self._render_patch(audit)
        (self.run_dir / f"candidate-{attempt}.patch").write_text(patch)
        (self.run_dir / "backport.patch").write_text(patch)
        check = self._check_application(patch)
        self.record.update(patch_file=str(self.run_dir / "backport.patch"),
                           patch_sha256=hashlib.sha256(patch.encode()).hexdigest(), patch_application=check)
        self._event("patch_exported", attempt=attempt, sha256=self.record["patch_sha256"], application=check)
        replay = self._replay_clean_target(patch, attempt)
        self.record["patch_replay"] = replay["status"]
        self.record["patch_replay_evidence"] = replay
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
            applied = subprocess.run(["git", "apply", "--check", "--binary", "-"], cwd=replay_dir,
                                     input=patch, text=True, capture_output=True)
            result.update(returncode=applied.returncode, stderr=applied.stderr[-5000:])
            if applied.returncode == 0:
                applied = subprocess.run(["git", "apply", "--binary", "-"], cwd=replay_dir,
                                         input=patch, text=True, capture_output=True)
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

    def verify(self) -> dict[str, Any]:
        self.audit_diff(); before = self.record.get("patch_sha256"); results = []
        checks = self.case.validation_checks or tuple(
            {"stage": "configured", "argv": list(argv), "artifacts": []}
            for argv in self.case.validation)
        # R12 port: stages that already passed for this exact patch are not
        # re-run; any patch change invalidates the memory (full re-run).
        memory = self.record.get("verification_memory") or {}
        passed_stages = (set(memory.get("passed_stages", []))
                         if memory.get("patch_sha256") and memory["patch_sha256"] == before
                         else set())
        for number, check_spec in enumerate(checks, 1):
            argv = tuple(check_spec["argv"])
            stage = check_spec.get("stage", "configured")
            if stage in passed_stages:
                results.append({"stage": stage, "argv": list(argv), "returncode": 0,
                                "skipped_passed": True, "stdout": "", "stderr": "",
                                "stdout_log": None, "stderr_log": None, "elapsed_seconds": 0.0,
                                "artifacts": [{"path": artifact, "exists": None, "sha256": None}
                                              for artifact in check_spec.get("artifacts", [])]})
                continue
            start = time.monotonic()
            try:
                completed = subprocess.run(list(argv), cwd=self.worktree, text=True, capture_output=True,
                                           timeout=1800, env=_safe_env())
                stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
            except subprocess.TimeoutExpired as exc:
                stdout, stderr, code = _decoded(exc.stdout), "validation timed out after 1800 seconds", 124
            except OSError as exc:
                stdout, stderr, code = "", str(exc), 127
            stem = f"validation-{self.record.get('attempt', 0)}-{number}"
            (self.run_dir / (stem + ".stdout")).write_text(stdout); (self.run_dir / (stem + ".stderr")).write_text(stderr)
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
                            "elapsed_seconds": round(time.monotonic() - start, 3), "artifacts": artifacts})
            if code: break
        self.audit_diff()
        if before is not None:
            after = self._render_patch()
            if hashlib.sha256(after.encode()).hexdigest() != before:
                raise RuntimeError("validation mutated the candidate patch")
        status = "NOT_CONFIGURED" if not results else ("PASS" if all(x["returncode"] == 0 for x in results) else "FAIL")
        stages = {stage: ("PASS" if all(item["returncode"] == 0 for item in results if item["stage"] == stage)
                          else "FAIL") for stage in {item["stage"] for item in results}}
        self.record["verification_memory"] = {"patch_sha256": before,
                                              "passed_stages": sorted(
                                                  stage for stage, outcome in stages.items()
                                                  if outcome == "PASS")}
        result = {"commands": results, "stages": stages, "status": status, "scope": "configured_commands_only",
                  "patch_sha256": self.record.get("patch_sha256"),
                  "skipped_stages": sorted(passed_stages & set(stages))}
        for layer in ("source_extracted_jvm", "android_module_build", "android_runtime"):
            if layer in stages:
                self.record[layer] = "pass" if stages[layer] == "PASS" else "fail"
        self._json("verification.json", result); self._event("verification", **result); return result

    def _write_record(self) -> None: self._json("run.json", self.record)


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
