"""Small, local Git fixtures for orchestration tests; no SDK calls or vulnerability PoCs."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from aosp_agent.case import Case


BASELINE = "def normalize_count(value):\n    return value\n"
FIXED = "def normalize_count(value):\n    return max(0, min(value, 10))\n"
PARTIAL = "def normalize_count(value):\n    return max(0, value)\n"
VALIDATOR = """from counter import normalize_count
assert normalize_count(4) == 4, 'ordinary count changed'
assert normalize_count(-1) == 0, 'lower bound missing'
assert normalize_count(11) == 10, 'upper bound missing'
print('contract verified')
"""
CHECK_LOWER = """from counter import normalize_count
assert normalize_count(-1) == 0, 'lower bound missing'
print('lower ok')
"""
CHECK_UPPER = """from counter import normalize_count
assert normalize_count(11) == 10, 'upper bound missing'
print('upper ok')
"""


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", "user.name=agent-test", "-c", "user.email=test@example.invalid", *args],
        cwd=repo, text=True, stderr=subprocess.PIPE,
    ).strip()


class GitFixture:
    def __init__(self):
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name).resolve()
        self.source_root = self.root / "source"
        self.repo = self.source_root / "repo"
        self.repo.mkdir(parents=True)
        git(self.repo, "init", "-q")
        (self.repo / "counter.py").write_text(BASELINE)
        (self.repo / "verify_contract.py").write_text(VALIDATOR)
        (self.repo / "check_lower.py").write_text(CHECK_LOWER)
        (self.repo / "check_upper.py").write_text(CHECK_UPPER)
        (self.repo / ".gitignore").write_text("__pycache__/\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "target baseline")
        self.target = git(self.repo, "rev-parse", "HEAD")
        (self.repo / "counter.py").write_text(FIXED)
        git(self.repo, "add", "counter.py")
        git(self.repo, "commit", "-q", "-m", "bound ordinary count values")
        self.donor = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "checkout", "--detach", "-q", self.target)
        self.run_root = self.root / "runs"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self._directory.cleanup()

    def case(self, *, validation: bool = False, already_fixed: bool = False) -> Case:
        return Case.from_dict({
            "cve": "CVE-2099-2000", "project": "AOSP orchestration fixture", "repository": "repo",
            "source_commit": self.donor, "source_parent": self.target,
            "target_commit": self.donor if already_fixed else self.target,
            "files": ["counter.py", "test_counter.py"],
            "validation": [[sys.executable, "-B", "verify_contract.py"]] if validation else [],
        })

    def assessment(self, status: str = "AFFECTED", *, already_fixed: bool = False) -> dict[str, Any]:
        evidence = [] if status == "UNKNOWN" else [
            {"revision": "target", "path": "counter.py", "line_start": 1, "line_end": 2,
             "excerpt": (FIXED if already_fixed else BASELINE).rstrip("\n"),
             "claim": "Target implementation at the selected baseline."},
            {"revision": "source_fix", "path": "counter.py", "line_start": 1, "line_end": 2,
             "excerpt": FIXED.rstrip("\n"), "claim": "Donor caps ordinary count values."},
        ]
        return {"status": status, "evidence": evidence,
                "reasoning": "Compare the target's ordinary count handling with the donor's bounds.",
                "limitations": ["This is an orchestration fixture, not Android runtime evidence."]}

    def record(self) -> dict[str, Any]:
        return json.loads((self.run_root / "CVE-2099-2000" / "run.json").read_text())


def write_counter(content: str) -> Callable[[Path], None]:
    def edit(worktree: Path):
        (worktree / "counter.py").write_text(content)
    return edit


class ScriptedRuntime:
    """A deterministic runtime double. Its mutations exercise real Git and verifier paths."""
    def __init__(self, assessment: dict[str, Any] | str,
                 edits: list[Callable[[Path], None] | None] | None = None,
                 impact_edit: Callable[[Path], None] | None = None,
                 patch_response: str | None = None):
        self.assessment = assessment
        self.edits = edits or []
        self.impact_edit = impact_edit
        self.patch_response = patch_response
        self.calls: list[dict[str, Any]] = []
        self.factory_options: dict[str, Any] = {}
        self.worktree: Path | None = None
        self.closed = False
        self._write_index = 0

    def factory(self, **kwargs):
        self.factory_options = kwargs
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def start(self, cwd: str | Path, instructions: str):
        self.worktree = Path(cwd)
        self.instructions = instructions
        return "fixture-thread"

    def run(self, prompt: str, read_only: bool, output_schema=None) -> dict[str, Any]:
        if self.worktree is None:
            raise AssertionError("runtime.start must precede runtime.run")
        self.calls.append({"prompt": prompt, "read_only": read_only, "output_schema": output_schema})
        if len(self.calls) == 1:
            if not read_only:
                raise AssertionError("impact assessment must be read-only")
            if self.impact_edit:
                self.impact_edit(self.worktree)
            response = (json.dumps(self.assessment) if isinstance(self.assessment, dict)
                        else self.assessment)
        elif read_only:
            # Evidence correction turns remain read-only and repeat the scripted
            # response when this fixture is testing exhaustion.
            response = (json.dumps(self.assessment) if isinstance(self.assessment, dict)
                        else self.assessment)
        else:
            if self._write_index >= len(self.edits):
                raise AssertionError("unexpected extra patch/revision turn")
            edit = self.edits[self._write_index]
            self._write_index += 1
            if edit:
                edit(self.worktree)
            # The backport contract requires a per-hunk declaration; the
            # fixture's donor diff has one hunk (counter.py -> f001-h001).
            response = (self.patch_response or
                        "Applied the proposed adaptation; use orchestrator validation results.\n"
                        "HUNK-RESULT f001-h001 implemented adapted the donor fix to the target baseline.")
        output = self.assessment if len(self.calls) == 1 and isinstance(self.assessment, dict) else response
        return {"status": "completed", "final_response": response, "output": output,
                "thread_id": "fixture-thread", "turn_id": f"fixture-turn-{len(self.calls)}",
                "usage": None, "elapsed_seconds": 0.0}

