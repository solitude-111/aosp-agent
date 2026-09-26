"""Cross-tag test inheritance analysis (doc category F).

Given a validated fix patch and two AOSP tags, determine whether the
validation result on the newer tag can be inherited by the older tag,
or whether re-testing is required. The analysis is deterministic first
(tag diff + function overlap check); the model is only consulted when
the deterministic check finds relevant overlap.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .prompts import SYSTEM


INHERIT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "verdict": {"type": "string", "enum": ["INHERIT", "RE_TEST", "CONDITIONAL"]},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "tag_diff_summary": {"type": "string", "minLength": 1},
        "overlap_analysis": {"type": "string", "minLength": 1},
        "tests_to_rerun": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "reasoning": {"type": "string", "minLength": 1},
    },
    "required": ["verdict", "confidence", "tag_diff_summary",
                 "overlap_analysis", "tests_to_rerun", "reasoning"],
}


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    env = {"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
           "PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    return subprocess.run(["git", "-c", "protocol.allow=never", "-c",
                           "core.hooksPath=/dev/null", "-C", str(repo), *args],
                          text=True, capture_output=True, check=check, env=env, timeout=120)


def resolve_tag(repo: Path, tag: str) -> str:
    """Map an Android tag name (or raw SHA) to a commit SHA."""
    result = _git(repo, "rev-parse", "--verify", f"{tag}^{{commit}}", check=False)
    if result.returncode != 0:
        raise ValueError(f"tag not found in repository: {tag}")
    return result.stdout.strip()


def compute_tag_diff(repo: Path, tag1_sha: str, tag2_sha: str,
                     files: list[str]) -> str:
    """Diff the case-relevant files between two tag commits."""
    if not files:
        return ""
    result = _git(repo, "diff", "--no-ext-diff", "-U3",
                  f"{tag1_sha}..{tag2_sha}", "--", *files, check=False)
    return result.stdout if result.returncode == 0 else ""


def extract_hunk_positions(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Extract changed line ranges per file from a unified diff.

    Returns {"path": [(start, end), ...]} where ranges are in the
    respective file's line space (old for -, new for +).
    """
    positions: dict[str, list[tuple[int, int]]] = {}
    current_file = None
    for line in diff_text.splitlines():
        if line.startswith("--- a/"):
            current_file = line[6:]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@ "):
            match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
            if match and current_file:
                start = int(match.group(1))
                count = int(match.group(2) or 1)
                positions.setdefault(current_file, []).append((start, start + count - 1))
    return positions


def check_function_overlap(fix_diff: str, tag_diff: str) -> dict[str, Any]:
    """Deterministically check whether fix and tag diffs share line ranges.

    Returns {"overlap": bool, "files_with_overlap": [...], "details": [...]}.
    """
    fix_pos = extract_hunk_positions(fix_diff)
    tag_pos = extract_hunk_positions(tag_diff)
    details = []
    overlap_files = []
    for path, fix_ranges in fix_pos.items():
        tag_ranges = tag_pos.get(path, [])
        if not tag_ranges:
            continue
        for f_start, f_end in fix_ranges:
            for t_start, t_end in tag_ranges:
                if f_start <= t_end and t_start <= f_end:
                    overlap_files.append(path)
                    details.append({
                        "file": path,
                        "fix_lines": [f_start, f_end],
                        "tag_diff_lines": [t_start, t_end],
                        "overlap": [max(f_start, t_start), min(f_end, t_end)],
                    })
    return {"overlap": bool(overlap_files), "files_with_overlap": sorted(set(overlap_files)),
            "details": details}


def inherit_prompt(cve: str, fix_diff: str, tag_diff: str,
                   tag1: str, tag2: str, files: list[str]) -> str:
    return f"""Analyze whether a fix validated on {tag1} can be inherited by {tag2} for {cve}.

The fix patch (validated on {tag1}, passed compilation and contract checks):
```diff
{fix_diff[:15000]}
```

The code differences between {tag1} and {tag2} in the relevant files:
```diff
{tag_diff[:15000]}
```

Files relevant to the fix: {', '.join(files)}

Your task: determine if the tag-to-tag differences affect the fix's validity on {tag2}.

Rules:
- If the differences are in completely unrelated functions or sections, the fix
  can be inherited without re-testing (INHERIT).
- If the differences touch the same functions or data structures the fix modifies
  or depends on, full re-validation is needed (RE_TEST).
- If the relationship is uncertain but limited in scope, recommend specific tests
  to re-run rather than full validation (CONDITIONAL with tests_to_rerun list).

Consider:
- Do the differences change any API signatures, types, or constants the fix uses?
- Do the differences add/remove callers of the functions the fix modifies?
- Do the differences change the behavior the fix is trying to correct?
- Are there new code paths in {tag2} that bypass the fix?

Return a JSON object with this exact schema:
{json.dumps(INHERIT_SCHEMA, ensure_ascii=False)}
"""


def analyze_inheritance(cve: str, fix_patch_path: Path, source_root: Path,
                        repository: str, files: list[str],
                        tag1: str, tag2: str,
                        model: str | None = None,
                        model_provider: str | None = None,
                        turn_timeout: float = 900) -> dict[str, Any]:
    """Run the full inheritance analysis pipeline.

    Returns the structured verdict dict.
    """
    repo = (source_root / repository).resolve()
    if not repo.is_dir():
        raise ValueError(f"repository not found: {repo}")

    fix_diff = fix_patch_path.read_text() if fix_patch_path.exists() else ""
    if not fix_diff.strip():
        raise ValueError(f"fix patch is empty or missing: {fix_patch_path}")

    # Phase 1: Resolve tags
    tag1_sha = resolve_tag(repo, tag1)
    tag2_sha = resolve_tag(repo, tag2)

    # Phase 2: Compute inter-tag diff on relevant files
    tag_diff = compute_tag_diff(repo, tag1_sha, tag2_sha, files)

    # Phase 3: Deterministic check
    if not tag_diff.strip():
        return {
            "verdict": "INHERIT",
            "confidence": "high",
            "tag_diff_summary": f"No differences in relevant files between {tag1} and {tag2}.",
            "overlap_analysis": "Not applicable - no tag differences to analyze.",
            "tests_to_rerun": [],
            "reasoning": f"The files touched by the fix are identical between {tag1} "
                        f"and {tag2}. The validated fix applies and behaves the same way.",
            "tags": {"tag1": tag1, "tag1_sha": tag1_sha, "tag2": tag2, "tag2_sha": tag2_sha},
        }

    overlap = check_function_overlap(fix_diff, tag_diff)
    if not overlap["overlap"]:
        return {
            "verdict": "INHERIT",
            "confidence": "high",
            "tag_diff_summary": f"Tag differences exist but do not overlap with the fix's "
                                f"modified line ranges.",
            "overlap_analysis": f"Deterministic check found no line-range overlap between "
                                f"the fix and the tag differences in: {', '.join(files)}",
            "tests_to_rerun": [],
            "reasoning": "The fix modifies line ranges that are distinct from the tag-to-tag "
                        "differences. The changes are in different sections of the same files "
                        "and are unlikely to interact.",
            "overlap_detail": overlap["details"],
            "tags": {"tag1": tag1, "tag1_sha": tag1_sha, "tag2": tag2, "tag2_sha": tag2_sha},
        }

    # Phase 4: Model analysis (overlap found, need semantic judgment)
    from .sdk_runtime import CodexRuntime
    events_path = fix_patch_path.parent / "inherit-events.jsonl"
    with CodexRuntime(events_path=events_path, model=model,
                      model_provider=model_provider, turn_timeout=turn_timeout,
                      env={"GIT_NO_LAZY_FETCH": "1"}) as runtime:
        runtime.start(str(repo), SYSTEM + "\nCross-tag inheritance analysis is read-only.")
        prompt = inherit_prompt(cve, fix_diff, tag_diff, tag1, tag2, files)
        result = runtime.run(prompt, read_only=True, output_schema=INHERIT_SCHEMA)
        output = result.get("output") or json.loads(result.get("final_response", "{}"))

    output["overlap_detail"] = overlap["details"]
    output["tags"] = {"tag1": tag1, "tag1_sha": tag1_sha,
                      "tag2": tag2, "tag2_sha": tag2_sha}
    return output
