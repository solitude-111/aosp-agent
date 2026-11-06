"""Cross-tag test inheritance analysis (doc category F).

Given a validated fix patch and two AOSP tags, determine whether the
validation result on the newer tag can be inherited by the older tag,
or whether re-testing is required. Line overlap is a review hint, never proof
of behavioral independence. This command reports revision compatibility;
it does not import validation receipts.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .prompts import SYSTEM
from .git_policy import OFFLINE_GIT_ENV
from .case import validate_relative_path


class InheritanceReadError(RuntimeError):
    kind = 'READ_FAILED'


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
    from .discovery import local_git
    try:
        return local_git(repo, *args, check=check, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise InheritanceReadError('Cannot read inheritance evidence: ' + str(exc)) from exc


def resolve_tag(repo: Path, tag: str) -> str:
    """Map an Android tag name (or raw SHA) to a commit SHA."""
    result = _git(repo, "rev-parse", "--verify", '--end-of-options', f"{tag}^{{commit}}", check=False)
    if result.returncode != 0:
        raise ValueError(f"tag not found in repository: {tag}")
    return result.stdout.strip()


def compute_tag_diff(repo: Path, tag1_sha: str, tag2_sha: str,
                     files: list[str]) -> str:
    """Diff the case-relevant files between two tag commits."""
    if not files:
        raise ValueError('inheritance requires a nonempty relevant-file scope')
    for path in files:
        validate_relative_path(path)
    result = _git(repo, "diff", "--no-ext-diff", "-U3",
                  f"{tag1_sha}..{tag2_sha}", "--", *files, check=False)
    if result.returncode:
        raise InheritanceReadError('Cannot read inter-tag diff (exit ' + str(result.returncode) + '): ' + result.stderr[:1000])
    return result.stdout


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

The caller-supplied fix patch for {tag1} (validation receipts are not supplied to this analysis):
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
- Non-overlapping line ranges alone do not establish unrelated behavior. A
  constant, helper, caller, build flag or permission check can alter the fix.
- Do not infer validation success from this patch or from the caller's label.
- Recommend INHERIT only if dependency and configuration equivalence is
  evidenced; otherwise use CONDITIONAL or RE_TEST and name the missing checks.
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
                        turn_timeout: float = 900, *, run_root: Path | None = None,
                        max_output_bytes: int = 256 * 1024 * 1024) -> dict[str, Any]:
    """Analyze read-only source; keep every result/event in a unique external run.

    Invalid output placement is rejected before creating any files. The default
    is cwd/runs/inherit, as with the other CLI task roots; callers running inside
    a source tree must explicitly choose an external root.
    """
    source_root = Path(source_root).resolve()
    output_root = Path(run_root if run_root is not None else Path.cwd() / 'runs/inherit').resolve()
    if output_root.is_relative_to(source_root):
        raise ValueError('inheritance run root must be outside source_root')
    output_root.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix='inherit-', dir=output_root)).resolve()
    from .output_budget import create_budget, write_json
    output_budget = create_budget(run_dir, max_output_bytes)
    result_path, events_path = run_dir / 'inherit-result.json', run_dir / 'inherit-events.jsonl'
    try:
        result = _analyze_inheritance(cve, Path(fix_patch_path), source_root, repository, files,
                                      tag1, tag2, model, model_provider, turn_timeout,
                                      events_path=events_path)
        result.update(result_file=str(result_path), events_file=str(events_path) if events_path.exists() else None)
        output_budget.check()
        write_json(result_path, result, control=True)
        output_budget.check()
    except Exception as exc:
        # Preserve diagnostics without touching the input patch's directory.
        # The API still raises; callers cannot confuse this with a verdict.
        write_json(result_path, {'verdict': 'ERROR', 'error_type': type(exc).__name__}, control=True)
        exc.inheritance_result_file = str(result_path)
        raise
    return result


def _analyze_inheritance(cve: str, fix_patch_path: Path, source_root: Path,
                        repository: str, files: list[str], tag1: str, tag2: str,
                        model: str | None, model_provider: str | None,
                        turn_timeout: float, *, events_path: Path) -> dict[str, Any]:
    """Run the full inheritance analysis pipeline.

    Returns the structured verdict dict.
    """
    source_root = Path(source_root).resolve()
    repo = (source_root / repository).resolve()
    if not repo.is_relative_to(source_root):
        raise ValueError('repository must remain inside source_root')
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
    context = {'tags': {'tag1': tag1, 'tag1_sha': tag1_sha, 'tag2': tag2, 'tag2_sha': tag2_sha},
               'scope': 'repository_revision_compatibility', 'validation_inherited': False,
               'limitations': ['No build environment or dependency closure was compared.',
                              'No prior validation receipt was supplied or reused.']}

    # Phase 3: Deterministic check
    if tag1_sha == tag2_sha:
        return {
            "verdict": "INHERIT",
            "confidence": "high",
            "tag_diff_summary": f"No differences in relevant files between {tag1} and {tag2}.",
            "overlap_analysis": "Not applicable - no tag differences to analyze.",
            "tests_to_rerun": [],
            "reasoning": 'Both names resolve to the same repository commit. This establishes code identity only; validation is not transferred.',
            **context,
        }

    if not tag_diff.strip():
        return {'verdict': 'CONDITIONAL', 'confidence': 'low',
                'tag_diff_summary': 'Selected files are identical; repository revisions differ.',
                'overlap_analysis': 'No selected-file changes, but dependent files and build configuration may differ.',
                'tests_to_rerun': ['target production build', 'fix-specific functional checks'],
                'reasoning': 'Selected-file identity does not establish dependency or environment equivalence.',
                **context}

    overlap = check_function_overlap(fix_diff, tag_diff)
    if not overlap["overlap"]:
        return {
            "verdict": "RE_TEST",
            "confidence": "high",
            "tag_diff_summary": f"Tag differences exist but do not overlap with the fix's "
                                f"modified line ranges.",
            "overlap_analysis": f"Deterministic check found no line-range overlap between "
                                f"the fix and the tag differences in: {', '.join(files)}",
            "tests_to_rerun": ['target production build', 'fix-specific functional checks'],
            "reasoning": 'Different line ranges can share constants, helpers, callers or control flow. Non-overlap cannot authorize validation inheritance.',
            "overlap_detail": overlap["details"],
            **context,
        }

    # Phase 4: Model analysis (overlap found, need semantic judgment)
    from .sdk_runtime import CodexRuntime
    from .sandbox_scope import source_scope
    with CodexRuntime(events_path=events_path, model=model,
                      model_provider=model_provider, turn_timeout=turn_timeout,
                      env=OFFLINE_GIT_ENV, read_scope=source_scope(fix_patch_path, [repo], tool_repositories={
                          'tag1': {'root': str(repo), 'head': tag1_sha},
                          'tag2': {'root': str(repo), 'head': tag2_sha}})) as runtime:
        runtime.start(str(repo), SYSTEM + "\nCross-tag inheritance analysis is read-only.")
        prompt = inherit_prompt(cve, fix_diff, tag_diff, tag1, tag2, files)
        result = runtime.run(prompt, read_only=True, output_schema=INHERIT_SCHEMA)
        output = result.get("output") or json.loads(result.get("final_response", "{}"))

    output["overlap_detail"] = overlap["details"]
    output.update(context)
    if output['verdict'] == 'INHERIT':
        output['model_recommendation'] = 'INHERIT'
        output.update(verdict='CONDITIONAL', confidence='low')
        output['reasoning'] += '\nController: no closed dependency/environment identity or reusable validation receipt proves inheritance.'
        output['tests_to_rerun'] = sorted(set(output.get('tests_to_rerun', []) +
            ['target production build', 'fix-specific functional checks']))
    return output
