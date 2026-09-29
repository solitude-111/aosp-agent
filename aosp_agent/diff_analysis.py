"""Donor diff preprocessing: classify fix type and extract security hunks.

For "version copy" donor diffs (e.g., sqlite 3.44.5 → 3.44.3 bulk copy),
the raw diff is dominated by version strings, changelogs and metadata noise.
This module classifies the diff and, for version copies, extracts only the
security-relevant hunks, grouping them by inferred vulnerability pattern.
The impact prompt then uses the clean extraction plus a vulnerability-class
specific search strategy instead of the noisy raw diff.
"""
from __future__ import annotations

import re
from typing import Any

# Patterns that indicate a hunk is metadata noise, not a security fix.
_VERSION_NOISE = re.compile(
    r"SQLITE_VERSION\s|SQLITE_VERSION_NUMBER\s|SQLITE_SOURCE_ID\s"
    r"|\d+\.\d+\.\d+(?:\.\d+)?\s*$|VERSION\s*=|PATCHLEVEL\s*=", re.I)
_CHANGELOG_NOISE = re.compile(r"^\+\*\* |^\-\-\* |Changelog|Changes\s*$|"
                               r"^\+#\s|^\-\#\s|Copyright|License|README", re.I)
_METADATA_FILES = re.compile(r"METADATA|README\.version|\.bp$|\.mk$|OWNERS$")

# Patterns that indicate a hunk is security-relevant.
_TYPE_WIDENING = re.compile(
    r"[-+]\s+(?:u16|u32|i16|int|short|unsigned)\s+\w+;")
_BOUNDS_CHECK = re.compile(
    r"[-+].*(?:if\s*\(|assert\s*\(|MAX_|LIMIT_|mxTerm|overflow|too (?:large|many|big))",
    re.I)
_LOCK_ATOMIC = re.compile(r"[-+].*(?:mutex|spin_lock|atomic|smp_|barrier|RCU)", re.I)
_PERMISSION = re.compile(r"[-+].*(?:permission|PERMISSION|checkPermission|"
                          r"enforce|requiresPermission|uid|grant)", re.I)


def classify_donor_diff(diff_text: str) -> dict[str, Any]:
    """Classify a donor diff as 'surgical_fix' or 'version_copy'.

    Returns {"type": "version_copy"|"surgical_fix",
             "noise_ratio": float, "total_lines": int, "noise_lines": int}.
    """
    if not diff_text.strip():
        return {"type": "surgical_fix", "noise_ratio": 0.0,
                "total_lines": 0, "noise_lines": 0}
    lines = diff_text.splitlines()
    changed = [l for l in lines if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    if not changed:
        return {"type": "surgical_fix", "noise_ratio": 0.0,
                "total_lines": 0, "noise_lines": 0}
    noise = sum(1 for l in changed if _VERSION_NOISE.search(l) or _CHANGELOG_NOISE.search(l))
    metadata_files = sum(1 for l in lines if _METADATA_FILES.search(l))
    ratio = noise / len(changed) if changed else 0.0
    # Version copy: high noise ratio OR many metadata file mentions
    is_version_copy = ratio > 0.3 or metadata_files >= 3
    return {"type": "version_copy" if is_version_copy else "surgical_fix",
            "noise_ratio": round(ratio, 2), "total_lines": len(changed),
            "noise_lines": noise}


def infer_vulnerability_class(hunks: list[str]) -> str:
    """Infer the vulnerability class from the security-relevant hunks."""
    text = "\n".join(hunks)
    scores: dict[str, int] = {"integer_overflow": 0, "race_condition": 0,
                              "permission_bypass": 0, "input_validation": 0}
    for line in text.splitlines():
        if _TYPE_WIDENING.search(line):
            scores["integer_overflow"] += 2
        if _BOUNDS_CHECK.search(line):
            scores["integer_overflow"] += 1
        if _LOCK_ATOMIC.search(line):
            scores["race_condition"] += 2
        if _PERMISSION.search(line):
            scores["permission_bypass"] += 2
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "logic_error"


def extract_security_hunks(diff_text: str) -> dict[str, Any]:
    """Extract security-relevant hunks from a donor diff.

    Returns {"security_diff": str, "vulnerability_class": str,
             "extracted_hunks": int, "filtered_hunks": int,
             "original_diff_lines": int}.
    """
    from .patches import split_hunks
    try:
        records = split_hunks(diff_text)
    except ValueError:
        return {"security_diff": diff_text, "vulnerability_class": "unknown",
                "extracted_hunks": 0, "filtered_hunks": 0,
                "original_diff_lines": len(diff_text.splitlines())}

    security_patches = []
    extracted = 0
    filtered = 0
    for record in records:
        if not record.get("supported"):
            continue
        patch_text = record.get("patch", "")
        changed_lines = [l for l in patch_text.splitlines()
                         if l[:1] in "+-" and not l.startswith(("+++", "---"))]
        if not changed_lines:
            continue
        # Check if ALL changed lines are noise
        all_noise = all(_VERSION_NOISE.search(l) or _CHANGELOG_NOISE.search(l)
                        for l in changed_lines)
        if _METADATA_FILES.search(record.get("path", "")) or all_noise:
            filtered += 1
            continue
        # Check if ANY changed line is security-relevant
        has_security = any(
            _TYPE_WIDENING.search(l) or _BOUNDS_CHECK.search(l)
            or _LOCK_ATOMIC.search(l) or _PERMISSION.search(l)
            for l in changed_lines)
        if has_security:
            security_patches.append(patch_text)
            extracted += 1
        else:
            # Not explicitly security-related, but also not pure noise.
            # Keep it — could be logic changes we don't pattern-match.
            security_patches.append(patch_text)
            extracted += 1

    security_diff = "\n".join(security_patches)
    vuln_class = infer_vulnerability_class(security_patches)
    return {"security_diff": security_diff, "vulnerability_class": vuln_class,
            "extracted_hunks": extracted, "filtered_hunks": filtered,
            "original_diff_lines": len(diff_text.splitlines())}


def preprocess_donor_diff(diff_text: str, commit_message: str = "") -> dict[str, Any]:
    """Full preprocessing pipeline: classify → extract → infer class.

    For surgical fixes, returns the original diff with the inferred
    vulnerability class (search strategy is applied based on CONTENT,
    not just version-copy classification). For version copies, also
    filters out noise hunks.
    """
    classification = classify_donor_diff(diff_text)
    # Always infer vulnerability class from diff content
    from .patches import split_hunks
    vuln_class = "input_validation"
    try:
        records = split_hunks(diff_text)
        hunks = [r.get("patch", "") for r in records if r.get("supported")]
        if hunks:
            vuln_class = infer_vulnerability_class(hunks)
    except ValueError:
        pass
    # Also check commit message for classification hints
    msg_lower = commit_message.lower()
    if "copy" in msg_lower and ("version" in msg_lower or "sqlite" in msg_lower):
        classification["type"] = "version_copy"
    if classification["type"] == "version_copy":
        extraction = extract_security_hunks(diff_text)
        return {**classification, **extraction, "preprocessed": True}
    return {**classification, "security_diff": diff_text,
            "vulnerability_class": vuln_class, "preprocessed": False}
