from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


@dataclass(frozen=True)
class Case:
    cve: str
    project: str
    repository: str
    source_commit: str
    source_parent: str
    target_commit: str
    files: tuple[str, ...]
    # Legacy attributes remain for callers, but loaded reference answers are discarded.
    impact: str = ""
    migration: str = ""
    validation: tuple[tuple[str, ...], ...] = ()
    # Normalized validation metadata. ``validation`` remains a compatibility
    # view for callers that only need argv arrays.
    validation_checks: tuple[dict[str, Any], ...] = ()
    poc: str = ""
    source_url: str = ""
    source_version: str = ""
    target_version: str = ""
    manifest: str = ""
    repositories: tuple[dict[str, Any], ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Case":
        if not isinstance(raw, dict):
            raise ValueError("case must be a JSON object")
        required = ("cve", "project", "repository", "source_commit", "source_parent",
                    "target_commit", "files", "validation")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"case is missing fields: {', '.join(missing)}")
        cve = str(raw["cve"])
        if not re.fullmatch(r"CVE-\d{4}-\d+", cve):
            raise ValueError(f"invalid CVE identifier: {cve}")
        repository = validate_relative_path(raw["repository"])
        if not isinstance(raw["files"], list) or not raw["files"]:
            raise ValueError(f"case {cve} files must be a nonempty list")
        files = tuple(validate_relative_path(path) for path in raw["files"])
        if len(files) != len(set(files)):
            raise ValueError(f"case {cve} contains duplicate file paths")
        for field in ("source_commit", "source_parent", "target_commit"):
            value = raw[field]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{1,64}", value):
                raise ValueError(f"case {cve} {field} must be a Git object ID")
        validation_raw = raw["validation"]
        if not isinstance(validation_raw, (list, dict)):
            raise ValueError(f"case {cve} validation must be a list or staged object")
        commands: list[tuple[str, ...]] = []
        checks: list[dict[str, Any]] = []
        if isinstance(validation_raw, dict):
            entries = validation_raw.get("checks", [])
            if not isinstance(entries, list):
                # Also accept {stage: [argv, ...]} for concise multi-stage cases.
                entries = [{"stage": stage, "argv": command}
                           for stage, commands_for_stage in validation_raw.items()
                           if stage != "checks"
                           for command in (commands_for_stage if isinstance(commands_for_stage, list) else [])]
        else:
            entries = validation_raw
        for entry in entries:
            stage = "configured"
            command = entry
            artifacts = []
            if isinstance(entry, dict):
                stage = entry.get("stage", stage)
                command = entry.get("argv")
                artifacts = entry.get("artifacts", [])
                if not isinstance(stage, str) or not stage.strip():
                    raise ValueError(f"case {cve} validation stage must be a nonempty string")
                if not isinstance(artifacts, list):
                    raise ValueError(f"case {cve} validation artifacts must be a list")
                artifacts = [validate_relative_path(path) for path in artifacts]
            if (not isinstance(command, list) or not command
                or any(not isinstance(token, str) or not token or "\x00" in token for token in command)):
                raise ValueError(f"case {cve} contains an invalid validation command")
            shell_tokens = {"sh", "bash", "zsh", "fish", "cmd", "powershell", "-c", "-command"}
            tokens = [str(token).lower() for token in command]
            if PurePosixPath(tokens[0]).name in shell_tokens or shell_tokens.intersection(tokens[1:]):
                raise ValueError(f"case {cve} must use argv validation commands, not a shell string")
            argv = tuple(str(token) for token in command)
            commands.append(argv)
            checks.append({"stage": stage, "argv": list(argv), "artifacts": artifacts})
        repositories_raw = raw.get("repositories", [])
        if not isinstance(repositories_raw, list):
            raise ValueError(f"case {cve} repositories must be a list")
        repositories: list[dict[str, Any]] = []
        for item in repositories_raw:
            if not isinstance(item, dict):
                raise ValueError(f"case {cve} repository entry must be an object")
            path = validate_relative_path(item.get("path", item.get("repository", "")))
            allowed = item.get("files", [])
            if not isinstance(allowed, list):
                raise ValueError(f"case {cve} repository files must be a list")
            normalized_allowed = [validate_relative_path(p) for p in allowed]
            repositories.append({"path": path, "files": normalized_allowed,
                                 **{k: item[k] for k in item if k not in ("path", "files")}})
        return cls(cve=cve, project=str(raw["project"]), repository=repository,
                   source_commit=str(raw["source_commit"]), source_parent=str(raw["source_parent"]),
                   target_commit=str(raw["target_commit"]), files=files,
                   validation=tuple(commands), validation_checks=tuple(checks),
                   source_url=str(raw.get("source_url", "")),
                   source_version=str(raw.get("source_version", "")),
                   target_version=str(raw.get("target_version", "")),
                   manifest=str(raw.get("manifest", "")), repositories=tuple(repositories))


def validate_relative_path(value: Any) -> str:
    """Accept exact repository-relative POSIX paths, never Git metadata or globs."""
    if (not isinstance(value, str) or not value or value.startswith(("/", "-"))
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or any(char in value for char in "\\:*?[]")):
        raise ValueError(f"unsafe repository path: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..", ".git", ".repo", ".codex", ".agents") for part in parts):
        raise ValueError(f"unsafe repository path: {value!r}")
    return value


def load_cases(dataset: Path) -> dict[str, Case]:
    dataset = dataset.resolve()
    if dataset.is_file():
        raw = json.loads(dataset.read_text())
        rows = raw.get("cases", [raw]) if isinstance(raw, dict) else raw
        root = dataset.parent
    else:
        rows = []
        root = dataset
        for path in sorted(dataset.glob("*.json")):
            rows.append(json.loads(path.read_text()))
    cases = {}
    for row in rows:
        case = Case.from_dict(row)
        if case.cve in cases:
            raise ValueError(f"duplicate case identifier: {case.cve}")
        cases[case.cve] = case
    if not cases:
        raise ValueError(f"no cases found in {root}")
    return cases


def load_case(dataset: Path, cve: str) -> Case:
    try:
        return load_cases(dataset)[cve]
    except KeyError as exc:
        raise ValueError(f"{cve} is not present in dataset {dataset}") from exc
