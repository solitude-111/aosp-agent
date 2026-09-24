"""Observable GLM runtime with bounded, controller-mediated tools."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .direct_api import GLM_DEFAULT_BASE_URL, GLMClient


DEFAULT_GLM_MODEL = "glm-5.3"
CONTROLLED_COMMANDS = {"locate-symbol", "view-code", "hunk-history", "show-commit"}


class GLMRuntimeError(RuntimeError):
    def __init__(self, message: str, *, kind: str = "GLM_ERROR", details: dict | None = None):
        super().__init__(message)
        self.kind = kind
        self.details = details or {}


class GLMRuntime:
    """One GLM conversation with durable events and a bounded tool loop.

    GLM has no built-in workspace agent. This runtime supplies only local file
    views, workspace writes, directory listings, and the four controller-owned
    AOSP tools. Writes are rejected in read-only phases and all paths are
    resolved against the session cwd to block symlink and traversal escapes.
    """

    def __init__(self, events_path: Path, model: str = DEFAULT_GLM_MODEL,
                 model_provider: str | None = None, turn_timeout: float = 900,
                 env: dict[str, str] | None = None,
                 reasoning_effort: str | None = None, api_base_url: str | None = None,
                 api_key_env: str | None = None, max_tool_calls: int = 64,
                 max_output_tokens: int = 16384):
        if turn_timeout <= 0:
            raise ValueError("turn_timeout must be positive")
        if max_tool_calls <= 0:
            raise ValueError("max_tool_calls must be positive")
        if max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")
        self.events_path = Path(events_path).resolve()
        self.model = model
        self.model_provider = model_provider or "bigmodel"
        self.turn_timeout = float(turn_timeout)
        self.env = dict(env or {})
        self.reasoning_effort = reasoning_effort
        self.api_base_url = (api_base_url or self.env.get("AOSP_AGENT_GLM_BASE_URL")
                             or os.environ.get("AOSP_AGENT_GLM_BASE_URL")
                             or GLM_DEFAULT_BASE_URL).rstrip("/")
        self.api_key_env = (api_key_env or self.env.get("AOSP_AGENT_GLM_API_KEY_ENV")
                            or os.environ.get("AOSP_AGENT_GLM_API_KEY_ENV")
                            or "GLM_API_KEY")
        self.max_tool_calls = max_tool_calls
        self.max_output_tokens = max_output_tokens
        self._messages: list[dict[str, Any]] = []
        self._cwd: Path | None = None
        self._thread_id = f"glm-{uuid.uuid4().hex}"
        self._turn_count = 0
        self._closed = False
        self._opened = False
        self._event_count = 0
        self._client: GLMClient | None = None
        combined = {**os.environ, **self.env}
        self._secrets = tuple(value for name, value in combined.items()
                              if len(value) >= 8 and re.search(r"KEY|TOKEN|PASSWORD|SECRET|AUTH", name, re.I))

    def __enter__(self) -> "GLMRuntime":
        if self._opened or self._closed:
            raise RuntimeError("GLMRuntime instances may only be entered once")
        combined = {**os.environ, **self.env}
        api_key = (combined.get(self.api_key_env) or combined.get("GLM_API_KEY")
                   or combined.get("ZHIPUAI_API_KEY"))
        if not api_key:
            raise GLMRuntimeError(f"Set {self.api_key_env} to a GLM API key", kind="AUTH_REQUIRED")
        self._client = GLMClient(self.api_base_url, api_key, self.model, self.turn_timeout)
        self._opened = True
        self._log("runtime_start", backend="glm", model=self.model, provider=self.model_provider,
                  api_base_url=self.api_base_url, api_key_env=self.api_key_env,
                  turn_timeout=self.turn_timeout, max_tool_calls=self.max_tool_calls)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self, cwd: Path | str, instructions: str) -> str:
        self._require_open()
        if self._cwd is not None:
            raise RuntimeError("This runtime already has a conversation")
        self._cwd = Path(cwd).resolve()
        if not self._cwd.is_dir():
            raise ValueError("cwd must be an existing directory")
        self._messages = [{"role": "system", "content": instructions + "\n\n" + _TOOL_INSTRUCTIONS}]
        self._log("thread_started", thread_id=self._thread_id, cwd=str(self._cwd),
                  backend="glm", tools=["view_file", "list_dir", "search_files", "write_file",
                                        "run_controlled_command"])
        return self._thread_id

    def run(self, prompt: str, read_only: bool = True,
            output_schema: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_open()
        if self._cwd is None:
            raise RuntimeError("start(cwd, instructions) must be called before run")
        validator = None
        if output_schema is not None:
            try:
                from jsonschema.validators import validator_for
            except ImportError as exc:
                raise GLMRuntimeError("Install aosp_agent/requirements-glm.txt",
                                      kind="DEPENDENCY_MISSING") from exc
            validator_class = validator_for(output_schema)
            validator_class.check_schema(output_schema)
            validator = validator_class(output_schema)

        self._turn_count += 1
        turn_id = f"{self._thread_id}-turn-{self._turn_count}"
        started = time.monotonic()
        deadline = started + self.turn_timeout
        self._log("turn_requested", thread_id=self._thread_id, turn_id=turn_id, prompt=prompt,
                  sandbox="read_only" if read_only else "workspace_write",
                  output_schema=output_schema)
        request_messages = list(self._messages)
        request_messages.append({"role": "system", "content": _mode_instructions(read_only)})
        user_message = {"role": "user", "content": prompt}
        request_messages.append(user_message)
        self._messages.append(user_message)
        items: list[dict[str, Any]] = []
        tool_calls_made = 0
        usage: dict[str, Any] | None = None
        final_content = ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GLMRuntimeError(f"GLM turn exceeded {self.turn_timeout} seconds", kind="TIMEOUT")
            assert self._client is not None
            self._client.timeout = min(self.turn_timeout, remaining)
            payload = {
                "messages": request_messages,
                "tools": _TOOL_SCHEMAS,
                "tool_choice": "auto",
                "temperature": 0,
                "max_tokens": self.max_output_tokens,
            }
            if self.reasoning_effort:
                payload["thinking"] = {"type": "enabled"} if self.reasoning_effort != "none" else {"type": "disabled"}
            self._log("glm_request", turn_id=turn_id, message_count=len(request_messages), tools=len(_TOOL_SCHEMAS))
            try:
                body = self._client.chat(payload)
            except Exception as exc:
                error = self._as_runtime_error(exc)
                self._log("runtime_error", kind=error.kind, message=str(error))
                raise error from exc
            usage = _usage(body.get("usage"))
            choice = _choice(body)
            message = choice.get("message") or {}
            content = _content(message.get("content"))
            finish_reason = choice.get("finish_reason")
            self._log("glm_response", turn_id=turn_id, finish_reason=finish_reason,
                      content_characters=len(content), usage=usage)
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                items.append({"type": "glmMessage", "phase": "tool_use", "content": content,
                              "tool_calls": tool_calls})
                assistant_message = {"role": "assistant", "content": content,
                                     "tool_calls": tool_calls}
                request_messages.append(assistant_message)
                self._messages.append(assistant_message)
                for tool_call in tool_calls:
                    tool_calls_made += 1
                    if tool_calls_made > self.max_tool_calls:
                        raise GLMRuntimeError(f"GLM exceeded the {self.max_tool_calls} tool-call limit",
                                              kind="TOOL_LIMIT")
                    call_id = str(tool_call.get("id") or f"{turn_id}-tool-{tool_calls_made}")
                    function = tool_call.get("function") or {}
                    name = str(function.get("name") or "")
                    arguments = None
                    try:
                        arguments = json.loads(function.get("arguments") or "{}")
                        if not isinstance(arguments, dict):
                            raise ValueError("tool arguments must be a JSON object")
                        result = self._execute_tool(name, arguments, read_only=read_only,
                                                    deadline=deadline)
                    except Exception as exc:
                        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                        self._log("glm_tool_error", turn_id=turn_id, tool_call_id=call_id,
                                  tool=name, error=result["error"])
                    tool_message = {"role": "tool", "tool_call_id": call_id, "name": name,
                                    "content": json.dumps(result, ensure_ascii=False)}
                    request_messages.append(tool_message)
                    self._messages.append(tool_message)
                    items.append({"type": "glmToolCall", "tool_call_id": call_id, "name": name,
                                  "arguments": arguments,
                                  "result": result})
                continue
            if not content.strip():
                raise GLMRuntimeError("GLM completed the turn with an empty message",
                                      kind="EMPTY_OUTPUT")
            final_content = content
            final_message = {"role": "assistant", "content": content}
            request_messages.append(final_message)
            self._messages.append(final_message)
            items.append({"type": "glmMessage", "phase": "final_answer", "content": content})
            break

        try:
            output = _json_output(final_content) if output_schema is not None else final_content
            if validator is not None:
                validator.validate(output)
        except Exception as exc:
            error = GLMRuntimeError("GLM output does not satisfy the requested JSON schema: "
                                    + str(exc), kind="INVALID_OUTPUT", details={"response": final_content})
            self._log("runtime_error", kind=error.kind, message=str(error))
            raise error from exc
        response_text = json.dumps(output, ensure_ascii=False) if output_schema is not None else final_content
        result = {"thread_id": self._thread_id, "turn_id": turn_id, "status": "completed",
                  "finish_reason": finish_reason, "final_response": response_text, "output": output,
                  "usage": usage, "items": items, "tool_calls": tool_calls_made,
                  "elapsed_seconds": round(time.monotonic() - started, 3),
                  "events_path": str(self.events_path)}
        self._log("turn_result", **result)
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._opened:
            self._log("runtime_closed")

    def _execute_tool(self, name: str, arguments: dict[str, Any], *, read_only: bool,
                      deadline: float) -> dict[str, Any]:
        if name == "view_file":
            return _view_file(self._assert_cwd(), arguments)
        if name == "list_dir":
            return _list_dir(self._assert_cwd(), arguments)
        if name == "search_files":
            if self.env.get("AOSP_AGENT_ENABLE_SEARCH") != "1":
                raise PermissionError("file search is not enabled for this runtime")
            return _search_files(self._assert_cwd(), arguments)
        if name == "write_file":
            if read_only:
                raise PermissionError("write_file is unavailable in a read-only phase")
            return _write_file(self._assert_cwd(), arguments)
        if name == "run_controlled_command":
            return self._run_controlled_command(arguments, deadline)
        raise ValueError(f"unsupported GLM tool: {name}")

    def _run_controlled_command(self, arguments: dict[str, Any], deadline: float) -> dict[str, Any]:
        command = arguments.get("command")
        if (not isinstance(command, list) or not command
                or any(not isinstance(part, str) or not part for part in command)):
            raise ValueError("command must be a non-empty JSON array of strings")
        tool_root = self.env.get("AOSP_AGENT_TOOL_BIN_DIR")
        if not tool_root:
            raise PermissionError("controlled tool directory is not configured")
        tool_root = Path(tool_root).resolve()
        executable = Path(command[0])
        executable = (executable if executable.is_absolute() else self._assert_cwd() / executable).resolve()
        if (executable.parent != tool_root or executable.name not in CONTROLLED_COMMANDS
                or not executable.is_file()):
            raise PermissionError("only the four controller-generated AOSP tools may be executed")
        safe_command = [str(executable), *command[1:]]
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("controlled tool exceeded the GLM turn deadline")
        try:
            completed = subprocess.run(safe_command, cwd=self._cwd, text=True, capture_output=True,
                                       env=environment, timeout=min(60, remaining), check=False)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"controlled tool exceeded {min(60, remaining):.1f} seconds") from exc
        self._log("glm_notification", method="item/completed", payload={
            "item": {"type": "commandExecution", "command": safe_command,
                     "returncode": completed.returncode,
                     "aggregatedOutput": (completed.stdout or "") + (completed.stderr or "")}})
        return {"ok": completed.returncode == 0, "returncode": completed.returncode,
                "stdout": _clip(completed.stdout), "stderr": _clip(completed.stderr)}

    def _assert_cwd(self) -> Path:
        if self._cwd is None:
            raise RuntimeError("GLM conversation has not started")
        return self._cwd

    def _require_open(self) -> None:
        if self._closed or not self._opened or self._client is None:
            raise RuntimeError("Use GLMRuntime inside a with statement")

    def _as_runtime_error(self, exc: Exception) -> GLMRuntimeError:
        message = self._redact(str(exc))
        lowered = message.lower()
        if getattr(exc, "status_code", None) in (401, 403) or "unauthorized" in lowered or "forbidden" in lowered:
            kind = "AUTH_REQUIRED"
        elif "model not found" in lowered or "model_not_found" in lowered or "does not exist" in lowered:
            kind = "MODEL_UNAVAILABLE"
        elif "timed out" in lowered or "timeout" in lowered:
            kind = "TIMEOUT"
        else:
            kind = "GLM_ERROR"
        return GLMRuntimeError(message, kind=kind)

    def _redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}", "[REDACTED]", text)
        text = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
        return text

    def _log(self, event: str, **data: Any) -> None:
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self._event_count += 1
        entry = {"sequence": self._event_count,
                 "timestamp": datetime.now(timezone.utc).isoformat(),
                 "event": event, **data}
        encoded = self._redact(json.dumps(entry, ensure_ascii=False, default=str))
        descriptor = os.open(self.events_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")


def _mode_instructions(read_only: bool) -> str:
    if read_only:
        return ("Current phase is READ-ONLY. You may call view_file, list_dir, and "
                "run_controlled_command; write_file attempts will fail.")
    return ("Current phase is WORKSPACE_WRITE. Make edits only with write_file, and only "
            "inside the current workspace. Controlled history commands remain read-only.")


_TOOL_INSTRUCTIONS = """GLM tool protocol:
- Use the provided function tools instead of requesting a shell.
- Use view_file/list_dir for bounded workspace reads.
- Use run_controlled_command only for the four controller-generated AOSP tools shown in task context.
- In a write phase, edit only declared allowlisted paths with write_file.
- After tool results are sufficient, stop calling tools and return the requested final text."""


_TOOL_SCHEMAS = [
    {"type": "function", "function": {
        "name": "view_file",
        "description": "Read a bounded, line-numbered UTF-8 file slice inside the session workspace.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Workspace-relative path"},
            "start": {"type": "integer", "minimum": 1},
            "end": {"type": "integer", "minimum": 1},
        }, "required": ["path", "start", "end"], "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "list_dir",
        "description": "List one directory inside the session workspace without recursion.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "default": "."},
        }, "required": ["path"], "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "search_files",
        "description": "Search UTF-8 text files with one bounded regular expression inside the workspace.",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"},
            "path": {"type": "string", "default": "."},
        }, "required": ["pattern", "path"], "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "Create or replace one UTF-8 file inside the session workspace.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"},
        }, "required": ["path", "content"], "additionalProperties": False}}},
    {"type": "function", "function": {
        "name": "run_controlled_command",
        "description": "Execute only locate-symbol, view-code, hunk-history, or show-commit.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "array", "items": {"type": "string"}},
        }, "required": ["command"], "additionalProperties": False}}},
]


def _inside(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("path must be a non-empty string")
    candidate = Path(relative)
    if candidate.is_absolute():
        raise PermissionError("absolute paths are not allowed")
    if any(part in (".git", ".repo", ".codex", ".agents") for part in candidate.parts):
        raise PermissionError("internal project directories are not accessible")
    resolved = (root / candidate).resolve(strict=False)
    if resolved != root and not resolved.is_relative_to(root):
        raise PermissionError("path resolves outside the workspace")
    return resolved


def _view_file(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    path = _inside(root, arguments.get("path"))
    start, end = arguments.get("start", 1), arguments.get("end")
    if not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start:
        raise ValueError("start and end must be integers with 1 <= start <= end")
    if end - start >= 2000:
        raise ValueError("view_file is limited to 2000 lines per call")
    if not path.is_file():
        return {"ok": False, "error": "file does not exist"}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if start > len(lines):
        return {"ok": False, "error": "start is past end of file", "line_count": len(lines)}
    selected = lines[start - 1:min(end, len(lines))]
    rendered = "\n".join(f"{number:>6}: {line}" for number, line in enumerate(selected, start))
    return {"ok": True, "start": start, "end": start + len(selected) - 1,
            "line_count": len(lines), "content": _clip(rendered)}


def _list_dir(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    path = _inside(root, arguments.get("path", "."))
    if not path.is_dir():
        return {"ok": False, "error": "directory does not exist"}
    entries = []
    for child in sorted(path.iterdir(), key=lambda item: item.name)[:2000]:
        entries.append({"name": child.name, "type": "directory" if child.is_dir() else "file"})
    return {"ok": True, "path": arguments.get("path", "."), "entries": entries}


def _write_file(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    path = _inside(root, arguments.get("path"))
    content = arguments.get("content")
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return {"ok": True, "path": arguments.get("path"), "bytes_written": len(content.encode("utf-8"))}


def _search_files(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    pattern = arguments.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("pattern must be a non-empty string")
    try:
        matcher = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regular expression: {exc}") from exc
    search_root = _inside(root, arguments.get("path", "."))
    if not search_root.is_dir():
        return {"ok": False, "error": "directory does not exist"}
    matches, files_scanned = [], 0
    for current, directories, files in os.walk(search_root):
        directories[:] = sorted(name for name in directories if name != ".git")
        for filename in sorted(files):
            files_scanned += 1
            if files_scanned > 10000 or len(matches) >= 500:
                return {"ok": True, "complete": False, "files_scanned": files_scanned,
                        "matches": matches, "truncation_reason": "search_limit"}
            path = Path(current) / filename
            try:
                if path.stat().st_size > 2_000_000:
                    continue
                lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
            except (OSError, UnicodeError):
                continue
            for line_number, line in enumerate(lines, 1):
                if matcher.search(line):
                    matches.append({"path": str(path.relative_to(root)), "line": line_number,
                                    "text": line[:500]})
                    if len(matches) >= 500:
                        break
    return {"ok": True, "complete": True, "files_scanned": files_scanned, "matches": matches}


def _choice(body: dict[str, Any]) -> dict[str, Any]:
    choices = body.get("choices") or []
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise GLMRuntimeError("GLM API returned no choices", kind="INVALID_RESPONSE")
    return choices[0]


def _content(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for part in value:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
        if parts:
            return "".join(parts)
    raise GLMRuntimeError("GLM API returned an unsupported message content", kind="INVALID_RESPONSE")


def _usage(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    prompt_tokens = value.get("prompt_tokens", value.get("input_tokens"))
    completion_tokens = value.get("completion_tokens", value.get("output_tokens"))
    total_tokens = value.get("total_tokens")
    if total_tokens is None and isinstance(prompt_tokens, int) and isinstance(completion_tokens, int):
        total_tokens = prompt_tokens + completion_tokens
    return {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
            "total_tokens": total_tokens}


def _json_output(content: str) -> Any:
    text = content.strip()
    if text.startswith("```json\n") and text.endswith("```"):
        text = text[8:-3].strip()
    elif text.startswith("```\n") and text.endswith("```"):
        text = text[4:-3].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
        raise


def _clip(text: str, limit: int = 200_000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated; {len(text) - limit} characters omitted]"
