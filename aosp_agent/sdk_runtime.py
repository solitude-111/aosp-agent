"""Bounded, observable execution through the official Codex Python SDK.

The synchronous facade owns one AsyncCodex session and an event loop. It uses
the SDK's pinned app-server binary unless ``codex_path`` is explicitly supplied.
It never rewrites Codex configuration or authentication files. Call from a sync
worker when integrating into an application that already has an asyncio loop.
"""
from __future__ import annotations

import asyncio
import dataclasses
import importlib.metadata
import json
import os
import re
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class CodexRuntimeError(RuntimeError):
    def __init__(self, message: str, *, kind: str = "CODEX_ERROR", details: dict | None = None):
        super().__init__(message)
        self.kind = kind
        self.details = details or {}


class CodexRuntime:
    """One Codex conversation with explicit sandbox changes and durable events.

    ``output`` is parsed and schema-validated JSON if output_schema is supplied;
    otherwise it is the final response text. Errors never become success results.
    Timeout closes the runtime; construct a new instance for a later attempt.
    Environment overrides are passed to the SDK, never written to disk or logged.
    """

    def __init__(self, events_path: Path, model: str = "gpt-5.6-sol",
                 model_provider: str | None = None, turn_timeout: float = 900,
                 codex_path: str | None = None, env: dict[str, str] | None = None,
                 reasoning_effort: str | None = "low"):
        if turn_timeout <= 0:
            raise ValueError("turn_timeout must be positive")
        self.events_path = Path(events_path).resolve()
        self.model = model
        self.model_provider = model_provider
        self.turn_timeout = float(turn_timeout)
        self.codex_path = codex_path
        self.reasoning_effort = reasoning_effort
        self.env = dict(env or {})
        self._loop = None
        self._codex = None
        self._thread = None
        self._handle = None
        self._cwd = None
        self._closed = False
        self._event_count = 0
        combined = {**os.environ, **self.env}
        self._secrets = tuple(value for name, value in combined.items()
                              if len(value) >= 8 and re.search(r"KEY|TOKEN|PASSWORD|SECRET|AUTH", name, re.I))

    def __enter__(self) -> "CodexRuntime":
        if self._loop is not None or self._closed:
            raise RuntimeError("CodexRuntime instances may only be entered once")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("CodexRuntime is synchronous; call it from a worker thread")
        try:
            from openai_codex import AsyncCodex, ApprovalMode, CodexConfig, Sandbox
        except ImportError as exc:
            raise CodexRuntimeError(
                "Install aosp_agent/requirements-sdk.txt in the execution environment",
                kind="SDK_MISSING") from exc
        self._sandbox = Sandbox
        self._approval = ApprovalMode.deny_all
        self._loop = asyncio.new_event_loop()
        self._codex = AsyncCodex(CodexConfig(codex_bin=self.codex_path, env=self.env or None,
                                           client_name="aosp_backport_agent"))
        self._log("runtime_start", model=self.model, model_provider=self.model_provider,
                  sdk_version=importlib.metadata.version("openai-codex"),
                  codex_bin=self.codex_path or "sdk-pinned", turn_timeout=self.turn_timeout)
        try:
            self._call(self._codex.__aenter__(), timeout=min(30, self.turn_timeout))
            self._log("runtime_ready", metadata=_plain(self._codex.metadata))
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self, cwd: Path | str, instructions: str) -> str:
        self._require_open()
        if self._thread is not None:
            raise RuntimeError("This runtime already has a conversation")
        self._cwd = Path(cwd).resolve()
        if not self._cwd.is_dir():
            raise ValueError("cwd must be an existing directory")
        kwargs = dict(cwd=str(self._cwd), base_instructions=instructions, model=self.model,
                      sandbox=self._sandbox.read_only, approval_mode=self._approval,
                      ephemeral=True)
        if self.model_provider:
            kwargs["model_provider"] = self.model_provider
        self._thread = self._call(self._codex.thread_start(**kwargs),
                                  timeout=min(30, self.turn_timeout))
        self._log("thread_started", thread_id=self._thread.id, cwd=str(self._cwd),
                  sandbox="read_only", approval_mode="deny_all")
        return self._thread.id

    def run(self, prompt: str, read_only: bool = True,
            output_schema: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_open()
        if self._thread is None:
            raise RuntimeError("start(cwd, instructions) must be called before run")
        validator = None
        if output_schema is not None:
            try:
                from jsonschema.validators import validator_for
            except ImportError as exc:
                raise CodexRuntimeError("Install aosp_agent/requirements-sdk.txt", kind="SDK_MISSING") from exc
            validator_class = validator_for(output_schema)
            validator_class.check_schema(output_schema)
            validator = validator_class(output_schema)
        started = time.monotonic()
        self._log("turn_requested", thread_id=self._thread.id, prompt=prompt,
                  sandbox="read_only" if read_only else "workspace_write",
                  output_schema=output_schema)
        result = self._call(self._consume(prompt, read_only, output_schema), timeout=self.turn_timeout)
        try:
            output = json.loads(result["final_response"]) if output_schema is not None else result["final_response"]
            if validator is not None:
                validator.validate(output)
        except Exception as exc:
            error = CodexRuntimeError("Codex output does not satisfy the requested JSON schema: "
                                      + str(exc), kind="INVALID_OUTPUT", details=result)
            self._log("runtime_error", kind=error.kind, message=str(error))
            raise error from exc
        result.update(output=output, elapsed_seconds=round(time.monotonic() - started, 3),
                      events_path=str(self.events_path))
        self._log("turn_result", **result)
        return result

    async def _consume(self, prompt: str, read_only: bool, output_schema) -> dict[str, Any]:
        self._handle = await self._thread.turn(
            prompt, cwd=str(self._cwd), model=self.model, approval_mode=self._approval,
            sandbox=self._sandbox.read_only if read_only else self._sandbox.workspace_write,
            output_schema=output_schema,
            **({"effort": self.reasoning_effort} if self.reasoning_effort else {}))
        self._log("turn_started", thread_id=self._thread.id, turn_id=self._handle.id)
        items, usage, completed = [], None, None
        async for notification in self._handle.stream():
            payload = _plain(notification.payload)
            method = notification.method
            self._log("sdk_notification", method=method, payload=payload)
            if method == "item/completed":
                items.append(payload["item"])
            elif method == "thread/tokenUsage/updated":
                usage = payload.get("token_usage", payload.get("tokenUsage"))
            elif method == "turn/completed":
                completed = payload["turn"]
        handle_id = self._handle.id
        self._handle = None
        if completed is None:
            raise CodexRuntimeError("SDK stream ended without turn/completed", kind="INCOMPLETE_TURN")
        status = completed.get("status")
        final = _final_response(items)
        result = dict(thread_id=self._thread.id, turn_id=handle_id, status=status,
                      final_response=final, usage=usage, items=items)
        if status != "completed":
            details = completed.get("error") or {}
            message = details.get("message") or f"Codex turn ended with status {status}"
            raise CodexRuntimeError(self._redact(message), kind=_error_kind(message, status), details=result)
        if not final:
            raise CodexRuntimeError("Completed turn has no final response", kind="EMPTY_OUTPUT", details=result)
        return result

    def _call(self, coroutine, *, timeout: float):
        try:
            return self._loop.run_until_complete(asyncio.wait_for(coroutine, timeout))
        except asyncio.TimeoutError as exc:
            self._log("runtime_error", kind="TIMEOUT", message=f"Operation exceeded {timeout} seconds")
            self.close()
            raise CodexRuntimeError(f"Codex operation exceeded {timeout} seconds", kind="TIMEOUT") from exc
        except CodexRuntimeError as exc:
            self._log("runtime_error", kind=exc.kind, message=str(exc), details=exc.details)
            raise
        except Exception as exc:
            message = self._redact(str(exc))
            kind = _error_kind(message)
            self._log("runtime_error", kind=kind, message=message, error_type=type(exc).__name__)
            raise CodexRuntimeError(message, kind=kind) from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._loop is not None:
            try:
                if self._handle is not None:
                    try:
                        self._loop.run_until_complete(asyncio.wait_for(self._handle.interrupt(), 5))
                        self._log("turn_interrupt_requested", turn_id=self._handle.id)
                    except Exception as exc:
                        self._log("interrupt_error", message=str(exc))
                if self._codex is not None:
                    self._loop.run_until_complete(asyncio.wait_for(self._codex.close(), 5))
            except Exception as exc:
                self._log("close_error", message=str(exc))
            finally:
                self._loop.close()
                self._log("runtime_closed")

    def _require_open(self):
        if self._closed or self._loop is None or self._codex is None:
            raise RuntimeError("Use CodexRuntime inside a with statement")

    def _redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, "[REDACTED]")
        text = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}", "[REDACTED]", text)
        text = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", text)
        return text

    def _log(self, event: str, **data) -> None:
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self._event_count += 1
        entry = dict(sequence=self._event_count, timestamp=datetime.now(timezone.utc).isoformat(),
                     event=event, **data)
        encoded = self._redact(json.dumps(_plain(entry), ensure_ascii=False))
        fd = os.open(self.events_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")


def _plain(value):
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {field.name: _plain(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _final_response(items):
    fallback = ""
    for item in reversed(items):
        if item.get("type") != "agentMessage":
            continue
        if item.get("phase") == "final_answer":
            return item.get("text", "")
        if item.get("phase") is None and not fallback:
            fallback = item.get("text", "")
    return fallback


def _error_kind(message: str, status: str | None = None) -> str:
    lower = message.lower()
    if re.search(r"\b(401|403)\b", message) or any(word in lower for word in ("unauthorized", "authentication", "not logged in")):
        return "AUTH_REQUIRED"
    if status == "interrupted":
        return "INTERRUPTED"
    if any(word in lower for word in ("model_not_found", "model not found", "unsupported model")):
        return "MODEL_UNAVAILABLE"
    return "CODEX_ERROR"
