import asyncio
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from aosp_agent.sdk_runtime import CodexRuntime, CodexRuntimeError


class FakeHandle:
    id = "turn-1"

    def __init__(self, mode):
        self.mode = mode
        self.interrupted = False

    async def interrupt(self):
        self.interrupted = True

    async def stream(self):
        if self.mode == "timeout":
            await asyncio.sleep(5)
        if self.mode == "missing_completion":
            return
        item = {"type": "agentMessage", "phase": "final_answer", "text": '{"verdict":"ready"}'}
        yield types.SimpleNamespace(method="item/completed", payload={"item": item})
        yield types.SimpleNamespace(method="thread/tokenUsage/updated", payload={"token_usage": {"total": {"total_tokens": 123}}})
        error = {"message": "HTTP 401 Unauthorized"} if self.mode == "failed" else None
        status = "failed" if error else "interrupted" if self.mode == "interrupted" else "completed"
        yield types.SimpleNamespace(method="turn/completed", payload={"turn": {"id": self.id, "status": status, "error": error}})


class FakeThread:
    id = "thread-1"

    def __init__(self, mode):
        self.mode = mode
        self.calls = []
        self.handle = None

    async def turn(self, prompt, **kwargs):
        self.calls.append(kwargs)
        self.handle = FakeHandle(self.mode)
        return self.handle


class FakeCodex:
    def __init__(self, config, mode):
        self.thread = FakeThread(mode)
        self.metadata = {"serverInfo": {"version": "fake"}}
        self.closed = False
        self.starts = []

    async def __aenter__(self):
        return self

    async def thread_start(self, **kwargs):
        self.starts.append(kwargs)
        return self.thread

    async def close(self):
        self.closed = True


class RuntimeTest(unittest.TestCase):
    def run_fake(self, mode, *, schema=None, timeout=1):
        fake = None

        def factory(config):
            nonlocal fake
            fake = FakeCodex(config, mode)
            return fake

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("openai_codex.AsyncCodex", factory):
                runtime = CodexRuntime(root / "events.jsonl", turn_timeout=timeout,
                                       env={"TEST_API_KEY": "example-secret-value"})
                try:
                    with runtime:
                        runtime.start(root, "defensive patch review")
                        result = runtime.run("Read evidence, example-secret-value", output_schema=schema)
                        runtime.run("Review", read_only=False)
                except CodexRuntimeError as exc:
                    result = exc
            log = (root / "events.jsonl").read_text()
            self.assertNotIn("example-secret-value", log)
            events = [json.loads(line) for line in log.splitlines()]
            self.assertTrue(fake.closed)
            return result, fake, events

    def test_streamed_turn_and_permissions(self):
        result, fake, events = self.run_fake("completed", schema={"type": "object", "required": ["verdict"], "properties": {"verdict": {"type": "string"}}, "additionalProperties": False})
        self.assertEqual(result["output"], {"verdict": "ready"})
        self.assertEqual(result["usage"]["total"]["total_tokens"], 123)
        self.assertEqual(fake.starts[0]["model"], "gpt-5.6-sol")
        self.assertEqual(fake.starts[0]["approval_mode"].value, "deny_all")
        self.assertNotEqual(fake.thread.calls[0]["sandbox"], fake.thread.calls[1]["sandbox"])
        self.assertEqual(fake.thread.calls[0]["effort"], "low")
        self.assertTrue(any(event.get("method") == "item/completed" for event in events))

    def test_failed_and_interrupted_turns_are_not_success(self):
        for mode, expected in (("failed", "AUTH_REQUIRED"), ("interrupted", "INTERRUPTED"), ("missing_completion", "INCOMPLETE_TURN")):
            with self.subTest(mode=mode):
                result, _, _ = self.run_fake(mode)
                self.assertIsInstance(result, CodexRuntimeError)
                self.assertEqual(result.kind, expected)

    def test_timeout_interrupts_and_closes(self):
        result, fake, events = self.run_fake("timeout", timeout=0.05)
        self.assertEqual(result.kind, "TIMEOUT")
        self.assertTrue(fake.thread.handle.interrupted)
        self.assertTrue(any(event["event"] == "turn_interrupt_requested" for event in events))

    def test_invalid_structured_output_is_rejected(self):
        result, _, _ = self.run_fake("completed", schema={"type": "object", "required": ["missing"]})
        self.assertEqual(result.kind, "INVALID_OUTPUT")


if __name__ == "__main__":
    unittest.main()
