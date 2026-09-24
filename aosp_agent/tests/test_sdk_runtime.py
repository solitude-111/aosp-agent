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
        texts = {
            "completed": '{"verdict":"ready"}',
            # GLM's observed tail slip: complete body, misordered closers.
            "broken_tail": '{"verdict":"ready"}]}',
            # The real signature from CVE-2025-48533 mb-003 (limitations tail).
            "glm_tail": ('{"status":"AFFECTED","evidence":[],"reasoning":"r",'
                         '"limitations":["...lazy fetching disabled."}]}'),
            # Truncation: string left open — repair must decline.
            "truncated": '{"verdict": "uncl',
            "broken_json": '{"status": "AFFECTED", "evidence": []',
        }
        text = texts.get(self.mode, texts["completed"])
        item = {"type": "agentMessage", "phase": "final_answer", "text": text}
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
        self.calls.append({"prompt": prompt, **kwargs})
        mode = self.mode
        if mode == "fix_once":
            mode = "broken_json" if len(self.calls) == 1 else "completed"
        elif mode == "trunc_then_ok":
            mode = "truncated" if len(self.calls) == 1 else "completed"
        self.handle = FakeHandle(mode)
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
        # Unspecified model/effort must be omitted so the Codex config
        # (~/.codex/config.toml, e.g. GLM glm-5.3) stays in control.
        self.assertNotIn("model", fake.starts[0])
        self.assertNotIn("model_provider", fake.starts[0])
        self.assertEqual(fake.starts[0]["approval_mode"].value, "deny_all")
        self.assertNotEqual(fake.thread.calls[0]["sandbox"], fake.thread.calls[1]["sandbox"])
        self.assertNotIn("model", fake.thread.calls[0])
        self.assertNotIn("effort", fake.thread.calls[0])
        self.assertTrue(any(event.get("method") == "item/completed" for event in events))

    def test_explicit_model_and_effort_are_forwarded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("openai_codex.AsyncCodex", lambda config: FakeCodex(config, "completed")):
                with CodexRuntime(root / "events.jsonl", model="glm-5.3",
                                  model_provider="ZAI", reasoning_effort="high") as runtime:
                    runtime.start(root, "instructions")
                    runtime.run("prompt")
            self.assertEqual(runtime._codex.starts[0]["model"], "glm-5.3")
            self.assertEqual(runtime._codex.starts[0]["model_provider"], "ZAI")
            self.assertEqual(runtime._codex.thread.calls[0]["model"], "glm-5.3")
            self.assertEqual(runtime._codex.thread.calls[0]["effort"], "high")

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

    def test_malformed_json_gets_exactly_one_corrective_retry(self):
        # First reply has a JSON syntax slip (unclosed object); the corrective
        # re-ask must repair it without the caller seeing an error.
        result, fake, events = self.run_fake("fix_once", schema={
            "type": "object", "required": ["verdict"],
            "properties": {"verdict": {"type": "string"}}, "additionalProperties": False})
        self.assertEqual(result["output"], {"verdict": "ready"})
        self.assertTrue(result.get("corrected_after"))
        # run_fake performs a second plain run() after the structured one:
        # calls = [structured turn, corrective turn, plain "Review" turn].
        self.assertEqual(len(fake.thread.calls), 3)
        self.assertIn("JSON schema exactly", fake.thread.calls[1]["prompt"])
        self.assertTrue(any(event.get("event") == "output_retry" for event in events))

    def test_persistently_malformed_json_is_still_invalid(self):
        result, _, _ = self.run_fake("broken_json", schema={
            "type": "object", "required": ["verdict"],
            "properties": {"verdict": {"type": "string"}}, "additionalProperties": False})
        self.assertIsInstance(result, CodexRuntimeError)
        self.assertEqual(result.kind, "INVALID_OUTPUT")

    def test_tail_slip_is_repaired_without_model_roundtrip(self):
        # GLM's deterministic '"}]}' tail slip must be fixed in place: no
        # corrective turn, no INVALID_OUTPUT — but the repair is logged.
        # run_fake performs one structured run plus one plain run afterwards,
        # so exactly 2 turns means the structured one needed no corrective ask.
        for mode in ("broken_tail", "glm_tail"):
            with self.subTest(mode=mode):
                result, fake, events = self.run_fake(mode, schema={"type": "object"})
                self.assertNotIsInstance(result, CodexRuntimeError)
                self.assertTrue(result.get("json_repaired"))
                self.assertEqual(len(fake.thread.calls), 2)
                self.assertTrue(any(event.get("event") == "output_json_repaired" for event in events))

    def test_truncated_json_is_never_repaired(self):
        # A truncation (string left open) must be declined: the corrective
        # re-ask handles it instead of silently accepting a broken document.
        # 3 turns = truncated + corrective + the plain trailing run.
        result, fake, events = self.run_fake("trunc_then_ok", schema={"type": "object"})
        self.assertEqual(result["output"], {"verdict": "ready"})
        self.assertNotIn("json_repaired", result)
        self.assertEqual(len(fake.thread.calls), 3)
        self.assertFalse(any(event.get("event") == "output_json_repaired" for event in events))


if __name__ == "__main__":
    unittest.main()
