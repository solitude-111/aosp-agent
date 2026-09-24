import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aosp_agent.glm_runtime import GLMRuntime, GLMRuntimeError


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def chat(self, payload):
        self.requests.append(json.loads(json.dumps(payload, ensure_ascii=False)))
        return self.responses.pop(0)


def message(content=None, tool_calls=None):
    return {"choices": [{"finish_reason": "tool_calls" if tool_calls else "stop",
                         "message": {"content": content, "tool_calls": tool_calls}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}}


def tool_call(name, arguments):
    return {"id": f"call-{name}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


class GLMRuntimeTest(unittest.TestCase):
    def run_runtime(self, responses, *, read_only=True, schema=None, prompts=("Read evidence.txt.",)):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "evidence.txt").write_text("glm-read-check\n", encoding="utf-8")
            fake = FakeClient(responses)
            factory = mock.Mock(return_value=fake)
            with mock.patch("aosp_agent.glm_runtime.GLMClient", factory):
                with GLMRuntime(root / "events.jsonl", env={"GLM_API_KEY": "test-secret-value"}) as runtime:
                    runtime.start(workspace, "Return only requested JSON.")
                    result = None
                    for prompt in prompts:
                        result = runtime.run(prompt, read_only=read_only, output_schema=schema)
            events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
        return result, fake, events, workspace

    def test_tool_loop_structured_output_and_redacted_events(self):
        schema = {"type": "object", "required": ["content"], "additionalProperties": False,
                  "properties": {"content": {"type": "string"}}}
        result, client, events, _ = self.run_runtime([
            message(tool_calls=[tool_call("view_file", {"path": "evidence.txt", "start": 1, "end": 1})]),
            message("```json\n{\"content\":\"glm-read-check\"}\n```"),
        ], schema=schema)
        self.assertEqual(result["output"], {"content": "glm-read-check"})
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["thread_id"].startswith("glm-"))
        self.assertTrue(result["turn_id"].startswith(result["thread_id"] + "-turn-"))
        self.assertEqual(result["usage"]["total_tokens"], 12)
        self.assertEqual(client.requests[1]["messages"][-1]["role"], "tool")
        self.assertIn("glm-read-check", client.requests[1]["messages"][-1]["content"])
        self.assertNotIn("test-secret-value", (events[0]["sequence"] and json.dumps(events)))
        self.assertTrue(any(item["type"] == "glmToolCall" for item in result["items"]))

    def test_read_only_phase_rejects_write_tool(self):
        result, client, _, workspace = self.run_runtime([
            message(tool_calls=[tool_call("write_file", {"path": "output.txt", "content": "denied"})]),
            message("write denied"),
        ])
        self.assertFalse((workspace / "output.txt").exists())
        self.assertIn("READ-ONLY", client.requests[0]["messages"][-2]["content"])
        self.assertIn("write_file is unavailable", client.requests[1]["messages"][-1]["content"])

    def test_conversation_preserves_user_turn_context(self):
        result, client, _, _ = self.run_runtime([message("first"), message("second")],
                                                prompts=("Read evidence.txt.", "Read it again."))
        self.assertEqual(result["output"], "second")
        users = [message for message in client.requests[1]["messages"]
                 if message["role"] == "user"]
        self.assertEqual([message["content"] for message in users],
                         ["Read evidence.txt.", "Read it again."])

    def test_invalid_structured_output_is_rejected(self):
        schema = {"type": "object", "required": ["missing"], "additionalProperties": False,
                  "properties": {"missing": {"type": "string"}}}
        with self.assertRaises(GLMRuntimeError) as raised:
            self.run_runtime([message("not json")], schema=schema)
        self.assertEqual(raised.exception.kind, "INVALID_OUTPUT")

    def test_redundant_glm_overall_summary_is_merged(self):
        schema = {"type": "object", "required": ["reasoning"], "additionalProperties": False,
                  "properties": {"reasoning": {"type": "string"}}}
        result, client, _, _ = self.run_runtime(
            [message('{"reasoning":"target evidence","overall":"not affected"}')], schema=schema)
        self.assertEqual(result["output"], {
            "reasoning": "target evidence\n\nOverall: not affected"
        })
        self.assertEqual(client.requests[0]["reasoning_effort"], "low")

    def test_invalid_schema_triggers_one_json_repair_turn(self):
        schema = {"type": "object", "required": ["reasoning"], "additionalProperties": False,
                  "properties": {"reasoning": {"type": "string"}}}
        result, client, _, _ = self.run_runtime([
            message('{"summary":"wrong shape"}'),
            message('{"reasoning":"repaired"}'),
        ], schema=schema)
        self.assertEqual(result["output"], {"reasoning": "repaired"})
        repair_request = client.requests[1]
        self.assertEqual(repair_request["tools"], [])
        self.assertEqual(repair_request["tool_choice"], "none")
        self.assertIn("required JSON schema", repair_request["messages"][-1]["content"])

    def test_workspace_traversal_is_rejected(self):
        result, client, _, _ = self.run_runtime([
            message(tool_calls=[tool_call("view_file", {"path": "../secret", "start": 1, "end": 1})]),
            message("traversal denied"),
        ])
        self.assertIn("outside the workspace", client.requests[1]["messages"][-1]["content"])
        self.assertEqual(result["output"], "traversal denied")

    def test_internal_git_directory_is_rejected(self):
        result, client, _, _ = self.run_runtime([
            message(tool_calls=[tool_call("view_file", {"path": ".git/config", "start": 1, "end": 1})]),
            message("git directory denied"),
        ])
        self.assertIn("internal project directories", client.requests[1]["messages"][-1]["content"])
        self.assertEqual(result["output"], "git directory denied")


if __name__ == "__main__":
    unittest.main()
