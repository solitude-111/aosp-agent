"""Explicit live smoke: one GPT-5.6 Sol turn, with an actual read-only tool call.

Run manually; this is not part of unittest discovery and uses model quota.
"""
import argparse
import hashlib
import json
from pathlib import Path

from aosp_agent.sdk_runtime import CodexRuntime, CodexRuntimeError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--timeout", default=120, type=float)
    args = parser.parse_args()
    root = args.run_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if (root / "events.jsonl").exists():
        raise SystemExit("Use a new run directory; an existing live trace must not be overwritten")
    workspace = root / "workspace"
    workspace.mkdir(exist_ok=True)
    fixture = workspace / "evidence.txt"
    fixture.write_text("sdk-read-check\n", encoding="utf-8")
    before = hashlib.sha256(fixture.read_bytes()).hexdigest()
    schema = {"type": "object", "properties": {"content": {"type": "string"}},
              "required": ["content"], "additionalProperties": False}
    try:
        with CodexRuntime(root / "events.jsonl", turn_timeout=args.timeout) as runtime:
            runtime.start(workspace, "You are checking a software agent integration. Read only the explicitly requested file using a shell tool. Do not modify files, use network tools, or inspect anything outside the workspace.")
            result = runtime.run("Use the shell tool to read evidence.txt in the current working directory. Return the content without trailing newline using the required JSON schema.", output_schema=schema)
    except CodexRuntimeError as exc:
        result = {"status": "failed", "kind": exc.kind, "message": str(exc)}
    events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
    tool_items = [event["payload"]["item"] for event in events
                  if event.get("method") == "item/completed"
                  and event.get("payload", {}).get("item", {}).get("type") == "commandExecution"]
    result["tool_commands"] = [item.get("command") for item in tool_items]
    result["fixture_unchanged"] = before == hashlib.sha256(fixture.read_bytes()).hexdigest()
    result["smoke_pass"] = (result.get("output") == {"content": "sdk-read-check"}
                            and bool(tool_items) and result["fixture_unchanged"])
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result.get(key) for key in ("status", "kind", "thread_id", "turn_id", "smoke_pass", "fixture_unchanged", "tool_commands")}, indent=2))
    raise SystemExit(0 if result["smoke_pass"] else 1)


if __name__ == "__main__":
    main()
