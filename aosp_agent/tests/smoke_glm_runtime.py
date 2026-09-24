"""Explicit live GLM smoke test; manual only because it uses model quota."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from aosp_agent.glm_runtime import GLMRuntime, GLMRuntimeError


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
    workspace.mkdir()
    fixture = workspace / "evidence.txt"
    fixture.write_text("glm-read-check\n", encoding="utf-8")
    before = hashlib.sha256(fixture.read_bytes()).hexdigest()
    schema = {"type": "object", "properties": {"content": {"type": "string"}},
              "required": ["content"], "additionalProperties": False}
    try:
        with GLMRuntime(root / "events.jsonl", turn_timeout=args.timeout) as runtime:
            runtime.start(workspace, "You are checking a GLM integration. Read only evidence.txt.")
            result = runtime.run("Read evidence.txt, then return exactly one JSON object with key content. Its value must be the file content without a trailing newline.",
                                 output_schema=schema)
    except GLMRuntimeError as exc:
        result = {"status": "failed", "kind": exc.kind, "message": str(exc)}
    events = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
    result["fixture_unchanged"] = before == hashlib.sha256(fixture.read_bytes()).hexdigest()
    result["smoke_pass"] = (result.get("output") == {"content": "glm-read-check"}
                            and result["fixture_unchanged"])
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result.get(key) for key in
                      ("status", "kind", "thread_id", "turn_id", "smoke_pass", "fixture_unchanged")},
                     indent=2))
    raise SystemExit(0 if result["smoke_pass"] else 1)


if __name__ == "__main__":
    main()
