from __future__ import annotations

import argparse
import json
from pathlib import Path

from .case import load_cases
from .engine import AospBackportAgent


def main() -> int:
    parser = argparse.ArgumentParser(description="Data-driven AOSP CVE impact/backport agent")
    parser.add_argument("--dataset", type=Path, default=Path(__file__).parent / "dataset/cases")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    diff = sub.add_parser("diff", help="discover, assess and backport from only a diff and target checkout(s)")
    diff.add_argument("--patch", type=Path, required=True)
    diff.add_argument("--target-root", type=Path, required=True,
                      help="standalone target Git checkout or AOSP root containing Git checkouts; pins each HEAD")
    diff.add_argument("--run-root", type=Path, default=Path("runs/diff-input"))
    diff.add_argument("--inspect-only", action="store_true")
    diff.add_argument("--model", default=None,
                      help="model id; default falls back to ~/.codex/config.toml (GLM via ZAI provider)")
    diff.add_argument("--model-provider")
    diff.add_argument("--turn-timeout", type=float, default=900)
    diff.add_argument("--max-attempts", type=int, default=3)
    diff.add_argument("--verify", action="store_true")
    diff.add_argument("--validation", type=Path, help="optional independent checks JSON keyed by discovered repository key")
    run = sub.add_parser("run")
    run.add_argument("cve")
    run.add_argument("--dataset", dest="run_dataset", type=Path)
    run.add_argument("--source-root", type=Path, required=True)
    run.add_argument("--run-root", type=Path, required=True)
    run.add_argument("--donor-root", type=Path, help="directory containing <repo-path with slashes replaced by hyphens>.git")
    run.add_argument("--model", default=None,
                     help="model id; default falls back to ~/.codex/config.toml (GLM via ZAI provider)")
    run.add_argument("--model-provider", help="Codex model provider id, or AOSP_AGENT_MODEL_PROVIDER")
    run.add_argument("--no-codex", "--inspect-only", dest="no_codex", action="store_true",
                     help="prepare and inspect without starting a model; reports PREPARED")
    run.add_argument("--no-mechanical", action="store_true",
                     help="skip the pre-model mechanical hunk application (debug)")
    run.add_argument("--verify", action="store_true")
    run.add_argument("--max-attempts", type=int, default=6,
                     help="maximum turns per assessment/backport phase, including the initial turn")
    run.add_argument("--turn-timeout", type=float, default=900,
                     help="timeout in seconds for each SDK turn")
    args = parser.parse_args()
    if args.command == "diff":
        from .diff_engine import DiffBackportAgent
        agent = None
        try:
            agent = DiffBackportAgent(args.patch, args.target_root, args.run_root, model=args.model,
                model_provider=args.model_provider, turn_timeout=args.turn_timeout,
                validation=json.loads(args.validation.read_text()) if args.validation else None)
            result = agent.run(inspect_only=args.inspect_only, max_attempts=args.max_attempts, verify=args.verify)
        except Exception as exc:
            result = {"status": "FAILED", "error": {"type": type(exc).__name__, "message": str(exc)}}
        summary = {k: result[k] for k in ("task_id", "status", "impact_decision", "model", "patches", "error") if k in result}
        if agent:
            summary["record"] = str(agent.run_dir / "run.json")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return {"DISCOVERED": 0, "NOT_AFFECTED": 0, "ALREADY_FIXED": 0, "VALIDATED": 0,
                "PATCH_UNVERIFIED": 3, "INCONCLUSIVE": 4, "VALIDATION_FAILED": 5,
                "MIGRATION_INCOMPLETE": 6}.get(result["status"], 2)
    cases = load_cases(getattr(args, "run_dataset", None) or args.dataset)
    if args.command == "list":
        for case in cases.values():
            print(f"{case.cve}\t{case.project}\t{case.repository}")
        return 0
    case = cases[args.cve]
    try:
        result = AospBackportAgent(args.source_root, args.run_root, case, args.model, args.donor_root,
                                   args.model_provider, turn_timeout=args.turn_timeout).run(
            use_codex=not args.no_codex, verify=args.verify, max_attempts=args.max_attempts,
            mechanical=not args.no_mechanical)
    except Exception as exc:
        print(json.dumps({"status": "FAILED", "error": {"type": type(exc).__name__, "message": str(exc)}},
                         ensure_ascii=False, indent=2))
        return 2
    summary = {key: result[key] for key in ("cve", "status", "backend", "model", "patch_file",
                                          "patch_sha256", "final_verification", "error") if key in result}
    summary["record"] = str(args.run_root.resolve() / case.cve / "run.json")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return {"PREPARED": 0, "NOT_AFFECTED": 0, "ALREADY_FIXED": 0, "VALIDATED": 0,
            "PATCH_UNVERIFIED": 3, "INCONCLUSIVE": 4, "VALIDATION_FAILED": 5}.get(result["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
