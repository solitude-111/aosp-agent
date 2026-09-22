"""RetroPatch R14 port: the 6-strategy ladder for backport retry turns.

RetroPatch used a two-stage agent (hunk-level generation, then a
VALIDATE&REVISE loop over the whole patch). The ladder generalizes that
escalation: every retry turn gets a *different* strategy prompt instead of
a homogeneous repeat. Strategy text follows the adaptation plan §7.4.
"""
from __future__ import annotations

import json
from typing import Any

STRATEGIES = ["verify_and_complete", "repair", "history_informed",
              "alternative_approach", "focused_fix", "final_attempt"]


def strategy_prompt(index: int, ctx: dict[str, Any]) -> str | None:
    """Return the strategy block for ladder position ``index`` (0-based).

    Returns None when the strategy is unavailable — currently only
    history_informed without usable donor history (the tools degrade to
    NOT_AVAILABLE, so the ladder skips that level).
    """
    if not 0 <= index < len(STRATEGIES):
        raise IndexError("ladder index out of range")
    strategy = STRATEGIES[index]
    if strategy == "verify_and_complete":
        return _verify_and_complete(ctx)
    if strategy == "repair":
        return _repair(ctx)
    if strategy == "history_informed":
        if not ctx.get("history_available"):
            return None
        return _history_informed()
    if strategy == "alternative_approach":
        return _alternative_approach()
    if strategy == "focused_fix":
        return _focused_fix(ctx)
    return _final_attempt()


def ladder_plan(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Available ladder levels for this run (T3 skipped when history absent)."""
    plan = []
    for index, strategy in enumerate(STRATEGIES):
        prompt = strategy_prompt(index, ctx)
        if prompt is not None:
            plan.append({"index": index, "strategy": strategy})
    return plan


def _verify_and_complete(ctx: dict[str, Any]) -> str:
    applied = ctx.get("applied_hunk_ids") or []
    failed = ctx.get("failed_hunks") or []
    missing = ctx.get("missing_symbols") or []
    lines = ["Strategy T1 (verify_and_complete): the controller already landed some donor "
             "hunks mechanically before this turn."]
    if applied:
        lines.append(f"- Hunks already landed in the workspace ({', '.join(applied)}): "
                     "verify their context and semantics, do NOT rewrite or re-apply them "
                     "unless they are wrong.")
    if failed:
        lines.append("- Hunks that failed mechanical application (adapt these, the diagnosis "
                     "for each is in the starting state above): "
                     + ", ".join(h.get("id", "?") for h in failed) + ".")
    if missing:
        lines.append(f"- Symbols the donor uses that are MISSING at this baseline "
                     f"({', '.join(missing)}): adapt them to the target's existing APIs "
                     "or provide an equivalent.")
    lines.append("- Add benign focused regression tests in the allowed test paths, then "
                 "finish with the HUNK-RESULT declaration.")
    return "\n".join(lines)


def _repair(ctx: dict[str, Any]) -> str:
    diagnosis = ctx.get("diagnosis_json")
    block = ("Strategy T2 (repair): the controller verification failed or your previous "
             "claims contradicted the produced diff. Structured diagnosis (not raw logs):\n")
    if diagnosis:
        rendered = json.dumps(diagnosis, ensure_ascii=False)
        block += rendered if len(rendered) < 12000 else json.dumps(
            {"summary": diagnosis.get("summary", ""), "truncated": True}, ensure_ascii=False)
    else:
        block += "(no structured diagnosis available; re-derive from the failing checks)"
    return block + ("\n" + (ctx.get("claim_feedback") or "")) .rstrip() + (
        "\nFix only what the diagnosis identifies. Do not rewrite hunks that already "
        "passed. End with the HUNK-RESULT declaration.")


def _history_informed() -> str:
    return ("Strategy T3 (history_informed): previous attempts did not resolve the "
            "conflicting hunks. BEFORE editing, call hunk-history for each unresolved "
            "hunk-id and show-commit for the relevant SHAs. Cite in your summary what "
            "the history showed (added-after-target / moved / context-only), then adapt "
            "accordingly: newly added code suggests need_not_ported, moved code points "
            "to the original location, context-only changes should be adapted in place. "
            "End with the HUNK-RESULT declaration.")


def _alternative_approach() -> str:
    return ("Strategy T4 (alternative_approach): the current adaptation direction has "
            "failed repeatedly. Consider a different equivalent implementation at the "
            "target baseline (a different existing API, or a restructured minimal "
            "semantic port). Re-derive the protective invariant from the donor commit "
            "message and diff; do not iterate on the previous shape. End with the "
            "HUNK-RESULT declaration.")


def _focused_fix(ctx: dict[str, Any]) -> str:
    stages = ctx.get("failing_stages") or []
    stage_text = ", ".join(stages) if stages else "(see the diagnosis)"
    return (f"Strategy T5 (focused_fix): only the following checks still fail: {stage_text}. "
            "Make the smallest change that addresses exactly these failures; leave every "
            "other hunk and file untouched. End with the HUNK-RESULT declaration.")


def _final_attempt() -> str:
    return ("Strategy T6 (final_attempt): last attempt. Resolve the remaining failures; "
            "for any hunk you can now prove (with target evidence) does not exist at this "
            "baseline or is already protected, declare HUNK-RESULT <id> need_not_ported "
            "with the evidence. Do not guess. End with the HUNK-RESULT declaration.")
