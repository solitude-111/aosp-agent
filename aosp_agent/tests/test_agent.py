import json
import subprocess
import unittest
from pathlib import Path

from aosp_agent.case import Case
from aosp_agent.engine import AospBackportAgent, _assert_patch_paths, _codex_error_kind, _extract_unified_diff
from aosp_agent.tests.engine_fixtures import (
    BASELINE, FIXED, PARTIAL, FlippingScriptedRuntime, GitFixture, ScriptedRuntime, git, write_counter,
)


class AgentTest(unittest.TestCase):
    def agent(self, fixture, runtime=None, case=None):
        return AospBackportAgent(
            fixture.source_root, fixture.run_root, case or fixture.case(),
            runtime_factory=runtime.factory if runtime else None,
        )

    def assert_failed(self, fixture, agent, **kwargs):
        with self.assertRaises((ValueError, RuntimeError)):
            agent.run(**kwargs)
        self.assertEqual(fixture.record()["status"], "FAILED")

    def test_codex_error_classification(self):
        self.assertEqual(_codex_error_kind("unexpected status 401 Unauthorized"), "AUTH_REQUIRED")
        self.assertEqual(_codex_error_kind("unexpected status 403 Forbidden"), "AUTH_REQUIRED")
        self.assertEqual(_codex_error_kind("thread failed"), "CODEX_ERROR")

    def test_direct_patch_is_limited_to_allowed_files(self):
        patch = "diff --git a/src.cc b/src.cc\n--- a/src.cc\n+++ b/src.cc\n@@ -1 +1 @@\n-a\n+b\n"
        self.assertEqual(_extract_unified_diff("```diff\n" + patch + "\n```").strip(), patch.strip())
        _assert_patch_paths(patch, {"src.cc"})
        with self.assertRaises(RuntimeError):
            _assert_patch_paths(patch.replace("src.cc", "other.cc"), {"src.cc"})

    def test_dataset_rejects_shell_validation(self):
        with GitFixture() as fixture:
            raw = {"cve": "CVE-2099-1", "project": "AOSP", "repository": "repo",
                   "source_commit": fixture.donor, "source_parent": fixture.target,
                   "target_commit": fixture.target, "files": ["counter.py"],
                   "validation": [["bash", "-c", "echo unsafe"]]}
            with self.assertRaises(ValueError):
                Case.from_dict(raw)

    def test_preparation_is_not_reported_as_patch_completion(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment())
            agent = self.agent(fixture, runtime)
            result = agent.run(use_codex=False)
            self.assertEqual(result["status"], "PREPARED")
            self.assertFalse(runtime.calls)
            self.assertEqual((agent.worktree / "counter.py").read_text(), BASELINE)
            self.assertEqual((fixture.repo / "counter.py").read_text(), BASELINE)
            self.assertEqual(git(fixture.repo, "rev-parse", "HEAD"), fixture.target)
            self.assertFalse(agent.worktree.is_relative_to(fixture.source_root))
            self.assertEqual(fixture.record()["status"], "PREPARED")

    def test_unknown_stops_before_patch_phase(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment("UNKNOWN"))
            agent = self.agent(fixture, runtime)
            self.assertEqual(agent.run()["status"], "INCONCLUSIVE")
            self.assertEqual([call["read_only"] for call in runtime.calls], [True, True])
            self.assertEqual(git(agent.worktree, "status", "--porcelain"), "")

    def test_counter_agreement_proceeds_to_migration(self):
        # 反方复核与正方结论一致 → 正常进入迁移（影响+反方+编辑 三回合）
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(verify=True)
            self.assertEqual(result["status"], "VALIDATED")
            self.assertEqual(result["counter_assessment"]["status"], "AFFECTED")
            self.assertEqual(len(runtime.calls), 3)
            self.assertIn("adversarial", runtime.calls[1]["prompt"])

    def test_counter_flip_becomes_inconclusive(self):
        # 反方翻转结论（判定方差被抓到）→ INCONCLUSIVE 交人工，不进迁移
        with GitFixture() as fixture:
            runtime = FlippingScriptedRuntime(fixture.assessment())
            agent = self.agent(fixture, runtime)
            self.assertEqual(agent.run(verify=False)["status"], "INCONCLUSIVE")
            self.assertEqual(agent.record["impact_decision"], "counter_flipped")
            self.assertEqual(len(runtime.calls), 2)  # 影响 + 反方，无编辑
            self.assertEqual(git(agent.worktree, "status", "--porcelain"), "")

    def test_not_affected_stops_before_patch_phase(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment("NOT_AFFECTED", already_fixed=True))
            agent = self.agent(fixture, runtime, fixture.case(already_fixed=True))
            self.assertEqual(agent.run()["status"], "NOT_AFFECTED")
            self.assertEqual(len(runtime.calls), 2)
            self.assertEqual(git(agent.worktree, "status", "--porcelain"), "")

    def test_affected_without_actual_changes_fails(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [None])
            # mechanical=False isolates "no changes at all": with the mechanical
            # pass on, the donor hunk lands before the model ever edits.
            self.assert_failed(fixture, self.agent(fixture, runtime), mechanical=False)
            self.assertEqual(len(runtime.calls), 3)

    def test_mechanical_landing_alone_yields_candidate(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [None])
            result = self.agent(fixture, runtime).run(verify=False)
            self.assertEqual(result["status"], "PATCH_UNVERIFIED")
            self.assertEqual(result["mechanical_migration"]["applied"], ["f001-h001"])
            self.assertEqual(result["mechanical_migration"]["starting_state"], "full")
            self.assertIn("+    return max(0, min(value, 10))", Path(result["patch_file"]).read_text())

    def test_patch_without_verification_is_explicitly_unverified(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            agent = self.agent(fixture, runtime, fixture.case(validation=True))
            result = agent.run(verify=False)
            self.assertEqual(result["status"], "PATCH_UNVERIFIED")
            self.assertEqual([call["read_only"] for call in runtime.calls], [True, True, False])
            self.assertIsNotNone(runtime.calls[0]["output_schema"])
            self.assertEqual((fixture.repo / "counter.py").read_text(), BASELINE)
            self.assertIn("+    return max(0, min(value, 10))", Path(result["patch_file"]).read_text())

    def test_no_validators_cannot_produce_validated_status(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            result = self.agent(fixture, runtime).run(verify=True)
            self.assertEqual(result["status"], "PATCH_UNVERIFIED")
            self.assertEqual(result["final_verification"]["status"], "NOT_CONFIGURED")

    def test_passing_configured_contract_is_validated(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(verify=True)
            self.assertEqual(result["status"], "VALIDATED")
            self.assertEqual(result["final_verification"]["status"], "PASS")
            self.assertIn("contract verified", result["final_verification"]["commands"][0]["stdout"])
            self.assertEqual(len(runtime.calls), 3)

    def test_validation_failure_guides_revision_and_rechecks_it(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(PARTIAL), write_counter(FIXED)])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATED")
            self.assertEqual(len(runtime.calls), 4)
            self.assertIn("upper bound missing", runtime.calls[3]["prompt"])
            self.assertEqual(result["final_verification"]["status"], "PASS")
            self.assertIn("+    return max(0, min(value, 10))", Path(result["patch_file"]).read_text())

    def test_exhausted_validation_failure_never_reports_success(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(PARTIAL), None])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            self.assertEqual(result["final_verification"]["status"], "FAIL")
            self.assertEqual(len(runtime.calls), 4)
            self.assertTrue(Path(result["patch_file"]).is_file())

    def test_forged_target_evidence_is_rejected_before_editing(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment()
            assessment["evidence"][0]["excerpt"] = "def imaginary_function():\n    return 42"
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_wrong_source_revision_evidence_is_rejected(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment()
            assessment["evidence"][1]["revision"] = "source_parent"
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_source_evidence_outside_donor_diff_is_rejected(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment()
            assessment["evidence"][1]["path"] = "donor-only.py"
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_determinate_assessment_requires_donor_evidence(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment()
            assessment["evidence"] = assessment["evidence"][:1]
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_invalid_json_assessment_is_not_treated_as_affected(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime("The issue appears affected. Proceed with the patch.")
            self.assert_failed(fixture, self.agent(fixture, runtime))
            self.assertEqual(len(runtime.calls), 1)

    def test_read_only_phase_cannot_silently_change_source(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment("UNKNOWN"), impact_edit=write_counter(FIXED))
            self.assert_failed(fixture, self.agent(fixture, runtime))
            self.assertEqual((fixture.repo / "counter.py").read_text(), BASELINE)

    def test_unapproved_file_changes_fail_audit(self):
        with GitFixture() as fixture:
            def rogue(worktree):
                write_counter(FIXED)(worktree)
                (worktree / "rogue.txt").write_text("unapproved change\n")
            runtime = ScriptedRuntime(fixture.assessment(), [rogue])
            self.assert_failed(fixture, self.agent(fixture, runtime))
            self.assertFalse((fixture.repo / "rogue.txt").exists())

    def test_changing_worktree_head_fails_audit(self):
        with GitFixture() as fixture:
            def commit_change(worktree):
                write_counter(FIXED)(worktree)
                git(worktree, "add", "counter.py")
                git(worktree, "commit", "-q", "-m", "unexpected agent commit")
            runtime = ScriptedRuntime(fixture.assessment(), [commit_change])
            self.assert_failed(fixture, self.agent(fixture, runtime))
            self.assertEqual(git(fixture.repo, "rev-parse", "HEAD"), fixture.target)

    def test_allowed_path_cannot_be_replaced_by_external_symlink(self):
        with GitFixture() as fixture:
            external = fixture.root / "external.py"
            external.write_text(FIXED)

            def replace_with_symlink(worktree):
                (worktree / "counter.py").unlink()
                (worktree / "counter.py").symlink_to(external)

            runtime = ScriptedRuntime(fixture.assessment(), [replace_with_symlink])
            self.assert_failed(fixture, self.agent(fixture, runtime))
            self.assertEqual(external.read_text(), FIXED)

    def test_staging_changes_does_not_hide_them_from_patch_export(self):
        with GitFixture() as fixture:
            def stage_patch(worktree):
                write_counter(FIXED)(worktree)
                git(worktree, "add", "counter.py")

            runtime = ScriptedRuntime(fixture.assessment(), [stage_patch])
            result = self.agent(fixture, runtime).run()
            self.assertEqual(result["status"], "PATCH_UNVERIFIED")
            self.assertIn("+    return max(0, min(value, 10))", Path(result["patch_file"]).read_text())

    def test_new_untracked_test_is_in_exported_applicable_patch(self):
        with GitFixture() as fixture:
            new_test = "from counter import normalize_count\nassert normalize_count(4) == 4\n"
            def add_patch_and_test(worktree):
                write_counter(FIXED)(worktree)
                (worktree / "test_counter.py").write_text(new_test)
            runtime = ScriptedRuntime(fixture.assessment(), [add_patch_and_test])
            result = self.agent(fixture, runtime).run()
            patch = Path(result["patch_file"]).read_text()
            self.assertIn("diff --git a/test_counter.py b/test_counter.py", patch)
            clean = fixture.root / "reapply"
            git(fixture.repo, "worktree", "add", "--detach", str(clean), fixture.target)
            subprocess.run(["git", "apply", "--check", "-"], cwd=clean, input=patch,
                           text=True, check=True, capture_output=True)
            subprocess.run(["git", "apply", "-"], cwd=clean, input=patch,
                           text=True, check=True, capture_output=True)
            self.assertEqual((clean / "test_counter.py").read_text(), new_test)
            self.assertEqual((clean / "counter.py").read_text(), FIXED)

    def test_export_records_independent_clean_replay(self):
        with GitFixture() as fixture:
            def edit_with_test(worktree):
                write_counter(FIXED)(worktree)
                (worktree / "test_counter.py").write_text("assert normalize_count(4) == 4\n")
            runtime = ScriptedRuntime(fixture.assessment(), [edit_with_test])
            result = self.agent(fixture, runtime).run()
            self.assertEqual(result["patch_replay"], "pass")
            self.assertEqual(result["patch_replay_evidence"]["allowlist_ok"], True)
            self.assertIn("test_counter.py", result["patch_replay_evidence"]["untracked_files"])

    def test_declared_cross_repository_case_is_explicitly_unsupported(self):
        with GitFixture() as fixture:
            case = fixture.case()
            case = Case(**{**case.__dict__, "repositories": ({"path": "repo", "files": []},
                                                               {"path": "other", "files": []})})
            with self.assertRaises(ValueError):
                self.agent(fixture, case=case).run(use_codex=False)
            self.assertEqual(fixture.record()["error"]["kind"], "UNSUPPORTED_MULTI_REPOSITORY")

    def _conflict_fixture(self):
        """Donor hunk whose context matches the donor parent but not the target."""
        import tempfile
        from aosp_agent.tests.engine_fixtures import git as fixture_git

        class _Conflict:
            def __enter__(self):
                self._directory = tempfile.TemporaryDirectory()
                self.root = Path(self._directory.name).resolve()
                self.source_root = self.root / "source"
                self.repo = self.source_root / "repo"
                self.repo.mkdir(parents=True)
                fixture_git(self.repo, "init", "-q")
                (self.repo / "widget.py").write_text("alpha\nctx\nomega\n")
                fixture_git(self.repo, "add", ".")
                fixture_git(self.repo, "commit", "-q", "-m", "target baseline")
                self.target = fixture_git(self.repo, "rev-parse", "HEAD")
                (self.repo / "widget.py").write_text("alpha\nctx\nbeta\nomega\n")
                fixture_git(self.repo, "add", "widget.py")
                fixture_git(self.repo, "commit", "-q", "-m", "donor parent adds beta")
                self.parent = fixture_git(self.repo, "rev-parse", "HEAD")
                (self.repo / "widget.py").write_text("alpha\nchanged\nbeta\nomega\n")
                fixture_git(self.repo, "add", "widget.py")
                fixture_git(self.repo, "commit", "-q", "-m", "donor fix changes ctx")
                self.donor = fixture_git(self.repo, "rev-parse", "HEAD")
                fixture_git(self.repo, "checkout", "--detach", "-q", self.target)
                self.run_root = self.root / "runs"
                return self

            def __exit__(self, *_args):
                self._directory.cleanup()

            def case(self):
                return Case.from_dict({
                    "cve": "CVE-2099-2001", "project": "AOSP conflict fixture", "repository": "repo",
                    "source_commit": self.donor, "source_parent": self.parent,
                    "target_commit": self.target, "files": ["widget.py"], "validation": [],
                })

            def assessment(self):
                return {"status": "AFFECTED", "evidence": [
                    {"revision": "target", "path": "widget.py", "line_start": 1, "line_end": 3,
                     "excerpt": "alpha\nctx\nomega", "claim": "Target still has the old context."},
                    {"revision": "source_fix", "path": "widget.py", "line_start": 1, "line_end": 4,
                     "excerpt": "alpha\nchanged\nbeta\nomega", "claim": "Donor fix changes the line."}],
                    "reasoning": "The protective change applies to the target's counterpart.",
                    "limitations": ["fixture"]}
        return _Conflict()

    def test_mechanical_failure_feeds_diagnosis_into_first_turn(self):
        with self._conflict_fixture() as fixture:
            def adapt(worktree):
                (worktree / "widget.py").write_text("alpha\nchanged\nomega\n")
            runtime = ScriptedRuntime(fixture.assessment(), [adapt])
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case(),
                                      runtime_factory=runtime.factory)
            result = agent.run(verify=False)
            self.assertEqual(result["status"], "PATCH_UNVERIFIED")
            migration = result["mechanical_migration"]
            self.assertEqual(migration["failed"], ["f001-h001"])
            self.assertEqual(migration["starting_state"], "none")
            self.assertEqual(migration["hunks"][0]["diagnosis"]["kind"], "context_mismatch")
            first_turn = runtime.calls[2]["prompt"]
            self.assertIn("Failed to apply mechanically", first_turn)
            self.assertIn("f001-h001", first_turn)
            self.assertIn("context_mismatch", first_turn)
            self.assertEqual(result["attempts"][0]["strategy"], "verify_and_complete")
            self.assertIn("patch_sha256", result["attempts"][0])

    def test_missing_hunk_result_declaration_fails_closed(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [None, None],
                                      patch_response="I edited the files; trust me.")
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            self.assertEqual([call["read_only"] for call in runtime.calls], [True, True, False, False])
            self.assertIn("no HUNK-RESULT declaration", runtime.calls[3]["prompt"])
            self.assertIn("Strategy T2", runtime.calls[3]["prompt"])
            self.assertEqual(result["hunk_results"], [])
            self.assertTrue(result["attempts"])

    def test_contradicted_need_not_ported_claim_fails_the_turn(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(
                fixture.assessment(), [None, None],
                patch_response="HUNK-RESULT f001-h001 need_not_ported already protected upstream")
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            self.assertIn("contradict", runtime.calls[3]["prompt"])
            self.assertEqual(result["hunk_results"][0]["status"], "need_not_ported")

    def test_cross_file_mapping_claim_is_not_path_audited(self):
        # CVE-2025-32348 lesson: a donor path absent at the target baseline can
        # only be semantically ported into another allowlisted file; an
        # "implemented Adapted in <other file>" claim must not be rejected by
        # the path-literal audit (the case validation checks carry semantics).
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            agent._current_hunks = [{"id": "f001-h008", "path": "wm/AbsentController.java"}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h008 implemented Adapted in ActivityStarter.java",
                changed_files=["ActivityStarter.java"])
            self.assertTrue(claims["ok"])
            self.assertEqual(claims["claims"][0]["status"], "implemented")
            # The strict rule still holds for paths the diff could touch.
            agent._current_hunks = [{"id": "f001-h001", "path": "counter.py"}]
            strict = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 implemented trust me", changed_files=[])
            self.assertFalse(strict["ok"])

    def test_impact_turn_sees_clean_baseline_before_mechanical_landing(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            agent = self.agent(fixture, runtime, fixture.case(validation=True))
            result = agent.run(verify=True)
            self.assertEqual(result["status"], "VALIDATED")
            # The impact turn ran while the worktree was still at the clean
            # baseline (r2 revision 1) and mechanical landing happened after.
            self.assertEqual((agent.worktree / "counter.py").read_text(), FIXED)
            self.assertEqual(agent.record["mechanical_migration"]["applied"], ["f001-h001"])

    def _staged_case(self, fixture):
        import sys
        from aosp_agent.case import Case
        return Case.from_dict({
            "cve": "CVE-2099-2000", "project": "AOSP orchestration fixture", "repository": "repo",
            "source_commit": fixture.donor, "source_parent": fixture.target,
            "target_commit": fixture.target, "files": ["counter.py", "test_counter.py"],
            "validation": {"checks": [
                {"stage": "lower_bound", "argv": [sys.executable, "-B", "check_lower.py"]},
                {"stage": "upper_bound", "argv": [sys.executable, "-B", "check_upper.py"]}]}
        })

    def test_passed_stages_are_skipped_while_patch_is_unchanged(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(PARTIAL), None])
            result = self.agent(fixture, runtime, self._staged_case(fixture)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            commands = result["final_verification"]["commands"]
            self.assertTrue(commands[0]["skipped_passed"])
            self.assertEqual(commands[0]["returncode"], 0)
            self.assertIsNotNone(commands[1]["stdout_log"])
            self.assertEqual(result["verification_memory"]["passed_stages"], ["lower_bound"])
            self.assertEqual(result["final_verification"]["skipped_stages"], ["lower_bound"])

    def test_patch_change_resets_verification_memory(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(PARTIAL), write_counter(FIXED)])
            result = self.agent(fixture, runtime, self._staged_case(fixture)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATED")
            commands = result["final_verification"]["commands"]
            self.assertNotIn("skipped_passed", commands[0])
            self.assertEqual(result["final_verification"]["skipped_stages"], [])

    def test_workflow_prompt_contents(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            self.agent(fixture, runtime).run(verify=False)
            impact, backport = runtime.calls[0]["prompt"], runtime.calls[2]["prompt"]
            self.assertIn("bound ordinary count values", impact)  # donor commit message (R1)
            self.assertIn("Existence first", impact)
            self.assertIn("locate-symbol", impact)
            self.assertIn("Starting state produced by the controller", backport)
            self.assertIn("HUNK-RESULT", backport)
            self.assertIn("Strategy T1", backport)
            self.assertIn("verify_and_complete", backport)

    def test_tool_usage_markers_are_swept_from_sdk_events(self):
        import io
        import contextlib
        from aosp_agent.agent_tools import main as tools_main
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            agent = self.agent(fixture, runtime)
            agent.run(verify=False)  # produces run.json / inspection.json
            run_dir = fixture.run_root / "CVE-2099-2000"
            marker_text = None
            # Simulate a sandboxed tool call: capture the stdout marker only.
            captured = io.StringIO()
            target = fixture.record()["target_commit"]
            with contextlib.redirect_stdout(captured):
                tools_main(["--run-dir", str(run_dir), "view-code", "--repo", "target",
                            "--ref", target, "--path", "counter.py", "--start", "1", "--end", "1"])
            for line in captured.getvalue().splitlines():
                if line.startswith("AOSP-TOOL-USAGE "):
                    marker_text = line
                    break
            self.assertIsNotNone(marker_text)
            usage = run_dir / "tool-usage.jsonl"
            usage.unlink()  # emulate the sandbox having denied the direct append
            event = {"event": "sdk_notification", "method": "item/completed",
                     "payload": {"item": {"type": "commandExecution",
                                          "command": "view-code ...",
                                          "aggregatedOutput": captured.getvalue()}}}
            (run_dir / "sdk-events.jsonl").write_text(json.dumps(event) + "\n")
            agent._events_swept = 0
            agent._sweep_tool_usage()
            swept = [json.loads(line) for line in usage.read_text().splitlines()]
            self.assertEqual(len(swept), 1)
            self.assertEqual(swept[0]["cmd"], "view-code")
            self.assertIn("uid", swept[0])
            # A second sweep must not duplicate the entry.
            agent._sweep_tool_usage()
            self.assertEqual(len(usage.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
