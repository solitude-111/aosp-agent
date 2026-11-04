import hashlib
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from aosp_agent.case import Case
from aosp_agent.engine import (AospBackportAgent, AssessmentError, _assert_patch_paths,
                               _codex_error_kind, _extract_unified_diff)
from aosp_agent.tests.engine_fixtures import (
    BASELINE, FIXED, PARTIAL, GitFixture, ScriptedRuntime, git, write_counter,
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

    def test_impact_evidence_may_use_directly_referenced_tracked_file(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            agent.prepare()
            inspection = agent.inspect()
            agent._current_hunks = inspection["hunks"]
            assessment = fixture.assessment()
            assessment["evidence"][0].update({
                "path": "verify_contract.py", "line_start": 2, "line_end": 2,
                "excerpt": "assert normalize_count(4) == 4, 'ordinary count changed'",
            })
            self.assertEqual(agent._ground_assessment(assessment)["status"], "AFFECTED")

    def test_dataset_rejects_shell_validation(self):
        with GitFixture() as fixture:
            raw = {"cve": "CVE-2099-1", "project": "AOSP", "repository": "repo",
                   "source_commit": fixture.donor, "source_parent": fixture.target,
                   "target_commit": fixture.target, "files": ["counter.py"],
                   "validation": [["bash", "-c", "echo unsafe"]]}
            with self.assertRaises(ValueError):
                Case.from_dict(raw)

    def test_cli_module_is_importable(self):
        completed = subprocess.run(
            [sys.executable, "-m", "aosp_agent", "run", "--help"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertIn("--impact-only", completed.stdout)

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
            self.assertEqual([call["read_only"] for call in runtime.calls], [True])
            self.assertEqual(git(agent.worktree, "status", "--porcelain"), "")

    def test_impact_only_stops_before_patch_phase_for_affected_case(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(FIXED)])
            agent = self.agent(fixture, runtime)
            result = agent.run(impact_only=True)
            self.assertEqual(result["status"], "AFFECTED")
            self.assertEqual(result["impact_decision"], "affected")
            self.assertEqual([call["read_only"] for call in runtime.calls], [True])
            self.assertEqual(git(agent.worktree, "status", "--porcelain"), "")

    def test_interrupted_worktree_registration_is_pruned_before_reuse(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            agent.run_dir.mkdir(parents=True)
            git(fixture.repo, "worktree", "add", "--detach", str(agent.worktree),
                fixture.target)
            shutil.rmtree(agent.run_dir)
            agent.prepare()
            self.assertTrue(agent.worktree.is_dir())
            self.assertEqual(git(agent.worktree, "rev-parse", "HEAD"), fixture.target)



    def test_not_affected_stops_before_patch_phase(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment("NOT_AFFECTED", already_fixed=True))
            agent = self.agent(fixture, runtime, fixture.case(already_fixed=True))
            self.assertEqual(agent.run()["status"], "NOT_AFFECTED")
            self.assertEqual(len(runtime.calls), 1)
            self.assertEqual(git(agent.worktree, "status", "--porcelain"), "")

    def test_affected_without_actual_changes_fails(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [None])
            # mechanical=False isolates "no changes at all": with the mechanical
            # pass on, the donor hunk lands before the model ever edits.
            result = self.agent(fixture, runtime).run(mechanical=False, max_attempts=1)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            self.assertEqual(result["patch_sha256"],
                             hashlib.sha256(b"").hexdigest())
            self.assertIn("empty_patch", [event["event"] for event in result["events"]])
            self.assertEqual(len(runtime.calls), 2)

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
            self.assertEqual([call["read_only"] for call in runtime.calls], [True, False])
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
            self.assertEqual(result["post_fix_impact"]["overall_risk"], "low")

    def test_validation_failure_guides_revision_and_rechecks_it(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(PARTIAL), write_counter(FIXED)])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATED")
            self.assertEqual(len(runtime.calls), 4)
            self.assertIn("upper bound missing", runtime.calls[2]["prompt"])
            self.assertEqual(result["final_verification"]["status"], "PASS")
            self.assertIn("+    return max(0, min(value, 10))", Path(result["patch_file"]).read_text())

    def test_empty_patch_consumes_a_retry_but_next_strategy_can_succeed(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [None, write_counter(FIXED)])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2, mechanical=False)
            self.assertEqual(result["status"], "VALIDATED")
            self.assertEqual(len(runtime.calls), 4)
            self.assertIn("The AFFECTED assessment produced an empty patch",
                          runtime.calls[2]["prompt"])
            self.assertIn("empty_patch", [event["event"] for event in result["events"]])

    def test_exhausted_validation_failure_never_reports_success(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(fixture.assessment(), [write_counter(PARTIAL), None])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            self.assertEqual(result["final_verification"]["status"], "FAIL")
            self.assertEqual(len(runtime.calls), 3)
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
            assessment["evidence"][2]["revision"] = "source_parent"
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

    def test_affected_assessment_requires_pattern_proof_steps(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment()
            assessment["proof_steps"] = [step for step in assessment["proof_steps"]
                                         if step["id"] != "target_fault"]
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_equivalent_representation_requires_comparison_proof(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment()
            assessment["scope_contract"]["representation_change"] = "equivalent_representation"
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_unknown_assessment_requires_unresolved_material_question(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment("UNKNOWN")
            for step in assessment["proof_steps"]:
                step["resolved"] = True
            runtime = ScriptedRuntime(assessment)
            self.assert_failed(fixture, self.agent(fixture, runtime), max_attempts=3)
            self.assertEqual(len(runtime.calls), 3)

    def test_not_affected_assessment_requires_clearing_proof(self):
        with GitFixture() as fixture:
            assessment = fixture.assessment("NOT_AFFECTED")
            assessment["proof_steps"] = [step for step in assessment["proof_steps"]
                                         if step["id"] != "equivalent_protection"]
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
        # new16-par2 lesson: a wrong-file edit exhausts the retry ladder with
        # per-attempt feedback instead of terminating the run on first sight.
        with GitFixture() as fixture:
            def rogue(worktree):
                write_counter(FIXED)(worktree)
                (worktree / "rogue.txt").write_text("unapproved change\n")
            runtime = ScriptedRuntime(fixture.assessment(), [rogue, rogue])
            self.assert_failed(fixture, self.agent(fixture, runtime),
                               verify=True, max_attempts=2)
            record = fixture.record()
            self.assertEqual(record["status"], "FAILED")
            events = [e.get("event") for e in record["events"] if isinstance(e, dict)]
            self.assertIn("patch_export_rejected", events)
            self.assertEqual(len(record.get("attempts", [])), 2)
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
                return {"status": "AFFECTED",
                    "scope_contract": {
                        "vulnerability_pattern": "generic_data_flow",
                        "representation_change": "same_representation",
                        "donor_security_invariant": "The widget consumes a protected value.",
                        "donor_fault_scope": "The donor parent consumes the unprotected context.",
                        "target_counterpart_scope": "The target consumes the corresponding context.",
                        "adjacent_behavior_excluded": "Other widget callers are outside this fixture.",
                    },
                    "proof_steps": [
                        {"id": "donor_fault", "question": "Does the donor parent have the fault?",
                         "resolution": "The donor parent consumes the old context.",
                         "resolved": True, "evidence": [2]},
                        {"id": "target_fault", "question": "Does the target have the fault?",
                         "resolution": "The target consumes the same old context.",
                         "resolved": True, "evidence": [1]},
                        {"id": "downstream_harm", "question": "Can the faulty value escape?",
                         "resolution": "The widget path consumes the unprotected value.",
                         "resolved": True, "evidence": [1]},
                    ],
                    "root_cause": {"category": "logic_error",
                                    "description": "Old context lacks the protective change.",
                                    "attack_vector": "Missing guard on the widget path."},
                    "evidence": [
                    {"revision": "target", "path": "widget.py", "line_start": 1, "line_end": 3,
                     "excerpt": "alpha\nctx\nomega", "claim": "Target still has the old context."},
                    {"revision": "source_parent", "path": "widget.py", "line_start": 1, "line_end": 4,
                     "excerpt": "alpha\nctx\nbeta\nomega", "claim": "Donor parent has the old context."},
                    {"revision": "source_fix", "path": "widget.py", "line_start": 1, "line_end": 4,
                     "excerpt": "alpha\nchanged\nbeta\nomega", "claim": "Donor fix changes the line."}],
                    "causal_chain": {
                        "donor_fault_evidence": [2],
                        "donor_fix_evidence": [3],
                        "target_fault_evidence": [1],
                        "target_harm_evidence": [1],
                        "target_fault_state": "The target consumes the old context.",
                        "donor_to_target_mapping": "Both paths consume the same contextual value.",
                        "external_behavior_assumptions": [],
                        "platform_semantics": [],
                    },
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
            first_turn = runtime.calls[1]["prompt"]
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
            self.assertEqual([call["read_only"] for call in runtime.calls], [True, False, False])
            self.assertIn("no HUNK-RESULT declaration", runtime.calls[2]["prompt"])
            self.assertIn("Strategy T2", runtime.calls[2]["prompt"])
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
            self.assertIn("contradict", runtime.calls[2]["prompt"])
            self.assertEqual(result["hunk_results"][0]["status"], "need_not_ported")

    def test_wrong_file_edit_becomes_ladder_feedback_not_fatal(self):
        # new16-par2/CVE-0000-283006437 lesson: editing outside the allowlist
        # must reject the candidate and retry with the audit contradiction,
        # not terminate the run.
        with GitFixture() as fixture:
            def stray_edit(worktree):
                (worktree / "widget.py").write_text("bad\n")
            def corrected(worktree):
                (worktree / "widget.py").unlink(missing_ok=True)
                (worktree / "counter.py").write_text(FIXED)
            runtime = ScriptedRuntime(fixture.assessment(), [stray_edit, corrected])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATED")
            events = [e.get("event") for e in result["events"] if isinstance(e, dict)]
            self.assertIn("patch_export_rejected", events)
            self.assertEqual(len(result["attempts"]), 2)

    def test_ledger_blocked_candidate_does_not_reuse_previous_verification(self):
        with GitFixture() as fixture:
            runtime = ScriptedRuntime(
                fixture.assessment(),
                [write_counter(PARTIAL), write_counter(FIXED)],
                patch_responses=[None, "Changed the workspace without a ledger."])
            result = self.agent(fixture, runtime, fixture.case(validation=True)).run(
                verify=True, max_attempts=2)
            self.assertEqual(result["status"], "VALIDATION_FAILED")
            first_verification = result["attempt_verifications"]["1"]
            final_verification = result["final_verification"]
            self.assertEqual(first_verification["status"], "FAIL")
            self.assertEqual(final_verification["status"], "NOT_RUN")
            self.assertEqual(final_verification["blocked_by"], "HUNK_LEDGER")
            self.assertEqual(final_verification["patch_sha256"], result["patch_sha256"])
            self.assertNotEqual(final_verification["patch_sha256"],
                                first_verification["patch_sha256"])

    def test_hunk_result_declaration_accepts_optional_colon(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            agent._current_hunks = [{"id": "f001-h001", "path": "counter.py"}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 implemented: the counter guard was adapted.",
                changed_files=["counter.py"],
                candidate_patch=(
                    "diff --git a/counter.py b/counter.py\n"
                    "--- a/counter.py\n"
                    "+++ b/counter.py\n"
                    "@@ -1,1 +1,1 @@\n"
                    "-return value\n"
                    "+return max(0, min(value, 10))\n"))
            self.assertTrue(claims["ok"])
            self.assertEqual(claims["claims"][0]["status"], "implemented")

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

    def test_versioned_donor_path_maps_to_normalized_target_path(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files",
                ("dist/generated.c", "dist/orig/generated.c"))
            self.assertEqual(
                agent._donor_targets("dist/library-3440300/generated.c"),
                {"dist/generated.c"})
            self.assertEqual(
                agent._donor_targets("dist/library-3440300/orig/generated.c"),
                {"dist/orig/generated.c"})

    def test_ambiguous_versioned_path_mapping_fails_closed(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files", ("v1/widget.c", "v2/widget.c"))
            self.assertEqual(agent._donor_targets("v1/v2/widget.c"), set())

    def test_no_target_counterpart_rejected_when_controller_maps_path(self):
        # dpsk_8/CVE-2025-48595 lesson: the donor path lives under a version
        # directory the controller normalizes away, so the target file does
        # exist; a no_target_counterpart exclusion citing controller path
        # absence must be rejected regardless of any tool UID it also cites.
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files", ("dist/generated.c", "dist/orig/generated.c"))
            agent._current_hunks = [{
                "id": "f005-h007",
                "path": "dist/library-3440300/orig/generated.c",
                "patch": "@@ -1,1 +1,1 @@\n-    flags &= ~VALID_KEY;\n"
                         "+    flags &= ~(VALID_KEY|VALID_OVERFLOW);\n",
            }]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f005-h007 need_not_ported "
                "evidence=no_target_counterpart tools=27342022df19 "
                "controller=missing_target_path donor file absent at target",
                changed_files=[])
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("f005-h007" in item and "no_target_counterpart is false" in item
                    and "dist/orig/generated.c" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])

    def test_no_target_counterpart_accepted_when_donor_path_is_unmappable(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            agent._current_hunks = [{
                "id": "f001-h001",
                "path": "absent/dir/widget.c",
                "patch": "@@ -1,1 +1,1 @@\n-old\n+new\n",
                "application_check": {
                    "stderr": "error: absent/dir/widget.c: does not exist in index"},
            }]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=no_target_counterpart controller=missing_target_path",
                changed_files=[])
            self.assertTrue(claims["ok"])
            self.assertIn("controller=missing_target_path",
                          claims["claims"][0]["reason"])

    GUARD_SIBLING = (
        "static int overwriteCell(BtCursor *pCur){\n"
        "  int loc = 0;\n"
        "  if( loc==0 ){\n"
        "    clearCell(pCur);\n"
        "    invalidateOverflowCache(pCur);\n"
        "    dropCell();\n"
        "  }else if( loc<0 ){\n"
        "    pCur->ix++;\n"
        "    pCur->curFlags &= ~BTCF_ValidNKey;\n"
        "  }else{\n"
        "    pCur->ix = 0;\n"
        "  }\n"
        "  insertCell();\n"
        "  return 0;\n"
        "}\n"
        "static void deletePath(BtCursor *pCur){\n"
        "  pCur->curFlags &= ~(BTCF_ValidNKey|BTCF_ValidOvfl);\n"
        "}\n")
    GUARD_COVERING = GUARD_SIBLING.replace(
        "  int loc = 0;\n",
        "  invalidateOverflowCache(pCur);\n  int loc = 0;\n")
    GUARD_SAME_FUNCTION_FIX = GUARD_SIBLING.replace(
        "    pCur->ix = 0;\n",
        "    pCur->ix = 0;\n"
        "    pCur->curFlags &= ~(BTCF_ValidNKey|BTCF_ValidOvfl);\n")
    GUARD_HUNK_PATCH = (
        "@@ -6,7 +6,7 @@\n"
        "   }else if( loc<0 ){\n"
        "-    pCur->curFlags &= ~BTCF_ValidNKey;\n"
        "+    pCur->curFlags &= ~(BTCF_ValidNKey|BTCF_ValidOvfl);\n")

    def _guard_case(self, fixture, baseline, old=None, new=None):
        old = old or "    pCur->curFlags &= ~BTCF_ValidNKey;"
        new = new or "    pCur->curFlags &= ~(BTCF_ValidNKey|BTCF_ValidOvfl);"
        fixed = baseline.replace(old, new)
        (fixture.repo / "guard.c").write_text(baseline)
        git(fixture.repo, "add", "guard.c")
        git(fixture.repo, "commit", "-q", "-m", "guard baseline")
        target = git(fixture.repo, "rev-parse", "HEAD").strip()
        (fixture.repo / "guard.c").write_text(fixed)
        git(fixture.repo, "add", "guard.c")
        git(fixture.repo, "commit", "-q", "-m", "donor guard fix")
        donor = git(fixture.repo, "rev-parse", "HEAD").strip()
        return Case.from_dict({
            "cve": "CVE-2099-3000", "project": "AOSP orchestration fixture",
            "repository": "repo", "source_commit": donor,
            "source_parent": target, "target_commit": target,
            "files": ["guard.c"], "validation": {"checks": []}})

    def _guard_agent(self, fixture, baseline):
        agent = self.agent(fixture, case=self._guard_case(fixture, baseline))
        agent.prepare()
        (agent.run_dir / "tool-usage.jsonl").write_text(json.dumps({
            "uid": "f3e8e566198a", "cmd": "view-code",
            "args": {"cmd": "view-code", "repo": "target", "path": "guard.c"},
            "returncode": 0, "bytes_out": 120}) + "\n")
        agent._current_hunks = [{
            "id": "f001-h001", "path": "guard.c",
            "patch": self.GUARD_HUNK_PATCH}]
        return agent

    def test_semantic_equivalence_rejected_when_mechanism_in_sibling_branch(self):
        # dpsk_8 rerun/CVE-2025-48595 lesson: the claimed equivalent mechanism
        # exists only inside a branch that can never execute on the anchor's
        # path, so the exclusion must be falsified even though a relevant
        # view-code UID backs the claim.
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=semantic_equivalence tools=f3e8e566198a "
                "target overwriteCell uses invalidateOverflowCache and a "
                "distinct cursor-state lifecycle",
                changed_files=[])
            self.assertFalse(claims["ok"])
            joined = "\n".join(claims["contradictions"])
            self.assertIn("semantic_equivalence is false", joined)
            self.assertIn("invalidateOverflowCache", joined)
            self.assertIn("cannot execute on the anchor's path", joined)
            self.assertTrue(claims["claims"][0].get("falsified_exclusion"))

    def test_semantic_equivalence_accepted_when_mechanism_covers_anchor(self):
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_COVERING)
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=semantic_equivalence tools=f3e8e566198a "
                "target overwriteCell uses invalidateOverflowCache on every path",
                changed_files=[])
            self.assertTrue(claims["ok"], claims["contradictions"])

    def test_semantic_equivalence_left_intact_when_anchor_absent(self):
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            agent._current_hunks = [{
                "id": "f001-h002", "path": "guard.c",
                "patch": "@@ -20,1 +20,1 @@\n"
                         "-    xferOptimization(db, p);\n"
                         "+    xferOptimization(db, p, 1);\n"}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h002 need_not_ported "
                "evidence=semantic_equivalence tools=f3e8e566198a "
                "target has no xferOptimization call site",
                changed_files=[])
            self.assertTrue(claims["ok"], claims["contradictions"])

    def test_already_present_rejected_when_prechange_line_remains(self):
        # fixabc-three/48595 lesson: the donor's added line exists in the
        # target only inside an unrelated function (deletePath); the anchor
        # site itself is unchanged, so already_present must be falsified at
        # the site, not accepted because the line exists elsewhere.
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=already_present tools=f3e8e566198a "
                "target already clears the overflow flag",
                changed_files=[])
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("already_present is false" in item
                    and "outside that function" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])

    def test_already_present_accepted_when_addition_shares_the_anchor_function(self):
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SAME_FUNCTION_FIX)
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=already_present tools=f3e8e566198a "
                "target overwriteCell already clears both flags",
                changed_files=[])
            self.assertTrue(claims["ok"], claims["contradictions"])

    def test_already_present_accepts_pure_reformat_hunk(self):
        # new16-par2/CVE-0000-340480881 lesson: a donor hunk that only
        # rewraps lines (no novel tokens) has nothing site-specific to
        # falsify; already_present must not be rejected for it.
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            agent._current_hunks = [{
                "id": "f001-h006", "path": "guard.c",
                "patch": ("@@ -100,3 +100,2 @@\n"
                          "                 app,\n"
                          "                 packageName\n"
                          "-            )\n"
                          "-                ?: return\n"
                          "+            ) ?: return\n")}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h006 need_not_ported "
                "evidence=already_present tools=f3e8e566198a "
                "target keeps the original line wrapping",
                changed_files=[])
            self.assertTrue(claims["ok"], claims["contradictions"])

    def test_semantic_equivalence_rejected_when_prose_names_no_mechanism(self):
        # Identifier-free prose must not bypass the falsifier: when the
        # anchor line exists in the target, an unnamed mechanism cannot be
        # verified, so the claim fails closed instead of passing on a
        # view-code UID alone.
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=semantic_equivalence tools=f3e8e566198a "
                "the flag is already cleared on row move here",
                changed_files=[])
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("names no equivalent target mechanism" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])

    def test_semantic_equivalence_falsified_with_comment_bearing_anchor(self):
        # A comment on the donor's removed line must not hide the anchor
        # from the falsifier: comments are stripped on both sides.
        with GitFixture() as fixture:
            baseline = self.GUARD_SIBLING.replace(
                "    pCur->curFlags &= ~BTCF_ValidNKey;",
                "    pCur->curFlags &= ~BTCF_ValidNKey; /* keep */")
            agent = self._guard_agent(fixture, baseline)
            agent._current_hunks = [{
                "id": "f001-h001", "path": "guard.c",
                "patch": ("@@ -6,7 +6,7 @@\n"
                          "   }else if( loc<0 ){\n"
                          "-    pCur->curFlags &= ~BTCF_ValidNKey; /* keep */\n"
                          "+    pCur->curFlags &= ~(BTCF_ValidNKey|BTCF_ValidOvfl);"
                          " /* keep */\n")}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 need_not_ported "
                "evidence=semantic_equivalence tools=f3e8e566198a "
                "target overwriteCell uses invalidateOverflowCache on this path",
                changed_files=[])
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("cannot execute on the anchor's path" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])

    def test_numeric_bound_change_is_not_metadata(self):
        # A bare-integer delta is a semantic change: only dotted versions,
        # long hashes and timestamps count as version noise.
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            agent._current_hunks = [{
                "id": "f001-h003", "path": "guard.c",
                "patch": "@@ -12,1 +12,1 @@\n"
                         "-  if( nCell > 10 ) return 1;\n"
                         "+  if( nCell > 100 ) return 1;\n"}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h003 need_not_ported evidence=metadata_only "
                "version-only numeric bump",
                changed_files=[])
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("metadata_only does not match" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])
            # Dotted version noise stays metadata.
            agent._current_hunks = [{
                "id": "f001-h004", "path": "guard.c",
                "patch": "@@ -12,1 +12,1 @@\n"
                         "-  static const char version[] = \"3.44.3\";\n"
                         "+  static const char version[] = \"3.44.5\";\n"}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h004 need_not_ported evidence=metadata_only "
                "version string bump",
                changed_files=[])
            self.assertTrue(claims["ok"], claims["contradictions"])

    def test_comment_echo_does_not_satisfy_token_ratio(self):
        # Echoing the donor hunk's comment words into an unrelated edit must
        # not satisfy the token-ratio evidence for an implemented claim.
        with GitFixture() as fixture:
            agent = self._guard_agent(fixture, self.GUARD_SIBLING)
            agent._current_hunks = [{
                "id": "f001-h005", "path": "guard.c",
                "patch": ("@@ -6,7 +6,7 @@\n"
                          "   }else if( loc<0 ){\n"
                          "-    pCur->curFlags &= ~BTCF_ValidNKey;\n"
                          "+    pCur->curFlags &= ~(BTCF_ValidNKey|BTCF_ValidOvfl);"
                          " /* aggregate limit for overflow cursor validity */\n")}]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h005 implemented adjusted the guard.",
                changed_files=["guard.c"],
                candidate_patch=(
                    "diff --git a/guard.c b/guard.c\n"
                    "--- a/guard.c\n"
                    "+++ b/guard.c\n"
                    "@@ -2,1 +2,2 @@\n"
                    "   int loc = 0;\n"
                    "+  /* aggregate limit for overflow cursor validity */\n"))
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("no mapped target semantic evidence" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])

    def test_implemented_evidence_accepts_rewrapped_adaptation(self):
        # dpsk_8/CVE-2025-32348 lesson: the donor rewraps an argument list and
        # inserts one operand; the target patch adds just that operand on its
        # own line. Exact-line matching and the token ratio both miss it, so
        # the hunk's novel tokens must carry the evidence.
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files", ("wm/WindowProcessController.java",))
            agent._current_hunks = [{
                "id": "f004-h001",
                "path": "wm/WindowProcessController.java",
                "patch": (
                    "@@ -727,7 +727,8 @@\n"
                    "                 mInfo.packageName, appSwitchState, checkConfiguration,\n"
                    "-                hasActivityInVisibleTask(), "
                    "mInstrumentingWithBackgroundActivityStartPrivileges,\n"
                    "+                hasActivityInVisibleTask(), inPinnedWindowingMode(),\n"
                    "+                mInstrumentingWithBackgroundActivityStartPrivileges,\n"),
            }]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f004-h001 implemented added pinned operand.",
                changed_files=["wm/WindowProcessController.java"],
                candidate_patch=(
                    "diff --git a/wm/WindowProcessController.java "
                    "b/wm/WindowProcessController.java\n"
                    "--- a/wm/WindowProcessController.java\n"
                    "+++ b/wm/WindowProcessController.java\n"
                    "@@ -519,2 +519,3 @@\n"
                    "                 appSwitchAllowed, isCheckingForFgsStart, "
                    "hasActivityInVisibleTask(),\n"
                    "+                inPinnedWindowingMode(),\n"
                    "                 mInstrumentingWithBackgroundActivityStartPrivileges,\n"))
            self.assertTrue(claims["ok"], claims["contradictions"])
            self.assertIn("inPinnedWindowingMode",
                          claims["claims"][0]["target_evidence"]["match"])

    def test_implemented_evidence_accepts_adapted_derivation_with_comments(self):
        # dpsk_8/CVE-2025-48649 lesson: the donor splits one condition across
        # two lines with a trailing comment; the target renames the variables
        # and derives the same predicate. Novel tokens (comment-stripped) must
        # be recognized inside the adapted target line.
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files", ("services/am/ActivityManagerService.java",))
            agent._current_hunks = [{
                "id": "f006-h002",
                "path": "services/am/ActivityManagerService.java",
                "patch": (
                    "@@ -3543,7 +3543,8 @@\n"
                    "-                permitted = (applicationInfo != null && "
                    "applicationInfo.uid == uid) // own uid data\n"
                    "+                permitted = (applicationInfo != null && "
                    "applicationInfo.uid == uid\n"
                    "+                        && !restorePregrantedPermissions) "
                    "// own uid data, not changing pregrants\n"),
            }]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f006-h002 implemented derived clearing predicate.",
                changed_files=["services/am/ActivityManagerService.java"],
                candidate_patch=(
                    "diff --git a/services/am/ActivityManagerService.java "
                    "b/services/am/ActivityManagerService.java\n"
                    "--- a/services/am/ActivityManagerService.java\n"
                    "+++ b/services/am/ActivityManagerService.java\n"
                    "@@ -3560,1 +3560,2 @@\n"
                    "                 pid, uid, -1, true);\n"
                    "+            final boolean clearingOwnUidData = appInfo != null "
                    "&& appInfo.uid == uid && !restorePregrantedPermissions;\n"))
            self.assertTrue(claims["ok"], claims["contradictions"])
            self.assertIn("restorePregrantedPermissions",
                          claims["claims"][0]["target_evidence"]["match"])

    def test_versioned_donor_hunk_requires_target_semantic_evidence(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files", ("dist/generated.c", "dist/orig/generated.c"))
            agent._current_hunks = [{
                "id": "f001-h001",
                "path": "dist/library-3440300/generated.c",
                "patch": (
                    "diff --git a/dist/sqlite3.c b/dist/sqlite3.c\n"
                    "@@ -79309,1 +79309,1 @@\n"
                    "-    cursor_flags &= ~CACHE_VALID_KEY;\n"
                    "+    cursor_flags &= ~(CACHE_VALID_KEY|CACHE_VALID_OVERFLOW);\n"
                ),
            }]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 implemented updated cursor invalidation.",
                changed_files=["dist/generated.c"],
                candidate_patch=(
                    "diff --git a/dist/generated.c b/dist/generated.c\n"
                    "--- a/dist/generated.c\n"
                    "+++ b/dist/generated.c\n"
                    "@@ -1,1 +1,1 @@\n"
                    "-int unrelated = 0;\n"
                    "+int unrelated = 1;\n"))
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("f001-h001" in item and "semantic evidence" in item
                    for item in claims["contradictions"]),
                claims["contradictions"])

    def test_parallel_generated_targets_require_each_mapped_hunk(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture, case=fixture.case(validation=True))
            object.__setattr__(
                agent.case, "files", ("dist/generated.c", "dist/orig/generated.c"))
            agent._current_hunks = [
                {"id": "f001-h001", "path": "dist/source-1.2/generated.c",
                 "patch": "@@ -1,1 +1,1 @@\n-old guard\n+stable_guard(1);\n"},
                {"id": "f002-h001", "path": "dist/source-1.2/orig/generated.c",
                 "patch": "@@ -1,1 +1,1 @@\n-old guard\n+stable_guard(2);\n"},
            ]
            claims = agent._check_hunk_results(
                "HUNK-RESULT f001-h001 implemented synchronized generated fix.\n"
                "HUNK-RESULT f002-h001 implemented synchronized generated fix.",
                changed_files=["dist/generated.c"],
                candidate_patch=(
                    "diff --git a/dist/generated.c b/dist/generated.c\n"
                    "--- a/dist/generated.c\n"
                    "+++ b/dist/generated.c\n"
                    "@@ -1,1 +1,1 @@\n"
                    "-old guard\n"
                    "+stable_guard(1);\n"))
            self.assertFalse(claims["ok"])
            self.assertTrue(
                any("f002-h001" in item for item in claims["contradictions"]),
                claims["contradictions"])

    def test_affected_platform_semantics_do_not_block_impact(self):
        # seven-410ea70/CVE-2025-48550 lesson: when the harm path flows through
        # documented standard-library semantics (java.io.File parent/child
        # resolution), listing them as platform_semantics anchored at the
        # executable target call site must not force AFFECTED down to UNKNOWN.
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["evidence"].append({
                "revision": "target", "path": "counter.py", "line_start": 4,
                "line_end": 4, "excerpt": "    out = File(slice_dir, file_name)",
                "claim": "Target builds the file name with the platform File API."})
            causal = assessment["causal_chain"]
            causal["target_harm_evidence"] = [1, 4]
            causal["platform_semantics"] = [{
                "api": "java.io.File",
                "behavior": "accepts child paths containing '/' and '..' without "
                            "confining resolution to the parent directory",
                "relied_at_evidence": [4],
            }]
            self._with_counter_hunk(agent)
            agent._validate_impact_causality(assessment)

    def test_platform_semantics_rejects_unanchored_api_name(self):
        # A libc-colliding bare name whose cited anchor never mentions the
        # symbol must not launder repo behavior into platform semantics.
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["causal_chain"]["platform_semantics"] = [{
                "api": "read",
                "behavior": "the target service read() dispatches caller data "
                            "without a permission check",
                "relied_at_evidence": [1],
            }]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("excerpt mentions the API", str(ctx.exception))

    def test_platform_semantics_requires_causal_chain_anchor(self):
        # A plausible platform API anchored at target code outside the causal
        # chain's target_fault/target_harm evidence is not reliance.
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["evidence"].append({
                "revision": "target", "path": "counter.py", "line_start": 4,
                "line_end": 4, "excerpt": "    out = File(slice_dir, file_name)",
                "claim": "Unrelated target File call site."})
            assessment["causal_chain"]["platform_semantics"] = [{
                "api": "java.io.File",
                "behavior": "does not confine child path resolution",
                "relied_at_evidence": [4],
            }]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("target_fault/target_harm evidence", str(ctx.exception))

    def test_platform_semantics_rejects_non_fqcn_prefix(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["causal_chain"]["platform_semantics"] = [{
                "api": "java.",
                "behavior": "platform behavior",
                "relied_at_evidence": [1],
            }]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("not a standard-library/platform API", str(ctx.exception))

    def test_platform_semantics_rejects_repo_implemented_api(self):
        # When the audited repository is libcore/bionic itself, the "platform"
        # semantics live inside the analyzed code and must be cited, not
        # asserted from memory.
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            object.__setattr__(agent.case, "repository", "libcore/luni")
            assessment = fixture.assessment("AFFECTED")
            assessment["evidence"].append({
                "revision": "target", "path": "counter.py", "line_start": 4,
                "line_end": 4, "excerpt": "    out = File(slice_dir, file_name)",
                "claim": "Target builds the file name with File."})
            causal = assessment["causal_chain"]
            causal["target_harm_evidence"] = [1, 4]
            causal["platform_semantics"] = [{
                "api": "java.io.File",
                "behavior": "does not confine child path resolution",
                "relied_at_evidence": [4],
            }]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("implemented by the repository under analysis",
                          str(ctx.exception))

    def test_repo_behavior_cannot_launder_as_platform_semantics(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["causal_chain"]["platform_semantics"] = [{
                "api": "com.android.server.wm.ActivityStarter",
                "behavior": "starts activities with the supplied options",
                "relied_at_evidence": [1],
            }]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("not a standard-library/platform API", str(ctx.exception))

    def test_platform_semantics_require_target_call_site(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["causal_chain"]["platform_semantics"] = [{
                "api": "java.io.File",
                "behavior": "does not confine child path resolution",
                "relied_at_evidence": [2],
            }]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("must cite the target call site", str(ctx.exception))

    def test_uncited_repo_behavior_still_blocks_affected(self):
        with GitFixture() as fixture:
            agent = self.agent(fixture)
            assessment = fixture.assessment("AFFECTED")
            assessment["causal_chain"]["external_behavior_assumptions"] = [
                "ActivityTaskManager resolves the intent synchronously"]
            self._with_counter_hunk(agent)
            with self.assertRaises(AssessmentError) as ctx:
                agent._validate_impact_causality(assessment)
            self.assertIn("cannot rest on uncited repository/framework behavior",
                          str(ctx.exception))

    def _with_counter_hunk(self, agent):
        agent._current_hunks = [{
            "id": "f001-h001", "path": "counter.py",
            "old_start": 1, "new_start": 1,
            "patch": "@@ -1,1 +1,1 @@\n-return value\n+return max(0, min(value, 10))\n"}]

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
            impact, backport = runtime.calls[0]["prompt"], runtime.calls[1]["prompt"]
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
