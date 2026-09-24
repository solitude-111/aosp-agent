"""Tests for aosp_agent.diagnosis (R5/R6/R13 ports)."""
import unittest

from aosp_agent.diagnosis import (
    apply_diagnosis, similar_files, verification_diagnosis,
)

PATH = "services/core/java/com/android/server/slice/SlicePermissionManager.java"


def make_hunk(body_lines, path=PATH):
    prefix = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,4 +1,4 @@\n"
    return {"id": "f001-h001", "kind": "hunk", "supported": True, "path": path,
            "patch": prefix + "\n".join(body_lines) + "\n"}


TARGET = ["public class SlicePermissionManager {",
          "    void grantSlicePermission(String pkg) {",
          "        validatePackageName(pkg);",
          "    }",
          "}"]


class ApplyDiagnosisTest(unittest.TestCase):
    def test_context_mismatch_reports_block_and_line_diffs(self):
        hunk = make_hunk([" public class SlicePermissionManager {",
                          "-        validateName(pkg);",
                          "+        enforceValidPackage();",
                          "     }"])
        diagnosis = apply_diagnosis(hunk, "error: patch failed: services/...: does not apply",
                                    TARGET)
        self.assertEqual(diagnosis["kind"], "context_mismatch")
        self.assertEqual(diagnosis["similar_block"]["path"], PATH)
        self.assertTrue(1 <= diagnosis["similar_block"]["start"] <= len(TARGET))
        self.assertTrue(diagnosis["line_diffs"])
        first = diagnosis["line_diffs"][0]
        self.assertIn("patch_text", first)
        self.assertIn("target_text", first)
        self.assertIn("Context lines differ", diagnosis["hint"])

    def test_positional_failure_when_text_matches(self):
        hunk = make_hunk(["     void grantSlicePermission(String pkg) {",
                          "-        validatePackageName(pkg);",
                          "+        validatePackageName(pkg, true);"])
        diagnosis = apply_diagnosis(hunk, "error: patch failed", TARGET)
        self.assertEqual(diagnosis["line_diffs"], [])
        self.assertIn("3 lines of exact context", diagnosis["hint"])

    def test_file_missing_lists_similar_files(self):
        hunk = make_hunk(["+new content"], path="src/moved/Gone.java")
        candidates = ["src/moved/GoneHelper.java", "src/Gone.java", "other/Unrelated.kt",
                      "a.java", "b.java", "c.java"]
        diagnosis = apply_diagnosis(hunk, "error: src/moved/Gone.java: No such file or directory",
                                    None, candidate_files=candidates)
        self.assertEqual(diagnosis["kind"], "file_missing")
        self.assertEqual(len(diagnosis["similar_files"]), 5)
        self.assertEqual(diagnosis["similar_files"][0], "src/Gone.java")
        self.assertEqual(diagnosis["similar_files"][1], "src/moved/GoneHelper.java")
        self.assertIn("hunk-history", diagnosis["hint"])

    def test_corrupt_patch_is_classified(self):
        diagnosis = apply_diagnosis(make_hunk(["+x"]), "error: corrupt patch at line 5", TARGET)
        self.assertEqual(diagnosis["kind"], "corrupt")


class SimilarFilesTest(unittest.TestCase):
    def test_ranking_prefers_basename_matches(self):
        ranked = similar_files("a/b/SlicePermissionManager.java",
                               ["a/SlicePermissionManagerTest.java", "z/other.java",
                                "a/b/SlicePermMgr.java", "1.java", "2.java"])
        self.assertEqual(ranked[0], "a/SlicePermissionManagerTest.java")


class VerificationDiagnosisTest(unittest.TestCase):
    def check(self, **overrides):
        base = {"stage": "android_module_build", "argv": ["make", "services"],
                "returncode": 1, "stdout": "", "stderr": "", "artifacts": []}
        base.update(overrides)
        return base

    def test_error_lines_and_symbols_are_extracted(self):
        result = verification_diagnosis([self.check(stderr=(
            "services/.../SlicePermissionManager.java:120: error: cannot find symbol\n"
            "  symbol:   variable FrameworkParsingPackageUtils\n"
            "error: package android.content.pm.parsing does not exist\n"
            "Note: some messages have been simplified\n"
            "FAILED: build failed\n"))])
        entry = result["stage_results"][0]
        self.assertEqual(len(entry["error_lines"]), 3)
        self.assertIn("FrameworkParsingPackageUtils", entry["symbols"])
        self.assertNotIn("log_tail", entry)
        self.assertIn("cannot find symbol", result["summary"])
        self.assertIn("FrameworkParsingPackageUtils", result["summary"])

    def test_missing_artifacts_are_reported(self):
        result = verification_diagnosis([self.check(
            returncode=125,
            artifacts=[{"path": "out/result.txt", "exists": False, "sha256": None}])])
        self.assertEqual(result["stage_results"][0]["missing_artifacts"], ["out/result.txt"])
        self.assertIn("out/result.txt", result["summary"])

    def test_no_error_lines_falls_back_to_log_tail(self):
        noise = [f"progress line {i}" for i in range(200)]
        result = verification_diagnosis([self.check(stdout="\n".join(noise))])
        entry = result["stage_results"][0]
        self.assertEqual(entry["error_lines"], [])
        tail = entry["log_tail"].splitlines()
        self.assertEqual(len(tail), 80)
        self.assertEqual(tail[-1], "progress line 199")
        self.assertIn("make services", result["summary"])

    def test_silent_failure_reports_argv(self):
        # grep -q / test -f fail with zero output; the failing argv is the
        # only actionable fact the model can act on (mb-005 lesson).
        result = verification_diagnosis([self.check(
            argv=["grep", "-Fq", "deferStartingWindowRemovalForKeyguardUnoccluding",
                  "services/tests/wmtests/src/com/android/server/wm/ActivityRecordTests.java"])])
        entry = result["stage_results"][0]
        self.assertEqual(entry["argv"][0], "grep")
        self.assertIn("no diagnostic output", result["summary"])
        self.assertIn("deferStartingWindowRemovalForKeyguardUnoccluding", result["summary"])
        self.assertIn("ActivityRecordTests.java", result["summary"])

    def test_passing_checks_summarize_cleanly(self):
        result = verification_diagnosis([self.check(returncode=0)])
        self.assertEqual(result["stage_results"][0]["error_lines"], [])
        self.assertIn("All configured checks passed", result["summary"])

    def test_summary_is_capped(self):
        checks = [self.check(stage=f"stage{i}", stderr="error: boom") for i in range(15)]
        self.assertLessEqual(len(verification_diagnosis(checks)["summary"].split(". ")), 11)


if __name__ == "__main__":
    unittest.main()
