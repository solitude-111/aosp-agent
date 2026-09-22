"""Tests for aosp_agent.patch_repair (R3 port of RetroPatch revise_patch).

repair_hunk's contract is a hunk dict, not parser output: RetroPatch's
repairs targeted free-form generated patches, so the prefix and
line-number repairs are exercised with hand-built dicts (the strict
split_hunks parser would reject such malformed hunks before repair ever
sees them; through the engine those repairs are defensive no-ops).
"""
import unittest

from aosp_agent.patches import split_hunks
from aosp_agent.patch_repair import (
    extract_context, find_most_similar_block, repair_hunk,
)

PATH = "demo/Widget.java"
TARGET = ["package demo;", "", "public class Widget {",
          "    int count;", "", "    void run() {", "        step();", "    }", "}"]


def make_hunk(body_lines, header="@@ -6,3 +6,3 @@", path=PATH):
    prefix = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
    return {"id": "f001-h001", "kind": "hunk", "supported": True, "path": path,
            "patch": prefix + header + "\n" + "\n".join(body_lines) + "\n"}


class FindMostSimilarBlockTest(unittest.TestCase):
    def test_exact_block_is_located(self):
        main = ["a", "x", "y", "b", "c", "b", "c", "d"]
        start, distance = find_most_similar_block(["b", "c"], main, 2)
        self.assertEqual(start, 4)
        self.assertEqual(distance, 0)

    def test_offset_alignment_snaps_to_exact_line(self):
        # The fuzzy window may start one line early; an exact stripped match
        # inside snaps it back (RetroPatch offset logic).
        main = ["", "int alpha();", "int beta();", "int gamma();", "// tail"]
        start, _ = find_most_similar_block(["int alpha();", "int beta();"], main, 2)
        self.assertEqual(start, 2)

    def test_empty_pattern_returns_start(self):
        self.assertEqual(find_most_similar_block([], TARGET, 0), (1, 0))


class ExtractContextTest(unittest.TestCase):
    def test_context_and_added_split(self):
        contexts, added = extract_context([" ctx", "-del", "+new", "\\ No newline at end of file"])
        self.assertEqual(contexts, ["ctx", "del"])
        self.assertEqual(added, ["new"])


class RepairHunkTest(unittest.TestCase):
    def test_indentation_repair_records_every_fix(self):
        # Context content carries tab indentation while the target uses
        # spaces: identical normalized text — RetroPatch's whitespace-equality
        # condition — so the context is aligned to the target text.
        hunk = make_hunk([" \tvoid run() {", "-        step();", "+        step(1);", " \t}"])
        patch, repairs = repair_hunk(hunk, TARGET)
        self.assertEqual([r["what"] for r in repairs], ["indent", "indent"])
        self.assertIn("     void run() {", patch)
        self.assertIn("-        step();", patch)
        self.assertNotIn("\t", patch)

    def test_different_text_is_never_rewritten(self):
        hunk = make_hunk(["    void run() {", "-        step();", "+        step(1);", "    }"])
        target = ["void run(int x) {", "        totallyDifferent();", "};"]
        patch, repairs = repair_hunk(hunk, target)
        self.assertEqual(repairs, [])
        self.assertIn("-        step();", patch)

    def test_prefix_repair_adds_missing_marker(self):
        hunk = make_hunk(["    void run() {", "step();", "+        extra();", "    }"])
        patch, repairs = repair_hunk(hunk, TARGET)
        self.assertTrue(any(r["what"] == "prefix" for r in repairs))
        self.assertIn(" step();", patch)
        self.assertTrue(any(r["what"] == "line_numbers" for r in repairs))

    def test_line_number_repair_recomputes_counts(self):
        # Declared counts (3/3) do not match the body (1 old / 2 new lines).
        hunk = make_hunk(["    void run() {", "+        audit();"], "@@ -6,3 +6,3 @@")
        patch, repairs = repair_hunk(hunk, TARGET)
        self.assertIn("@@ -6,1 +6,2 @@", patch)
        self.assertTrue(any(r["what"] == "line_numbers" for r in repairs))

    def test_clean_hunk_from_split_hunks_is_unchanged(self):
        diff = (f"diff --git a/{PATH} b/{PATH}\n--- a/{PATH}\n+++ b/{PATH}\n"
                "@@ -6,3 +6,3 @@\n     void run() {\n         step();\n     }\n")
        hunk = next(h for h in split_hunks(diff) if h["kind"] == "hunk")
        patch, repairs = repair_hunk(hunk, TARGET)
        self.assertEqual(repairs, [])
        self.assertIn("@@ -6,3 +6,3 @@", patch)
        self.assertIn("         step();", patch)

    def test_no_newline_marker_is_preserved(self):
        hunk = make_hunk(["    }", "+// end", "\\ No newline at end of file"], "@@ -9,1 +9,2 @@")
        patch, repairs = repair_hunk(hunk, TARGET)
        self.assertIn("\\ No newline at end of file", patch)
        self.assertFalse(any(r["what"] == "prefix" for r in repairs))

    def test_shifted_block_is_aligned_to_target_indentation(self):
        # The donor context sits lower in the target with different
        # indentation; the context is aligned to the located block so the
        # repaired hunk applies against the target text.
        target = ["junk1", "junk2", "\tpublic class Widget {", "\tint count;", "",
                  "    void run() {", "        step();", "    }", "}"]
        hunk = make_hunk(["public class Widget {", "    int count;", "+    boolean fixed;"],
                         "@@ -1,2 +1,3 @@")
        patch, repairs = repair_hunk(hunk, target)
        self.assertTrue(any(r["what"] == "indent" for r in repairs))
        self.assertIn("\tpublic class Widget {", patch)


if __name__ == "__main__":
    unittest.main()
