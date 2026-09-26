import unittest

from aosp_agent.inherit import extract_hunk_positions, check_function_overlap


class HunkPositionTest(unittest.TestCase):
    def test_extracts_positions_from_simple_diff(self):
        diff = """--- a/src/a.java
+++ b/src/a.java
@@ -10,4 +10,6 @@
 context
+added
 context
@@ -50,3 +52,5 @@
 context
+more
 context
"""
        positions = extract_hunk_positions(diff)
        self.assertIn("src/a.java", positions)
        ranges = positions["src/a.java"]
        self.assertEqual(len(ranges), 2)
        self.assertEqual(ranges[0], (10, 15))  # start=10, count=6
        self.assertEqual(ranges[1], (52, 56))  # start=52, count=5

    def test_multiple_files(self):
        diff = """--- a/old.java
+++ b/new.java
@@ -1,3 +1,3 @@
 ctx
--- a/other.java
+++ b/other.java
@@ -100,2 +100,2 @@
 ctx
"""
        positions = extract_hunk_positions(diff)
        self.assertIn("new.java", positions)
        self.assertIn("other.java", positions)


class OverlapTest(unittest.TestCase):
    def test_no_overlap_when_different_lines(self):
        fix = """--- a/src/a.java
+++ b/src/a.java
@@ -10,3 +10,4 @@
 old
+new
 ctx
"""
        tag = """--- a/src/a.java
+++ b/src/a.java
@@ -100,3 +100,4 @@
 old
+changed
 ctx
"""
        result = check_function_overlap(fix, tag)
        self.assertFalse(result["overlap"])

    def test_overlap_when_same_lines(self):
        fix = """--- a/src/a.java
+++ b/src/a.java
@@ -10,5 +10,6 @@
 old
+new
 ctx
"""
        tag = """--- a/src/a.java
+++ b/src/a.java
@@ -12,3 +12,4 @@
 ctx
+changed
 ctx
"""
        result = check_function_overlap(fix, tag)
        self.assertTrue(result["overlap"])
        self.assertIn("src/a.java", result["files_with_overlap"])
        self.assertEqual(len(result["details"]), 1)
        detail = result["details"][0]
        self.assertEqual(detail["fix_lines"][0], 10)
        self.assertEqual(detail["fix_lines"][1], 15)

    def test_no_overlap_when_different_files(self):
        fix = """--- a/src/a.java
+++ b/src/a.java
@@ -10,3 +10,4 @@
+new
"""
        tag = """--- a/src/b.java
+++ b/src/b.java
@@ -10,3 +10,4 @@
+changed
"""
        result = check_function_overlap(fix, tag)
        self.assertFalse(result["overlap"])

    def test_empty_diffs(self):
        result = check_function_overlap("", "")
        self.assertFalse(result["overlap"])


if __name__ == "__main__":
    unittest.main()
