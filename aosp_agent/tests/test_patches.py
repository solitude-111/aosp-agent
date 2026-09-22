import unittest

from aosp_agent.patches import split_hunks


class PatchParsingTest(unittest.TestCase):
    def test_multiple_files_and_hunks_keep_ranges_and_headers(self):
        first = "@@ -2,2 +2,3 @@ first method\n keep\n-old\n+new\n+extra\n"
        second = "@@ -20 +21 @@ second method\n-before\n+after\n"
        other = "@@ -1 +1 @@\n-left\n+right\n"
        header = "diff --git a/A.java b/A.java\nindex abc123..def456 100644\n--- a/A.java\n+++ b/A.java\n"
        diff = header + first + second + "diff --git a/B.java b/B.java\n--- a/B.java\n+++ b/B.java\n" + other
        hunks = split_hunks(diff)
        self.assertEqual([h["path"] for h in hunks], ["A.java", "A.java", "B.java"])
        self.assertEqual([h["id"] for h in hunks], ["f001-h001", "f001-h002", "f002-h001"])
        self.assertEqual((hunks[0]["old_count"], hunks[0]["new_count"]), (2, 3))
        self.assertEqual((hunks[0]["added_lines"], hunks[0]["removed_lines"]), (2, 1))
        self.assertEqual(hunks[1]["new_start"], 21)
        self.assertEqual(hunks[1]["patch"], header.replace("index abc123..def456 100644\n", "") + second)
        self.assertNotIn("index ", hunks[0]["patch"])
        self.assertEqual(hunks[2]["hunk_index"], 1)

    def test_header_looking_content_is_not_a_file_header(self):
        diff = "--- a/name.txt\n+++ b/name.txt\n@@ -1,2 +1,2 @@\n--- old text\n+++ new text\n same\n"
        hunks = split_hunks(diff)
        self.assertEqual(len(hunks), 1)
        self.assertEqual(hunks[0]["path"], "name.txt")
        self.assertEqual(hunks[0]["patch"], diff)
        self.assertEqual(hunks[0]["context_lines"], 1)

    def test_no_newline_markers_are_preserved_and_not_counted(self):
        diff = ("diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n"
                "\\ No newline at end of file\n+new\n\\ No newline at end of file\n")
        hunk = split_hunks(diff)[0]
        self.assertEqual(hunk["patch"], diff)
        self.assertEqual((hunk["old_count"], hunk["new_count"]), (1, 1))
        self.assertEqual(hunk["patch"].count("\\ No newline at end of file"), 2)

    def test_added_file_retains_creation_headers(self):
        diff = ("diff --git a/new.txt b/new.txt\nnew file mode 100644\n"
                "index 0000000..abc1234\n--- /dev/null\n+++ b/new.txt\n"
                "@@ -0,0 +1,2 @@\n+first\n+second\n")
        hunk = split_hunks(diff)[0]
        self.assertEqual(hunk["kind"], "hunk")
        self.assertIsNone(hunk["old_path"])
        self.assertEqual(hunk["new_path"], "new.txt")
        self.assertEqual(hunk["old_count"], 0)
        self.assertEqual(hunk["patch"], diff.replace("index 0000000..abc1234\n", ""))

    def test_plain_unified_multiple_files(self):
        diff = ("--- a/first\n+++ b/first\n@@ -1 +1 @@\n-a\n+b\n"
                "--- a/second\n+++ b/second\n@@ -2,0 +3 @@\n+extra\n")
        hunks = split_hunks(diff)
        self.assertEqual([h["path"] for h in hunks], ["first", "second"])
        self.assertTrue(hunks[1]["patch"].startswith("--- a/second\n+++ b/second\n"))

    def test_empty_file_creation_and_deletion_remain_metadata(self):
        for mode, old_path, new_path in [("new", None, "empty"), ("deleted", "empty", None)]:
            with self.subTest(mode=mode):
                diff = f"diff --git a/empty b/empty\n{mode} file mode 100644\n"
                record = split_hunks(diff)[0]
                self.assertEqual(record["kind"], "whole_file")
                self.assertEqual(record["hunk_count"], 0)
                self.assertEqual((record["old_path"], record["new_path"]), (old_path, new_path))

    def test_deleted_file_preserves_null_destination(self):
        diff = ("diff --git a/gone b/gone\ndeleted file mode 100644\n"
                "--- a/gone\n+++ /dev/null\n@@ -1 +0,0 @@\n-removed\n")
        record = split_hunks(diff)[0]
        self.assertEqual(record["path"], "gone")
        self.assertIsNone(record["new_path"])
        self.assertEqual(record["new_count"], 0)
        self.assertEqual(record["patch"], diff)

    def test_mode_only_change_is_not_an_empty_hunk(self):
        diff = "diff --git a/file name b/file name\nold mode 100644\nnew mode 100755\n"
        record = split_hunks(diff)[0]
        self.assertEqual(record["kind"], "whole_file")
        self.assertTrue(record["supported"])
        self.assertEqual(record["hunk_count"], 0)
        self.assertIsNone(record["hunk_index"])
        self.assertEqual(record["patch"], diff)
        self.assertEqual(record["path"], "file name")

    def test_rename_with_hunks_remains_whole_file(self):
        diff = ("diff --git a/old.java b/new.java\nsimilarity index 95%\n"
                "rename from old.java\nrename to new.java\nindex abc123..def456 100644\n"
                "--- a/old.java\n+++ b/new.java\n@@ -1 +1 @@\n-old\n+new\n"
                "@@ -10 +10 @@\n-before\n+after\n")
        records = split_hunks(diff)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "whole_file")
        self.assertEqual(records[0]["hunk_count"], 2)
        self.assertIn("rename from old.java\n", records[0]["patch"])

    def test_binary_and_combined_are_explicitly_unsupported(self):
        for diff, reason in [
            ("diff --git a/image.bin b/image.bin\nindex abc123..def456 100644\n"
             "Binary files a/image.bin and b/image.bin differ\n", "binary_diff"),
            ("diff --cc code.java\nindex abc123,def456..789abc\n"
             "--- a/code.java\n+++ b/code.java\n@@@ -1 -1 +1 @@@\n  value\n", "combined_diff"),
        ]:
            with self.subTest(reason=reason):
                record = split_hunks(diff)[0]
                self.assertFalse(record["supported"])
                self.assertEqual(record["kind"], "unsupported")
                self.assertEqual(record["reason"], reason)
                self.assertEqual(record["patch"], diff)

    def test_quoted_utf8_paths(self):
        diff = (r'diff --git "a/\303\251.java" "b/\303\251.java"' + "\n"
                + r'--- "a/\303\251.java"' + "\n" + r'+++ "b/\303\251.java"'
                + "\n@@ -1 +1 @@\n-old\n+new\n")
        self.assertEqual(split_hunks(diff)[0]["path"], "é.java")

    def test_malformed_counts_and_orphan_markers_are_rejected(self):
        for body in ["@@ -2,2 +2,2 @@\n-a\n+b\n", "@@ -1 +1 @@\n+a\n+b\n",
                     "@@ -1 +1 @@\n\\ No newline at end of file\n-a\n+b\n"]:
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    split_hunks("--- a/f\n+++ b/f\n" + body)

    def test_empty_diff_has_no_hunks(self):
        self.assertEqual(split_hunks(""), [])
        self.assertEqual(split_hunks("\n \n"), [])
        with self.assertRaises(ValueError):
            split_hunks("not a diff\n")


if __name__ == "__main__":
    unittest.main()
