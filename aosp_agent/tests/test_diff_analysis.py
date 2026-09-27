import unittest

from aosp_agent.diff_analysis import (
    classify_donor_diff, extract_security_hunks,
    infer_vulnerability_class, preprocess_donor_diff,
)


class ClassifyTest(unittest.TestCase):
    def test_surgical_fix(self):
        diff = """diff --git a/src/a.java b/src/a.java
--- a/src/a.java
+++ b/src/a.java
@@ -10,3 +10,4 @@
-    checkPermission(perm);
+    if (!checkPermission(perm)) {
+        return DENIED;
+    }
"""
        result = classify_donor_diff(diff)
        self.assertEqual(result["type"], "surgical_fix")

    def test_version_copy_detected(self):
        diff = """diff --git a/METADATA b/METADATA
--- a/METADATA
+++ b/METADATA
@@ -1 +1 @@
- version: "3.44.3"
+ version: "3.44.5"
diff --git a/README.version b/README.version
--- a/README.version
+++ b/README.version
@@ -1 +1 @@
- 3.44.3
+ 3.44.5
diff --git a/lib/sqlite3.c b/lib/sqlite3.c
--- a/lib/sqlite3.c
+++ b/lib/sqlite3.c
@@ -100 +100 @@
-#define SQLITE_VERSION "3.44.3"
+#define SQLITE_VERSION "3.44.5"
@@ -200,3 +200,3 @@
-  u16 nSortingColumn;
+  u32 nSortingColumn;
"""
        result = classify_donor_diff(diff)
        self.assertEqual(result["type"], "version_copy")


class ExtractTest(unittest.TestCase):
    def test_filters_version_noise(self):
        diff = """diff --git a/lib/sqlite3.c b/lib/sqlite3.c
--- a/lib/sqlite3.c
+++ b/lib/sqlite3.c
@@ -1,1 +1,1 @@
-#define SQLITE_VERSION "3.44.3"
+#define SQLITE_VERSION "3.44.5"
@@ -100,1 +100,2 @@
-  u16 nSortingColumn;
+  u32 nSortingColumn;
+  int mxTerm = aLimit[SQLITE_LIMIT_COLUMN];
"""
        result = extract_security_hunks(diff)
        self.assertGreater(result["extracted_hunks"], 0)
        self.assertIn("u32", result["security_diff"])
        self.assertIn("mxTerm", result["security_diff"])
        # Version string should NOT appear in the security diff hunk
        self.assertNotIn("3.44.5", result["security_diff"])

    def test_infer_integer_overflow(self):
        hunks = ["-  u16 nSortingColumn;\n+  u32 nSortingColumn;\n",
                 "+  if( k>mxTerm ){\n+    error;\n+  }\n"]
        self.assertEqual(infer_vulnerability_class(hunks), "integer_overflow")

    def test_infer_permission(self):
        hunks = ["+  if (!checkPermission(perm)) {\n+    return;\n+  }\n"]
        self.assertEqual(infer_vulnerability_class(hunks), "permission_bypass")


class PreprocessTest(unittest.TestCase):
    def test_surgical_passthrough(self):
        diff = "diff --git a/a.java b/a.java\n--- a/a.java\n+++ b/a.java\n@@ -1 +1 @@\n-a\n+b\n"
        result = preprocess_donor_diff(diff)
        self.assertFalse(result["preprocessed"])
        self.assertEqual(result["security_diff"], diff)
        self.assertIsNotNone(result["vulnerability_class"])

    def test_version_copy_preprocessed(self):
        diff = """diff --git a/METADATA b/METADATA
--- a/METADATA
+++ b/METADATA
@@ -1 +1 @@
- 3.44.3
+ 3.44.5
diff --git a/README.version b/README.version
--- a/README.version
+++ b/README.version
@@ -1 +1 @@
- 3.44.3
+ 3.44.5
diff --git a/lib/code.c b/lib/code.c
--- a/lib/code.c
+++ b/lib/code.c
@@ -100 +100 @@
-  u16 count;
+  u32 count;
"""
        result = preprocess_donor_diff(diff)
        self.assertTrue(result["preprocessed"])
        self.assertIsNotNone(result["vulnerability_class"])
        self.assertNotIn("3.44.5", result["security_diff"])
        self.assertIn("u32", result["security_diff"])


if __name__ == "__main__":
    unittest.main()
