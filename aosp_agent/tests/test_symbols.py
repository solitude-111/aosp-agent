"""Tests for aosp_agent.symbols (R4 port: extraction + git grep location)."""
import subprocess
import unittest
from pathlib import Path

from aosp_agent.patches import split_hunks
from aosp_agent.symbols import (
    existence_report, extract_referenced_symbols, locate_in_revision, nearest_symbols,
)
from aosp_agent.tests.engine_fixtures import git

DONOR_GIT = Path("/home/guolei/aosp-agent-48550/donor-git/frameworks-base.git")
TARGET_CHECKOUT = Path("/home/guolei/aosp-agent-48550/source/frameworks/base")
TARGET_COMMIT = "cebf5c06997b64f4e47a1611edb5f97044509d76"
SOURCE_COMMIT = "5f0874dde8c0572e078ebb9d74d8f891e3103175"
SOURCE_PARENT = "2d2c1fa2213b9032689512741b07c1d181047972"

DONOR_DIFF = """diff --git a/src/Widget.java b/src/Widget.java
--- a/src/Widget.java
+++ b/src/Widget.java
@@ -1,2 +1,10 @@
 head
+import a.b.Foo;
+import x.y.Missing;
+@Deprecated
+        Widget w = new Foo();
+        Missing.verify(w);
+        helperCall(1);
+        localHelper(2);
+    private void localHelper(int v) {
 tail
"""


class SymbolFixture:
    """A small real Git repository with a target baseline to grep."""

    def __enter__(self):
        import tempfile
        self._directory = tempfile.TemporaryDirectory()
        self.root = Path(self._directory.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q")
        (self.repo / "a" / "b").mkdir(parents=True)
        (self.repo / "a" / "b" / "Foo.java").write_text(
            "package a.b;\npublic class Foo {\n    public static Foo create() { return new Foo(); }\n}\n")
        (self.repo / "Helper.java").write_text(
            "public class Helper {\n    public boolean helperCall(int x) { return x > 0; }\n}\n")
        (self.repo / "MissedHandler.java").write_text(
            "public class MissedHandler {\n    public void dispatch() { }\n}\n")
        (self.repo / "Use.java").write_text(
            "@Deprecated\npublic class Use {\n    FooBar bar = new FooBar();\n}\n")
        (self.repo / "FooBar.java").write_text("public class FooBar { }\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "target baseline")
        self.target = git(self.repo, "rev-parse", "HEAD")
        return self

    def __exit__(self, *_args):
        self._directory.cleanup()


class ExtractReferencedSymbolsTest(unittest.TestCase):
    def test_kinds_and_method_call_defined_in_hunk_is_excluded(self):
        hunks = split_hunks(DONOR_DIFF)
        symbols = extract_referenced_symbols(hunks)
        by_name = {}
        for symbol in symbols:
            by_name.setdefault(symbol["name"], set()).add(symbol["kind"])
        self.assertEqual(by_name["Foo"], {"import", "type_ref"})
        self.assertEqual(by_name["Missing"], {"import", "type_ref"})
        self.assertIn("annotation", by_name["Deprecated"])
        self.assertIn("method_call", by_name["helperCall"])
        self.assertNotIn("localHelper", by_name)
        self.assertNotIn("Widget", by_name)  # bare identifier, not a call/reference
        for symbol in symbols:
            self.assertTrue(symbol["origin"]["hunk_id"])
            self.assertGreater(symbol["origin"]["line"], 0)


class LocateInRevisionTest(unittest.TestCase):
    def test_found_missing_and_word_boundaries(self):
        with SymbolFixture() as fixture:
            hit = locate_in_revision([], fixture.target, "Foo", cwd=fixture.repo)
            self.assertTrue(hit["found"])
            self.assertEqual(hit["matches"], ["a/b/Foo.java:2", "a/b/Foo.java:3"])
            miss = locate_in_revision([], fixture.target, "Missing", cwd=fixture.repo)
            self.assertFalse(miss["found"])
            # Word matching: Foo must not match FooBar.
            prefix = locate_in_revision([], fixture.target, "FooB", cwd=fixture.repo)
            self.assertFalse(prefix["found"])
            helper = locate_in_revision([], fixture.target, "helperCall", cwd=fixture.repo)
            self.assertEqual(helper["matches"], ["Helper.java:2"])

    def test_git_failure_is_reported_not_raised(self):
        result = locate_in_revision([], "0" * 40, "Foo", cwd=Path.cwd())
        self.assertFalse(result["found"])
        self.assertIn("error", result)


class NearestSymbolsTest(unittest.TestCase):
    def test_difflib_close_matches(self):
        self.assertEqual(nearest_symbols("ParsingPackageUtils",
                                         ["ParsingPackageUtil", "PackageParser", "OtherThing"], n=2),
                         ["ParsingPackageUtil", "PackageParser"])


class ExistenceReportTest(unittest.TestCase):
    def test_found_and_missing_with_nearest_hints(self):
        with SymbolFixture() as fixture:
            report = existence_report(split_hunks(DONOR_DIFF), fixture.repo, fixture.target)
            found = {entry["name"] for entry in report["found"]}
            missing = {entry["name"] for entry in report["missing"]}
            self.assertIn("Foo", found)
            self.assertIn("helperCall", found)
            self.assertIn("Deprecated", found)
            self.assertIn("Missing", missing)
            self.assertNotIn("FooBar", missing)  # never referenced by the donor
            entry = next(item for item in report["missing"] if item["name"] == "Missing")
            self.assertEqual(entry["origins"][0]["hunk_id"], "f001-h001")
            self.assertIn("referenced symbols", report["summary"])
            self.assertIn("missing", report["summary"])

    def test_report_is_size_capped(self):
        import json
        with SymbolFixture() as fixture:
            report = existence_report(split_hunks(DONOR_DIFF), fixture.repo, fixture.target)
            self.assertLessEqual(len(json.dumps(report, ensure_ascii=False)), 8192)


@unittest.skipUnless(DONOR_GIT.is_dir() and TARGET_CHECKOUT.is_dir(),
                     "real 48550 repositories are not present")
class Golden48550Test(unittest.TestCase):
    """Golden assertion: the donor's Android 16 package-validation API is missing at Android 12.

    The donor diff references FrameworkParsingPackageUtils (the pm.parsing
    utils family, absent from the Android 12 baseline); the plan's original
    wording said "ParsingPackageUtils", which is the historical shorthand for
    the same API family — the exact donor identifier is the prefixed class.
    """

    def test_parsingpackageutils_is_missing_at_target(self):
        diff = subprocess.run(["git", "-c", "protocol.allow=never", "--git-dir", str(DONOR_GIT),
                               "diff", "--no-ext-diff", SOURCE_PARENT, SOURCE_COMMIT],
                              capture_output=True, text=True, check=True,
                              env={"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
                                   "PATH": "/usr/bin:/bin"}).stdout
        hunks = split_hunks(diff)
        report = existence_report(hunks, TARGET_CHECKOUT, TARGET_COMMIT)
        missing = {entry["name"] for entry in report["missing"]}
        self.assertIn("FrameworkParsingPackageUtils", missing)


if __name__ == "__main__":
    unittest.main()
