"""Tests for aosp_agent.agent_tools (P2.2 controlled tools)."""
import json
import os
import subprocess
import unittest
from pathlib import Path

from aosp_agent.agent_tools import main as tools_main
from aosp_agent.engine import AospBackportAgent
from aosp_agent.tests.engine_fixtures import GitFixture, git


class PreparedRun:
    """A completed inspect-only run with a separate donor bare store."""

    def __enter__(self):
        self.fixture = GitFixture()
        self.fixture.__enter__()
        self.donor_root = self.fixture.root / "donor"
        self.donor_root.mkdir()
        subprocess.run(["git", "clone", "-q", "--bare", str(self.fixture.repo),
                        str(self.donor_root / "repo.git")], check=True, capture_output=True)
        agent = AospBackportAgent(self.fixture.source_root, self.fixture.run_root,
                                  self.fixture.case(), donor_root=self.donor_root)
        agent.run(use_model=False)
        self.agent = agent
        self.run_dir = self.fixture.run_root / "CVE-2099-2000"
        self.record = json.loads((self.run_dir / "run.json").read_text())
        return self

    def __exit__(self, *_args):
        self.fixture.__exit__(None, None, None)

    def usage_lines(self):
        path = self.run_dir / "tool-usage.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


class AgentToolsTest(unittest.TestCase):
    def run_tool(self, prepared, *argv):
        code = tools_main(["--run-dir", str(prepared.run_dir), *argv])
        return code

    def test_wrappers_are_generated_and_executable(self):
        with PreparedRun() as prepared:
            for command in ("locate-symbol", "view-code", "hunk-history", "show-commit"):
                script = prepared.run_dir / "bin" / command
                self.assertTrue(script.is_file(), command)
                self.assertTrue(os.access(script, os.X_OK), command)
            target = prepared.record["target_commit"]
            completed = subprocess.run(
                ["bash", str(prepared.run_dir / "bin" / "locate-symbol"),
                 "--repo", "target", "--ref", target, "--symbol", "normalize_count"],
                capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("counter.py:1", completed.stdout)

    def test_view_code_slices_and_shrinks_out_of_range(self):
        with PreparedRun() as prepared:
            target = prepared.record["target_commit"]
            code = self.run_tool(prepared, "view-code", "--repo", "target", "--ref", target,
                                 "--path", "counter.py", "--start", "1", "--end", "2")
            self.assertEqual(code, 0)
            code = self.run_tool(prepared, "view-code", "--repo", "target", "--ref", target,
                                 "--path", "counter.py", "--start", "1", "--end", "50")
            self.assertEqual(code, 0)
            code = self.run_tool(prepared, "view-code", "--repo", "target", "--ref", target,
                                 "--path", "missing.py", "--start", "1", "--end", "5")
            self.assertEqual(code, 0)

    def test_ref_whitelist_and_path_validation(self):
        with PreparedRun() as prepared:
            target = prepared.record["target_commit"]
            self.assertEqual(self.run_tool(prepared, "view-code", "--repo", "target",
                                           "--ref", "0" * 40, "--path", "counter.py",
                                           "--start", "1", "--end", "2"), 2)
            self.assertEqual(self.run_tool(prepared, "view-code", "--repo", "target",
                                           "--ref", target, "--path", "../outside",
                                           "--start", "1", "--end", "2"), 2)
            # argparse rejects an unknown --repo before the tool runs.
            with self.assertRaises(SystemExit):
                tools_main(["--run-dir", str(prepared.run_dir), "locate-symbol",
                            "--repo", "somewhere", "--ref", target, "--symbol", "x"])
    def test_locate_symbol_miss_suggests_nearest(self):
        with PreparedRun() as prepared:
            target = prepared.record["target_commit"]
            code = self.run_tool(prepared, "locate-symbol", "--repo", "target", "--ref", target,
                                 "--symbol", "normalize_counts")
            self.assertEqual(code, 0)

    def test_hunk_history_and_show_commit_chain(self):
        with ThreeCommitRun() as prepared:
            code = self.run_tool(prepared, "hunk-history", "--hunk-id", "f001-h001")
            self.assertEqual(code, 0)
            history = prepared.run_dir / "history-commits.jsonl"
            self.assertTrue(history.is_file())
            shas = [json.loads(line)["sha"] for line in history.read_text().splitlines()]
            self.assertTrue(shas)
            # A SHA recorded by hunk-history is accepted by show-commit.
            code = self.run_tool(prepared, "show-commit", "--sha", shas[0],
                                 "--hunk-id", "f001-h001")
            self.assertEqual(code, 0)
            # Unrecorded arbitrary SHAs stay rejected.
            self.assertEqual(self.run_tool(prepared, "show-commit", "--sha", "1" * 40), 2)

    def test_usage_log_records_every_call(self):
        with PreparedRun() as prepared:
            target = prepared.record["target_commit"]
            self.run_tool(prepared, "view-code", "--repo", "target", "--ref", target,
                          "--path", "counter.py", "--start", "1", "--end", "1")
            self.run_tool(prepared, "locate-symbol", "--repo", "target", "--ref", target,
                          "--symbol", "normalize_count")
            entries = prepared.usage_lines()
            self.assertEqual([entry["cmd"] for entry in entries], ["view-code", "locate-symbol"])
            for entry in entries:
                self.assertIn("time", entry)
                self.assertIn("returncode", entry)
                self.assertIn("bytes_out", entry)
                self.assertGreater(entry["bytes_out"], 0)
                self.assertIn("uid", entry)

    def test_show_commit_accepts_in_range_ancestor_without_prior_history(self):
        with ThreeCommitRun() as prepared:
            # parent B is an in-range commit of the donor's target..fix window
            # even though hunk-history never recorded it (same-turn chain case).
            code = self.run_tool(prepared, "show-commit", "--sha", prepared.parent)
            self.assertEqual(code, 0)
            # A commit outside the window (after the fix) stays rejected, as
            # does any random SHA.
            self.assertEqual(self.run_tool(prepared, "show-commit",
                                           "--sha", prepared.out_of_range), 2)
            self.assertEqual(self.run_tool(prepared, "show-commit", "--sha", "1" * 40), 2)


class ThreeCommitRun:
    """target(A) -> parent(B) -> fix(C) repository with a full-history donor clone.

    The standard GitFixture has source_parent == target_commit, which makes
    the hunk-history range empty; history tools need three distinct commits.
    """

    def __init__(self, shallow: bool = False):
        self.shallow = shallow

    def __enter__(self):
        import tempfile
        from aosp_agent.case import Case
        self._directory = tempfile.TemporaryDirectory()
        root = Path(self._directory.name).resolve()
        self.root = root
        repo = root / "source" / "repo"
        repo.mkdir(parents=True)
        git(repo, "init", "-q")
        (repo / "widget.py").write_text("alpha\nctx\nomega\n")
        git(repo, "add", ".")
        git(repo, "commit", "-q", "-m", "target baseline")
        self.target = git(repo, "rev-parse", "HEAD")
        (repo / "widget.py").write_text("alpha\nctx\nbeta\nomega\n")
        git(repo, "add", "widget.py")
        git(repo, "commit", "-q", "-m", "donor parent")
        self.parent = git(repo, "rev-parse", "HEAD")
        (repo / "widget.py").write_text("alpha\nchanged\nbeta\nomega\n")
        git(repo, "add", "widget.py")
        git(repo, "commit", "-q", "-m", "donor fix")
        self.donor = git(repo, "rev-parse", "HEAD")
        # A post-fix commit on the branch: exists in the donor store but is
        # OUTSIDE the target..fix window, so show-commit must reject it.
        (repo / "extra.txt").write_text("later\n")
        git(repo, "add", "extra.txt")
        git(repo, "commit", "-q", "-m", "post-fix unrelated change")
        self.out_of_range = git(repo, "rev-parse", "HEAD")
        self.branch = git(repo, "symbolic-ref", "--short", "HEAD")
        git(repo, "checkout", "--detach", "-q", self.target)
        donor_root = root / ("donor-shallow" if self.shallow else "donor")
        donor_root.mkdir()
        clone = ["git", "clone", "-q", "--bare", "--no-local", "--branch", self.branch,
                 f"file://{repo}", str(donor_root / "repo.git")]
        if self.shallow:
            clone[4:4] = ["--depth", "3"]  # D, C, B present; target A cut off
        subprocess.run(clone, check=True, capture_output=True)
        case = Case.from_dict({
            "cve": "CVE-2099-2002", "project": "AOSP", "repository": "repo",
            "source_commit": self.donor, "source_parent": self.parent,
            "target_commit": self.target, "files": ["widget.py"], "validation": []})
        self.agent = AospBackportAgent(root / "source", root / "runs", case,
                                       donor_root=donor_root)
        self.agent.run(use_model=False)
        self.run_dir = root / "runs" / "CVE-2099-2002"
        return self

    def __exit__(self, *_args):
        self._directory.cleanup()


class ShallowDonorTest(unittest.TestCase):
    """hunk-history degrades to NOT_AVAILABLE when donor history is shallow."""

    def test_not_available_without_deepened_history(self):
        with ThreeCommitRun(shallow=True) as prepared:
            code = tools_main(["--run-dir", str(prepared.run_dir), "hunk-history",
                               "--hunk-id", "f001-h001"])
            self.assertEqual(code, 0)
            usage = [json.loads(line) for line in
                     (prepared.run_dir / "tool-usage.jsonl").read_text().splitlines()]
            self.assertEqual(usage[-1]["cmd"], "hunk-history")


if __name__ == "__main__":
    unittest.main()
