import unittest
import json
import sys
from dataclasses import asdict
from pathlib import Path
import subprocess
from unittest.mock import patch

from aosp_agent.inherit import (extract_hunk_positions, check_function_overlap,
                               analyze_inheritance, compute_tag_diff, InheritanceReadError)
from engine_fixtures import GitFixture, git
from test_diff_workflow import QueueRuntime
from aosp_agent.sdk_runtime import CodexRuntime


class LocalLogRuntime(CodexRuntime):
    """Actual event writer, with no SDK process or network/model request."""
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def start(self, *args, **kwargs): self._log('local_inheritance_fixture')
    def run(self, *args, **kwargs):
        return {'output': dict(verdict='CONDITIONAL', confidence='low',
            tag_diff_summary='fixture', overlap_analysis='fixture',
            tests_to_rerun=['build'], reasoning='fixture')}


class InheritanceDecisionTest(unittest.TestCase):
    def test_input_inside_source_keeps_events_results_and_repeat_runs_external(self):
        with GitFixture() as fx:
            fix = fx.repo / 'input.patch'
            fix.write_text(git(fx.repo, 'diff', fx.target, fx.donor, '--', 'counter.py'))
            before = git(fx.repo, 'status', '--porcelain')
            results = []
            with patch('aosp_agent.sdk_runtime.CodexRuntime', LocalLogRuntime):
                for _ in range(2):
                    results.append(analyze_inheritance('ordinary-fixture', fix, fx.source_root, 'repo',
                        ['counter.py'], fx.target, fx.donor, run_root=fx.run_root))
            self.assertNotEqual(results[0]['result_file'], results[1]['result_file'])
            for result in results:
                self.assertTrue(Path(result['events_file']).is_file())
                self.assertTrue(Path(result['result_file']).is_relative_to(fx.run_root))
                self.assertEqual(json.loads(Path(result['result_file']).read_text()), result)
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), before)

    def test_rejects_source_output_and_symlink_alias_before_writing(self):
        with GitFixture() as fx:
            fix = self.fix(fx)
            alias = fx.root / 'alias'; alias.symlink_to(fx.repo, target_is_directory=True)
            for root in (fx.repo / 'out', alias / 'out'):
                with self.assertRaisesRegex(ValueError, 'outside source_root'):
                    analyze_inheritance('ordinary-fixture', fix, fx.source_root, 'repo',
                                        ['counter.py'], fx.target, fx.target, run_root=root)
            with patch('aosp_agent.inherit.Path.cwd', return_value=fx.repo):
                with self.assertRaisesRegex(ValueError, 'outside source_root'):
                    analyze_inheritance('ordinary-fixture', fix, fx.source_root, 'repo',
                                        ['counter.py'], fx.target, fx.target)
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_cli_honors_inherit_dataset_and_external_output_even_without_model(self):
        with GitFixture() as fx:
            dataset = fx.root / 'case.json'; dataset.write_text(json.dumps(asdict(fx.case())))
            fix = fx.repo / 'input.patch'; fix.write_bytes(self.fix(fx).read_bytes())
            before = git(fx.repo, 'status', '--porcelain')
            args = [sys.executable, '-m', 'aosp_agent', 'inherit', fx.case().cve,
                    '--dataset', str(dataset), '--fix-patch', str(fix), '--source-root', str(fx.source_root),
                    '--tag1', fx.target, '--tag2', fx.target, '--run-root']
            result = subprocess.run(args + [str(fx.run_root)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertTrue(Path(json.loads(result.stdout)['result_file']).is_relative_to(fx.run_root))
            rejected = subprocess.run(args + [str(fx.repo / 'out')], capture_output=True, text=True)
            self.assertEqual(rejected.returncode, 3, rejected.stderr + rejected.stdout)
            self.assertEqual(json.loads(rejected.stdout)['verdict'], 'ERROR')
            failed = subprocess.run(args + [str(fx.run_root), '--tag2', 'missing-tag'], capture_output=True, text=True)
            self.assertEqual(failed.returncode, 3, failed.stderr + failed.stdout)
            error_path = Path(json.loads(failed.stdout)['result_file'])
            self.assertTrue(error_path.is_relative_to(fx.run_root))
            self.assertEqual(json.loads(error_path.read_text())['verdict'], 'ERROR')
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), before)

    def fix(self, fx):
        path = fx.root / 'fix.patch'
        path.write_text(git(fx.repo, 'diff', fx.target, fx.donor, '--', 'counter.py'))
        return path

    def test_git_failure_is_not_empty_success_and_empty_scope_is_rejected(self):
        with patch('aosp_agent.inherit._git', return_value=subprocess.CompletedProcess([], 128, '', 'missing object')):
            with self.assertRaises(InheritanceReadError):
                compute_tag_diff(Path('.'), 'a', 'b', ['counter.py'])
        with self.assertRaises(ValueError):
            compute_tag_diff(Path('.'), 'a', 'b', [])
        with patch('aosp_agent.discovery.local_git', side_effect=subprocess.TimeoutExpired('git', 1)):
            with self.assertRaises(InheritanceReadError):
                compute_tag_diff(Path('.'), 'a', 'b', ['counter.py'])

    def test_nonoverlapping_constant_change_requires_retest(self):
        with GitFixture() as fx:
            baseline = 'LIMIT = 10\n' + '\n' * 25 + 'def bounded(value):\n    return value\n'
            (fx.repo / 'counter.py').write_text(baseline)
            git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'baseline')
            first = git(fx.repo, 'rev-parse', 'HEAD')
            fixed = baseline.replace('return value', 'return min(value, LIMIT)')
            (fx.repo / 'counter.py').write_text(fixed)
            fix = fx.root / 'fix.patch'; fix.write_text(git(fx.repo, 'diff'))
            changed = baseline.replace('LIMIT = 10', 'LIMIT = 1000')
            (fx.repo / 'counter.py').write_text(changed)
            git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'dependency change')
            second = git(fx.repo, 'rev-parse', 'HEAD')
            result = analyze_inheritance('ordinary-fixture', fix, fx.source_root, 'repo', ['counter.py'], first, second, run_root=fx.run_root)
            a, b = {}, {}; exec(fixed, a); exec(changed.replace('return value', 'return min(value, LIMIT)'), b)
            self.assertNotEqual(a['bounded'](100), b['bounded'](100))
            self.assertEqual(result['verdict'], 'RE_TEST')
            self.assertFalse(result['validation_inherited'])

    def test_same_file_in_different_revision_does_not_prove_dependencies_unchanged(self):
        with GitFixture() as fx:
            fix = self.fix(fx)
            (fx.repo / 'build.conf').write_text('configuration changed\n')
            git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'different environment input')
            second = git(fx.repo, 'rev-parse', 'HEAD')
            result = analyze_inheritance('ordinary-fixture', fix, fx.source_root, 'repo', ['counter.py'], fx.target, second, run_root=fx.run_root)
            self.assertEqual(result['verdict'], 'CONDITIONAL')
            self.assertTrue(result['tests_to_rerun'])
            self.assertFalse(result['validation_inherited'])

    def test_same_commit_reports_identity_without_importing_validation(self):
        with GitFixture() as fx:
            result = analyze_inheritance('ordinary-fixture', self.fix(fx), fx.source_root, 'repo',
                                         ['counter.py'], fx.target, fx.target, run_root=fx.run_root)
            self.assertEqual(result['verdict'], 'INHERIT')
            self.assertFalse(result['validation_inherited'])

    def test_model_recommendation_cannot_transfer_unprovided_validation(self):
        with GitFixture() as fx:
            answer = dict(verdict='INHERIT', confidence='high', tag_diff_summary='nearby change',
                overlap_analysis='overlap', tests_to_rerun=[], reasoning='model believes compatible')
            runtime = QueueRuntime([(answer, None)])
            with patch('aosp_agent.sdk_runtime.CodexRuntime', runtime.factory):
                result = analyze_inheritance('ordinary-fixture', self.fix(fx), fx.source_root, 'repo',
                                             ['counter.py'], fx.target, fx.donor, run_root=fx.run_root)
            self.assertEqual(result['model_recommendation'], 'INHERIT')
            self.assertEqual(result['verdict'], 'CONDITIONAL')
            self.assertFalse(result['validation_inherited'])
            self.assertTrue(result['tests_to_rerun'])


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
