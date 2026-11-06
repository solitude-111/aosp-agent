"""Original P4 ledger boundaries, using harmless counter code and real Git diffs."""
from dataclasses import replace
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aosp_agent.engine import AospBackportAgent
from aosp_agent.lifecycle import RecoveryBlocked
from aosp_agent.patches import split_hunks
from engine_fixtures import GitFixture, git


def raw_git(repo, *args):
    # Preserve trailing context whitespace: stripping it corrupts Git hunks.
    return subprocess.check_output(['git', *args], cwd=repo, text=True)


class HunkBoundariesTest(unittest.TestCase):
    baseline = ('#define COUNT_LIMIT 100\n#define clamp_count(n) (n)\n\n'
                'int first(int n) {\n  return n;\n}\n' + '\n' * 12 +
                'int second(int n) {\n  return n;\n}\n')

    def agent(self, fx, baseline=None, fixed=None):
        baseline = baseline or self.baseline
        fixed = fixed or baseline.replace('return n;', 'return clamp_count(n);')
        (fx.repo / 'counts.c').write_text(baseline)
        git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'ordinary counter baseline')
        target = git(fx.repo, 'rev-parse', 'HEAD')
        (fx.repo / 'counts.c').write_text(fixed)
        git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'ordinary counter adaptation')
        donor = git(fx.repo, 'rev-parse', 'HEAD'); git(fx.repo, 'checkout', '--detach', '-q', target)
        case = replace(fx.case(), files=('counts.c',), target_commit=target, source_parent=target, source_commit=donor)
        agent = AospBackportAgent(fx.source_root, fx.run_root, case)
        agent.prepare(); agent.inspect()
        agent._current_hunks = split_hunks(raw_git(fx.repo, 'diff', target, donor))
        (agent.run_dir / 'tool-usage.jsonl').write_text(json.dumps(dict(uid='123456abcdef', cmd='view-code',
            args={'repo': 'target', 'path': 'counts.c'}, returncode=0)) + '\n')
        return agent

    def implemented(self, agent, text, *, context=3):
        (agent.worktree / 'counts.c').write_text(text)
        candidate = raw_git(agent.worktree, 'diff', '--no-ext-diff', '--unified=' + str(context))
        response = '\n'.join('HUNK-RESULT ' + h['id'] + ' implemented adapted site' for h in agent._current_hunks)
        return agent._check_hunk_results(response, ['counts.c'], candidate)

    def excluded(self, agent, category):
        return agent._check_hunk_results('HUNK-RESULT f001-h001 need_not_ported evidence=' + category +
            ' tools=123456abcdef clamp_count', [])

    def test_sibling_hunks_cannot_borrow_one_edit_even_inside_broad_mapping(self):
        for mapped in (False, True):
            with self.subTest(mapped=mapped), GitFixture() as fx:
                agent = self.agent(fx)
                if mapped:
                    region = dict(path='counts.c', action='edit', status='AFFECTED', line_start=1,
                                  line_end=len(self.baseline.splitlines()))
                    agent.mapping_plan = SimpleNamespace(targets=lambda *args, **kwargs: [region])
                with patch.object(agent, '_target_baseline_lines', wraps=agent._target_baseline_lines) as reads:
                    partial = self.implemented(agent, self.baseline.replace('return n;', 'return clamp_count(n);', 1))
                    self.assertFalse(partial['ok'])
                    complete = self.implemented(agent, self.baseline.replace('return n;', 'return clamp_count(n);'))
                    self.assertTrue(complete['ok'], complete['contradictions'])
                    self.assertEqual(reads.call_count, 1)  # Pinned source reused across hunks/retry.
                self.assertEqual((fx.repo / 'counts.c').read_text(), self.baseline)

    def test_separate_change_blocks_within_one_hunk_each_need_an_edit(self):
        baseline = ('int count(int n) {\n  int first = n;\n  log_count(first);\n'
                    '  int second = n;\n  return first + second;\n}\n')
        fixed = baseline.replace('= n;', '= clamp_count(n);')
        with GitFixture() as fx:
            agent = self.agent(fx, baseline, fixed)
            self.assertEqual(len(agent._current_hunks), 1)
            partial = self.implemented(agent, baseline.replace('= n;', '= clamp_count(n);', 1))
            self.assertFalse(partial['ok'])
            self.assertTrue(self.implemented(agent, fixed)['ok'])

    def test_zero_context_candidate_insertion_uses_after_line_position(self):
        baseline = 'int count(int n) {\n  log_count(n);\n  return n;\n}\n'
        fixed = baseline.replace('  return n;', '  n = clamp_count(n);\n  return n;')
        with GitFixture() as fx:
            agent = self.agent(fx, baseline, fixed)
            result = self.implemented(agent, fixed, context=0)
            self.assertTrue(result['ok'], result['contradictions'])

    def test_leading_increment_decrement_lines_are_changes_not_file_headers(self):
        from aosp_agent.engine import _changed_diff_lines
        baseline = 'int count(int n) {\n-- n;\nreturn n;\n}\n'
        fixed = baseline.replace('-- n;', '++ n;')
        with GitFixture() as fx:
            agent = self.agent(fx, baseline, fixed)
            source = agent._current_hunks[0]['patch']
            self.assertEqual(_changed_diff_lines(source, added=False), ['-- n;'])
            self.assertEqual(_changed_diff_lines(source, added=True), ['++ n;'])
            plain = source + '--- a/other.c\n+++ b/other.c\n@@ -1 +1 @@\n-old();\n+new();\n'
            self.assertEqual(_changed_diff_lines(plain, added=True), ['++ n;', 'new();'])
            wrong = self.implemented(agent, baseline.replace('return n;', 'return n + 1;'))
            self.assertFalse(wrong['ok'])
            self.assertTrue(self.implemented(agent, fixed)['ok'])

    def test_unanchored_addition_requires_whole_file_or_precise_mapping(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            agent._current_hunks = [dict(id='f001-h001', path='counts.c',
                patch='@@ -4,0 +5,1 @@\n+  return n;\n')]
            self.assertFalse(self.excluded(agent, 'already_present')['ok'])
            # Mapping the whole file still does not identify the insertion.
            region = dict(path='counts.c', action='edit', status='AFFECTED', line_start=1,
                          line_end=len(self.baseline.splitlines()))
            agent.mapping_plan = SimpleNamespace(targets=lambda *args, **kwargs: [region])
            self.assertFalse(self.excluded(agent, 'already_present')['ok'])
            region.update(line_start=5, line_end=5)
            self.assertTrue(self.excluded(agent, 'already_present')['ok'])
            agent.mapping_plan = None
            agent._current_hunks[0]['patch'] = '@@ -0,0 +1,21 @@\n' + ''.join('+' + s + '\n' for s in self.baseline.splitlines())
            self.assertTrue(self.excluded(agent, 'already_present')['ok'])

    def test_unanchored_addition_order_cannot_be_assembled_from_other_lines(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            region = dict(path='counts.c', action='edit', status='AFFECTED', line_start=4, line_end=5)
            agent.mapping_plan = SimpleNamespace(targets=lambda *args, **kwargs: [region])
            agent._current_hunks = [dict(id='f001-h001', path='counts.c',
                patch='@@ -0,0 +1,2 @@\n+  return n;\n+int first(int n) {\n')]
            self.assertFalse(self.excluded(agent, 'already_present')['ok'])
            agent._current_hunks[0]['patch'] = '@@ -0,0 +1,2 @@\n+int first(int n) {\n+  return n;\n'
            self.assertTrue(self.excluded(agent, 'already_present')['ok'])

    def test_unchanged_top_level_macro_cannot_be_excluded_by_another_macro(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            agent._current_hunks = [dict(id='f001-h001', path='counts.c',
                patch='@@ -1 +1 @@\n-#define COUNT_LIMIT 100\n+#define COUNT_LIMIT 10\n')]
            for category in ('already_present', 'semantic_equivalence'):
                self.assertFalse(self.excluded(agent, category)['ok'])
            result = self.implemented(agent, self.baseline.replace('COUNT_LIMIT 100', 'COUNT_LIMIT 10'))
            self.assertTrue(result['ok'], result['contradictions'])

    def test_metadata_filename_does_not_exempt_executable_changes(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            for name in ('METADATA', 'OWNERS', 'README.version', 'Android.bp'):
                self.assertFalse(agent._is_metadata_hunk(dict(path=name,
                    patch='@@ -1 +1 @@\n-allow_all = true\n+allow_all = false\n')))
            self.assertTrue(agent._is_metadata_hunk(dict(path='OWNERS',
                patch='@@ -1 +1 @@\n-old@example.invalid\n+new@example.invalid\n')))
            self.assertTrue(agent._is_metadata_hunk(dict(path='METADATA',
                patch='@@ -1 +1 @@\n-version: "1.2"\n+version: "1.3"\n')))

    def test_failed_baseline_read_cannot_fall_back_to_filewide_tokens(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            original = agent._git
            def failed(*args, **kwargs):
                if args[0] == 'show': return subprocess.CompletedProcess(args, 128, '', 'object temporarily unreadable')
                return original(*args, **kwargs)
            with patch.object(agent, '_git', side_effect=failed):
                with self.assertRaises(RecoveryBlocked):
                    self.implemented(agent, self.baseline.replace('return n;', 'return clamp_count(n);'))

    def test_already_present_requires_same_path_not_just_same_function(self):
        base = ('int clamp_count(int n) { return n < 0 ? 0 : (n > 10 ? 10 : n); }\n'
                'int count(int n) {\n  if (n < 0) {\n    n = clamp_count(n);\n'
                '  } else {\n    n = n;\n  }\n  return n;\n}\n')
        for covered in (False, True):
            with self.subTest(covered=covered), GitFixture() as fx:
                baseline = base.replace('    n = n;', '    n = clamp_count(n);\n    n = n;') if covered else base
                fixed = baseline.replace('    n = n;', '    n = clamp_count(n);')
                agent = self.agent(fx, baseline, fixed)
                result = self.excluded(agent, 'already_present')
                self.assertEqual(result['ok'], covered, result['contradictions'])

    def test_already_present_requires_all_lines_in_the_change_block(self):
        baseline = ('int count(int n) {\n  n = clamp_count(n);\n  n = n;\n  return n;\n}\n')
        fixed = baseline.replace('  n = n;', '  n = clamp_count(n);\n  n = n / 2;')
        with GitFixture() as fx:
            agent = self.agent(fx, baseline, fixed)
            result = self.excluded(agent, 'already_present')
            self.assertFalse(result['ok'])
            self.assertIn('complete ordered change block', '\n'.join(result['contradictions']))

    def test_complete_conditional_guard_before_anchor_can_be_already_present(self):
        guard = '  if (n > 10) {\n    n = 10;\n  }\n'
        baseline = 'int count(int n) {\n' + guard + '  return n;\n}\n'
        fixed = baseline.replace('  return n;', guard + '  return n;')
        with GitFixture() as fx:
            agent = self.agent(fx, baseline, fixed)
            result = self.excluded(agent, 'already_present')
            self.assertTrue(result['ok'], result['contradictions'])


if __name__ == '__main__': unittest.main()
