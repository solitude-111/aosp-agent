"""Shared source coordinates: real Git output and cross-consumer regressions."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from aosp_agent.discovery import diff_units
from aosp_agent.engine import _changed_diff_lines, _context_diff_lines
from aosp_agent.hunk_groups import review_groups
from aosp_agent.hunk_scope import changed_lines_in_region
from aosp_agent.hunk_sites import old_chunks
from aosp_agent.impact_proof import CausalityChecks
from aosp_agent.integration import added_numbers
from aosp_agent.patches import split_hunks, text_hunks
from aosp_agent.validation_plan import added_lines


class PatchCoordinatesTest(unittest.TestCase):
    def test_real_git_rename_mode_change_and_distant_edits_keep_coordinates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', *args], cwd=root, text=True)
            git('init', '-q')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            baseline = ['int first(int count) {', '-- count;', 'return count;', '}']
            baseline += ['// unchanged counter documentation ' + str(i) for i in range(30)]
            baseline += ['int second(int count) {', 'return count;', '}']
            (root / 'old.c').write_text('\n'.join(baseline) + '\n')
            git('add', '.'); git('commit', '-qm', 'counter baseline')
            git('mv', 'old.c', 'new.c')
            fixed = list(baseline)
            fixed[1] = '++ count;'
            fixed[-2] = 'return count + 1;'
            (root / 'new.c').write_text('\n'.join(fixed) + '\n')
            (root / 'new.c').chmod(0o755)
            git('add', '.')
            patch = git('diff', '--cached', '--find-renames', '--unified=0')
            unit, = diff_units(patch)
            self.assertEqual(unit['kind'], 'whole_file')
            self.assertEqual(unit['hunk_count'], 2)
            self.assertEqual((unit['old_path'], unit['new_path']), ('old.c', 'new.c'))
            self.assertEqual(unit['before'], {2: '-- count;', 36: 'return count;'})
            self.assertEqual(unit['after'], {2: '++ count;', 36: 'return count + 1;'})
            for revision in ('source_parent', 'source_fix'):
                self.assertEqual(CausalityChecks._changed_hunk_lines(unit, revision), {2, 36})
            self.assertEqual(added_numbers([unit]), {2, 36})
            self.assertEqual(added_lines(unit), [{'line': 2, 'text': '++ count;'},
                                               {'line': 36, 'text': 'return count + 1;'}])

    def test_header_looking_code_and_next_file_headers_are_separate(self):
        patch = ('--- a/first.c\n+++ b/first.c\n@@ -2 +2 @@\n--- count;\n+++ count;\n'
                 '--- a/second.c\n+++ b/second.c\n@@ -30 +40 @@\n-old_count();\n+new_count();\n'
                 '-- \n2.0\n')
        self.assertEqual(_changed_diff_lines(patch, False), ['-- count;', 'old_count();'])
        self.assertEqual(_changed_diff_lines(patch, True), ['++ count;', 'new_count();'])
        self.assertEqual(_context_diff_lines(patch), [])
        chunks = old_chunks(patch)
        self.assertEqual([chunk['old'] for chunk in chunks], [['-- count;'], ['old_count();']])
        self.assertEqual([chunk['blocks'][0]['added'] for chunk in chunks],
                         [['++ count;'], ['new_count();']])
        self.assertEqual(changed_lines_in_region(patch, 2, 2, added=True), ['++ count;'])
        self.assertEqual(changed_lines_in_region(patch, 30, 30, added=True), ['new_count();'])

    def test_newline_markers_and_blank_content_do_not_shift_evidence(self):
        patch = ('--- a/f\n+++ b/f\n@@ -4,2 +7,3 @@\n \n--- count;\n'
                 '\\ No newline at end of file\n+++ count;\n+return count;\n'
                 '\\ No newline at end of file\n')
        unit, = diff_units(patch)
        self.assertEqual(unit['before'], {4: '', 5: '-- count;'})
        self.assertEqual(unit['after'], {7: '', 8: '++ count;', 9: 'return count;'})
        self.assertEqual(CausalityChecks._changed_hunk_lines(unit, 'source_parent'), {5})
        self.assertEqual(CausalityChecks._changed_hunk_lines(unit, 'source_fix'), {8, 9})
        self.assertEqual(added_numbers([unit]), {8, 9})

    def test_pure_insert_delete_and_context_only_side_do_not_invent_zero_lines(self):
        insert = {'patch': '@@ -3,0 +4 @@\n+check_count();\n'}
        delete = {'patch': '@@ -4 +3,0 @@\n-check_count();\n'}
        for unit, empty, changed in ((insert, 'source_parent', 'source_fix'),
                                     (delete, 'source_fix', 'source_parent')):
            self.assertEqual(CausalityChecks._changed_hunk_lines(unit, empty), set())
            self.assertEqual(CausalityChecks._changed_hunk_lines(unit, changed), {4})
        self.assertEqual(changed_lines_in_region(insert['patch'], 4, 4, added=True), ['check_count();'])
        self.assertEqual(changed_lines_in_region(insert['patch'], 3, 3, added=True), [])
        contextual = {'patch': '@@ -3 +3,2 @@\n prepare_count();\n+check_count();\n'}
        self.assertEqual(CausalityChecks._changed_hunk_lines(contextual, 'source_parent'), {3})
        self.assertEqual(CausalityChecks._changed_hunk_lines(contextual, 'source_fix'), {4})

    def test_metadata_without_text_has_no_causal_line_credit(self):
        for patch in ('diff --git a/a.c b/b.c\nrename from a.c\nrename to b.c\n',
                      'diff --git a/a.c b/a.c\nold mode 100644\nnew mode 100755\n'):
            unit, = split_hunks(patch)
            self.assertEqual(text_hunks(patch), [])
            self.assertEqual(CausalityChecks._changed_hunk_lines(unit, 'source_fix'), set())
            self.assertEqual(added_numbers([unit]), set())
            self.assertEqual(added_lines(unit), [])

    def test_context_cannot_replace_delta_in_another_whole_file_hunk(self):
        patch = ('diff --git a/a.c b/b.c\nrename from a.c\nrename to b.c\n'
                 '--- a/a.c\n+++ b/b.c\n@@ -2 +2,2 @@\n keep();\n+prepare();\n'
                 '@@ -30 +31 @@\n-old_count();\n+new_count();\n')
        unit, = diff_units(patch)
        # The first hunk's unchanged parent context is not the fault delta of
        # this whole-file unit when another actual parent-side edit exists.
        self.assertEqual(CausalityChecks._changed_hunk_lines(unit, 'source_parent'), {30})
        self.assertEqual(CausalityChecks._changed_hunk_lines(unit, 'source_fix'), {3, 31})

    def test_review_navigation_keeps_operator_code_and_original_patch_line(self):
        patch = '--- a/f.c\n+++ b/f.c\n@@ -2 +2 @@\n--- limit;\n+++ limit;\n'
        report = review_groups(split_hunks(patch))
        evidence = report['entries'][0]['hint_evidence']
        self.assertEqual({e['text'] for e in evidence}, {'--- limit;', '+++ limit;'})
        for e in evidence:
            self.assertEqual(patch.splitlines()[e['patch_line'] - 1], e['text'])
        self.assertFalse(report['exclusion_authority'])

    def test_truncated_hunks_are_rejected_by_every_line_consumer(self):
        patch = '@@ -1,2 +1,2 @@\n-old_count();\n+new_count();\n'
        unit = {'patch': patch}
        consumers = [lambda: text_hunks(patch), lambda: _changed_diff_lines(patch, True),
                     lambda: _context_diff_lines(patch), lambda: old_chunks(patch),
                     lambda: changed_lines_in_region(patch, 1, 5, added=True),
                     lambda: CausalityChecks._changed_hunk_lines(unit, 'source_fix'),
                     lambda: added_lines(unit), lambda: added_numbers([unit])]
        for number, consumer in enumerate(consumers):
            with self.subTest(consumer=number), self.assertRaisesRegex(ValueError, 'truncated hunk'):
                consumer()

    def test_renamed_source_repair_passes_grounded_mapped_causal_validation(self):
        from engine_fixtures import GitFixture
        from test_mapped_impact import MappedImpactTest
        from aosp_agent.mapped_impact import check_impact_proofs
        with GitFixture() as fx:
            controller, assessment = MappedImpactTest().setup_proofs(fx)
            old = controller.units[0]
            patch = old['patch'].replace('diff --git a/counter.py b/counter.py',
                'diff --git a/counter.py b/counter_v2.py\nrename from counter.py\nrename to counter_v2.py')
            patch = patch.replace('+++ b/counter.py', '+++ b/counter_v2.py')
            unit, = diff_units(patch)
            unit.update(id=old['id'], source_id=old['source_id'])
            controller.units[0] = unit
            for entry in assessment['units'][0]['evidence']:
                if entry['origin'] == 'patch_after': entry['path'] = 'counter_v2.py'
            for entry in assessment['proof_groups'][0]['impact']['evidence']:
                if entry['revision'] == 'source_fix': entry['path'] = 'counter_v2.py'
            result = check_impact_proofs(controller, controller.ground(assessment), required=True)
            self.assertEqual(result['status'], 'GROUNDED_CAUSAL_PROOFS')
