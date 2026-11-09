"""Pinned structural locations and candidate coverage without case-specific rules."""
from types import SimpleNamespace
import unittest

from aosp_agent.discovery import Repository, diff_units
from aosp_agent.engine import AssessmentError
from aosp_agent.hunk_scope import change_blocks
from aosp_agent.java_regions import JavaSource
from aosp_agent.location_handoff import ground_locations
from aosp_agent.mapped_coverage import _import_evidence, _member_evidence, _method_evidence
from aosp_agent.mapping_plan import MappingPlanner
from engine_fixtures import GitFixture, git
from test_diff_workflow import diff


PATH = 'Reader.java'
QUALIFIED = 'repo/' + PATH


def target(start, end, symbol, relationship='same_function'):
    return {'path': QUALIFIED, 'line_start': start, 'line_end': end, 'symbol': symbol,
            'relationship': relationship, 'action': 'edit', 'reason': 'Check the observed target region.'}


def citation(source, start, end):
    return {'origin': 'target', 'path': QUALIFIED, 'line_start': start, 'line_end': end,
            'excerpt': '\n'.join(source.splitlines()[start - 1:end]), 'claim': 'Pinned target source.'}


class LocationRegionsTest(unittest.TestCase):
    def ground(self, fx, source, patch, targets, evidence, *, donor_after=None):
        (fx.repo / PATH).write_text(source)
        git(fx.repo, 'add', PATH)
        git(fx.repo, 'commit', '-qm', 'pin the Java fixture')
        repo = Repository('repo', fx.repo, git(fx.repo, 'rev-parse', 'HEAD'), {PATH: '100644'})
        donor = {}
        if donor_after is not None:
            (fx.repo / PATH).write_text(donor_after)
            git(fx.repo, 'commit', '-qam', 'verified donor fixture')
            donor = {'status': 'VERIFIED', 'donor_git': str(fx.repo / '.git'),
                     'source_parent': repo.head, 'source_commit': git(fx.repo, 'rev-parse', 'HEAD')}
            git(fx.repo, 'checkout', '--detach', '-q', repo.head)
        units = diff_units(patch)
        self.assertEqual(len(units), 1)
        mapper = MappingPlanner([repo], units)
        controller = SimpleNamespace(units=units, mapper=mapper, _owner=mapper._owner, donor=donor)
        raw = {'primary_repository': 'repo', 'units': [{
            'id': units[0]['id'], 'targets': targets, 'evidence': evidence, 'location_notes': 'Candidate locations.',
        }], 'new_files': [], 'repository_requests': []}
        return ground_locations(controller, raw)['units'][0]['targets']

    def test_import_scope_uses_real_declarations_even_when_reported_as_a_method(self):
        source = ('package demo;\n\nimport demo.A;\nimport demo.B;\n\nclass Reader {\n'
                  '    int read() { return 1; }\n}\n')
        donor = source.replace('import demo.B;', 'import demo.B;\nimport newapi.ModernHelper;')
        donor_patch = diff(PATH, source, donor)
        with GitFixture() as fx:
            region, = self.ground(fx, source, donor_patch, [target(3, 6, 'Reader')],
                                   [citation(source, 3, 4), citation(source, 6, 6)])
        self.assertEqual((region['region_kind'], region['line_start'], region['line_end']), ('imports', 3, 5))
        adapted = donor.replace('newapi.ModernHelper', 'oldapi.CompatibleHelper')
        unrelated = source.replace('return 1;', 'return 2;')
        for candidate, expected in ((donor, True), (adapted, False), (unrelated, None)):
            with self.subTest(expected=expected):
                detail, error = _import_evidence(JavaSource(PATH, source), JavaSource(PATH, candidate),
                    diff_units(diff(PATH, source, candidate)), region, donor_patch)
                if expected is None:
                    self.assertIn('required import changes', error)
                else:
                    self.assertEqual(detail['exact'], expected)
                    self.assertEqual(len(detail['added_imports']), 1)

    def test_renamed_and_split_implementations_keep_their_actual_declarations(self):
        source = ('class Reader {\n    int oldRead(int value) {\n        return value;\n    }\n'
                  '    int oldFallback(int value) {\n        return value + 1;\n    }\n}\n')
        before = 'class Reader {\n    int modernRead(int n) { return n; }\n}\n'
        after = before.replace('return n;', 'return checkValue(n);')
        with GitFixture() as fx:
            regions = self.ground(fx, source, diff(PATH, before, after),
                [target(3, 3, 'modernRead', 'renamed'), target(6, 6, 'checkValue', 'split')],
                [citation(source, 3, 3), citation(source, 6, 6)])
        self.assertEqual([(r['symbol'], r['region_kind']) for r in regions],
                         [('oldRead', 'method'), ('oldFallback', 'method')])
        with GitFixture() as fx, self.assertRaisesRegex(AssessmentError, 'crosses callable boundaries'):
            self.ground(fx, source, diff(PATH, before, after),
                        [target(2, 7, 'modernRead', 'data_or_configuration')], [citation(source, 3, 3)])

    def test_constructor_uses_its_pinned_region_during_coverage(self):
        source = ('class Reader {\n    int value;\n    Reader(int value) {\n'
                  '        this.value = value;\n    }\n}\n')
        candidate = source.replace('this.value = value;', 'this.value = Math.max(0, value);')
        patch = diff(PATH, source, candidate)
        with GitFixture() as fx:
            region, = self.ground(fx, source, patch, [target(4, 4, 'missingHelper')],
                                   [citation(source, 4, 4)])
        self.assertEqual((region['region_kind'], region['symbol']), ('constructor', 'Reader'))
        blocks = [(a, b, {row['new_line'] for row in rows if row['marker'] == '+'})
                  for a, b, rows in change_blocks(patch)]
        detail, error = _method_evidence(JavaSource(PATH, source), JavaSource(PATH, candidate), blocks, region)
        self.assertIsNone(error)
        self.assertEqual(detail['added_executable_lines'], [4])

    def test_missing_helper_uses_member_boundary_and_checks_actual_candidate_placement(self):
        source = ('class Reader {\n    int oldRead(int value) {\n        return value;\n    }\n\n'
                  '    int getMode() {\n        return 1;\n    }\n}\n')
        helper = '    int check(int value) {\n        return Math.max(0, value);\n    }\n\n'
        donor = source.replace('return value;', 'return check(value);').replace('    int getMode()', helper + '    int getMode()')
        with GitFixture() as fx:
            method, insertion = self.ground(fx, source, diff(PATH, source, donor),
                [target(3, 3, 'oldRead'), target(4, 8, 'getMode')],
                [citation(source, 3, 3), citation(source, 4, 8)], donor_after=donor)
        self.assertEqual(method['region_kind'], 'method')
        self.assertEqual(insertion['region_kind'], 'member_insertion')
        self.assertEqual(insertion['insertion_lines'], [5, 6])
        misplaced = source[:-2] + '\n' + helper + '}\n'
        for candidate, accepted in ((donor, True), (misplaced, False)):
            blocks = [(a, b, {row['new_line'] for row in rows if row['marker'] == '+'})
                      for a, b, rows in change_blocks(diff(PATH, source, candidate))]
            detail, _ = _member_evidence(JavaSource(PATH, source), JavaSource(PATH, candidate), blocks, insertion)
            self.assertEqual(bool(detail), accepted)
