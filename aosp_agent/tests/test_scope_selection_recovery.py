"""Selection-table recovery preserves pinned evidence without a new location turn."""
from copy import deepcopy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest

from aosp_agent.assessment_repair import digest
from aosp_agent.impact_proof import AssessmentError
from aosp_agent.location_handoff import (BackendEditSelectionError, backend_scope_feedback,
                                         select_edits)
from engine_fixtures import FIXED, GitFixture, git, write_counter
import test_location_handoff as handoff
import test_project_first as routing


class ScopeSelectionRecoveryTest(unittest.TestCase):
    execute = handoff.LocationHandoffTest.execute

    def test_empty_readonly_edit_reuses_checked_locations_and_impact_across_round_or_resume(self):
        for resume in (False, True):
            with self.subTest(resume=resume), GitFixture() as fx:
                parent = fx.target
                support = 'import org.junit.Before;\n'
                # The donor adds this import, but this separate target already has it.
                git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
                (fx.repo / 'Support.java').write_text(support)
                git(fx.repo, 'add', 'Support.java')
                git(fx.repo, 'commit', '--amend', '--no-edit', '-q')
                fx.donor = git(fx.repo, 'rev-parse', 'HEAD')
                git(fx.repo, 'checkout', '--detach', '-q', parent)
                (fx.repo / 'Support.java').write_text(support)
                git(fx.repo, 'add', 'Support.java')
                git(fx.repo, 'commit', '-qm', 'target already imports Before')
                fx.target = git(fx.repo, 'rev-parse', 'HEAD')
                # Git orders Support.java before counter.py in the donor diff.
                located = handoff.location()
                located['units'][0]['id'] = 'f002-h001'
                located['units'].insert(0, {'id': 'f001-h001', 'targets': [{
                    'path': 'repo/Support.java', 'symbol': 'org.junit.Before',
                    'line_start': 1, 'line_end': 1, 'action': 'read_dependency',
                    'relationship': 'dependency', 'reason': 'The import already exists.'}],
                    'evidence': [{'origin': 'target', 'path': 'repo/Support.java',
                        'line_start': 1, 'line_end': 1, 'excerpt': support.strip(),
                        'claim': 'The import already exists.'}], 'location_notes': 'No import edit needed.'})
                route = routing.ProjectFirstTest().plan()
                route['obligations'][0]['unit_id'] = 'f002-h001'
                route['obligations'].insert(0, {'unit_id': 'f001-h001',
                    'security_operation': 'Test import.', 'questions': ['Is the import already present?']})
                valid_edits = [{'unit_id': 'f002-h001', 'target_indices': [1]}]
                malformed = handoff.impact_reply(fx, 'AFFECTED', [
                    *valid_edits, {'unit_id': 'f001-h001', 'target_indices': []}])
                resolved = handoff.impact_reply(fx, 'AFFECTED', valid_edits)
                del resolved['impact']
                def read_support_then_edit(worktree):
                    from aosp_agent.agent_tools import main
                    backend = worktree.parent.parent / 'repositories/repo'
                    with redirect_stdout(io.StringIO()):
                        self.assertEqual(main(['--run-dir', str(backend), 'view-code', '--repo', 'target',
                            '--ref', fx.target, '--path', 'Support.java', '--start', '1', '--end', '1']), 0)
                    write_counter(FIXED)(worktree)
                result, calls, scopes = self.execute(fx, malformed, located=located,
                    resume=resume, max_rounds=1 if resume else 2,
                    input_changes={'source_parent_sequence': [parent]},
                    agent_options={'max_model_turns': 5, 'report_corrections': 1},
                    turns={'sdk-routing-1.jsonl': [(route, None)]}, extras=[(resolved, None),
                        ('HUNK-RESULT f001-h001 need_not_ported evidence=already_present The exact import already exists.\n'
                         'HUNK-RESULT f002-h001 implemented evidence=ordinary Fixed.', read_support_then_edit)])
                debug_child = json.loads((Path(result['final_round_record']).parent /
                    'repositories/repo/run.json').read_text())
                self.assertEqual(result['status'], 'PATCH_UNVERIFIED', [event for event in debug_child['events']
                    if event.get('event') == 'hunk_result_check_failed'])
                self.assertEqual(result['impact_decision'], 'AFFECTED')
                self.assertEqual(len(calls), 5)
                self.assertEqual(sum(name == 'sdk-location-handoff.jsonl' for name, _ in scopes), 1)
                self.assertIn('/edits/1/target_indices', calls[3]['prompt'])
                self.assertIn('Return only the edit scope', calls[3]['prompt'])
                round_dir = Path(result['final_round_record']).parent
                self.assertTrue(json.loads((round_dir / 'run.json').read_text())['location_reused'])
                child = json.loads((round_dir / 'repositories/repo/run.json').read_text())
                self.assertTrue(child['backend_impact_reused'])
                budget = result['execution_budget']
                self.assertEqual(budget['consumed']['model_calls'], 5)
                self.assertEqual(budget['consumed']['report_corrections'], 1)
                self.assertEqual(budget['consumed']['candidate_turns'], 1)
                self.assertEqual(budget['consumed']['investigation_rounds'], 1 if resume else 2)
                self.assertEqual(budget['limits']['model_calls'], 5)
                self.assertEqual(budget['limits']['report_corrections'], 1)

    def test_malformed_selection_with_real_gap_still_relocates(self):
        with GitFixture() as fx:
            malformed = handoff.impact_reply(fx, 'AFFECTED', [
                {'unit_id': 'f001-h001', 'target_indices': []}])
            malformed['location_gaps'] = ['Check the required return anchor.']
            resolved = handoff.impact_reply(fx, 'AFFECTED', [
                {'unit_id': 'f001-h001', 'target_indices': [1]}])
            del resolved['impact']
            result, calls, scopes = self.execute(fx, malformed, max_rounds=2, turns={
                'sdk-location-handoff.jsonl': [(handoff.location(), None), (handoff.location(), None)]},
                extras=[(resolved, None),
                    ('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED))])
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)
            self.assertEqual(sum(name == 'sdk-location-handoff.jsonl' for name, _ in scopes), 2)
            self.assertEqual(result['execution_budget']['consumed']['investigation_rounds'], 2)

    def test_selection_retry_cannot_add_an_investigation_round(self):
        with GitFixture() as fx:
            malformed = handoff.impact_reply(fx, 'AFFECTED', [
                {'unit_id': 'f001-h001', 'target_indices': []}])
            result, calls, _ = self.execute(fx, malformed, max_rounds=1)
            self.assertEqual(result['completion_blocked_by'], 'REPLANNING_BUDGET_EXHAUSTED')
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['location_handoff']['status'], 'READY')
            self.assertEqual(len(calls), 3)
            self.assertEqual(result['execution_budget']['consumed']['investigation_rounds'], 1)
            self.assertEqual(result['execution_budget']['consumed'].get('candidate_turns', 0), 0)

    def test_scope_only_retry_stops_before_model_when_correction_pool_is_spent(self):
        with GitFixture() as fx:
            malformed = handoff.impact_reply(fx, 'AFFECTED', [
                {'unit_id': 'f001-h001', 'target_indices': []}])
            excerpt = malformed['impact']['evidence'][0]['excerpt']
            malformed['impact']['evidence'][0]['excerpt'] = 'invalid source quotation'
            repair = {'base_sha256': digest(malformed), 'replacements': [
                {'path': '/impact/evidence/0/excerpt', 'value_json': json.dumps(excerpt)}]}
            result, calls, scopes = self.execute(fx, malformed, max_rounds=2, max_attempts=2,
                agent_options={'report_corrections': 1}, extras=[(repair, None),
                    ('must not reach this model turn', None)])
            self.assertEqual(result['completion_blocked_by'], 'BUDGET_EXHAUSTED')
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(len(calls), 4)
            self.assertEqual(sum(name == 'sdk-location-handoff.jsonl' for name, _ in scopes), 1)
            self.assertEqual(result['execution_budget']['consumed']['model_calls'], 4)
            self.assertEqual(result['execution_budget']['consumed']['report_corrections'], 1)
            self.assertEqual(result['execution_budget']['consumed'].get('candidate_turns', 0), 0)

    def test_table_diagnostics_are_precise_and_scope_expansion_is_not_reclassified(self):
        location = handoff.location()
        row = {'unit_id': 'f001-h001', 'target_indices': [1]}
        cases = [([dict(row, target_indices=[])], '/edits/0/target_indices'),
                 ([row, row], '/edits/1/unit_id'),
                 ([dict(row, unit_id='missing')], '/edits/0/unit_id'),
                 ([dict(row, target_indices=[1, 1])], '/edits/0/target_indices')]
        cases.extend(([dict(row, target_indices=[value])], '/edits/0/target_indices/0')
                     for value in (0, -1, 2, True, '1'))
        for edits, pointer in cases:
            with self.subTest(edits=edits), self.assertRaises(BackendEditSelectionError) as raised:
                select_edits(location, {'edits': edits, 'new_files': []})
            self.assertEqual(raised.exception.diagnostic['path'], pointer)
        location['units'][0]['targets'][0]['action'] = 'read_dependency'
        with self.assertRaises(AssessmentError) as raised:
            select_edits(location, {'edits': [row], 'new_files': []})
        self.assertNotIsInstance(raised.exception, BackendEditSelectionError)
        with self.assertRaises(AssessmentError) as raised:
            select_edits(handoff.location(), {'edits': [row], 'new_files': ['repo/new.py']})
        self.assertNotIsInstance(raised.exception, BackendEditSelectionError)

    def test_retry_marker_requires_unchanged_pins_locations_and_no_other_gaps(self):
        location = handoff.location()
        targets = {'repo': 'fixed-pin'}
        receipt = {'status': 'READY', 'targets': targets, 'unmapped_units': []}
        record = {'backend_scope_retry': {'kind': BackendEditSelectionError.kind,
            'targets': targets, 'location_digest': digest(location), 'diagnostic': {'path': '/edits/0'},
            'report': {'location_gaps': [], 'repository_requests': []}}}
        self.assertIsNotNone(backend_scope_feedback(record, location, receipt, targets))
        for changes in ({'location_gaps': ['gap']}, {'scope_requests': [{'repository': 'peer'}]},
                        {'backend_conflicts': ['changed premise']}):
            self.assertIsNone(backend_scope_feedback({**record, **changes}, location, receipt, targets))
        for changes in ({'status': 'RUNNING'}, {'scope': 'READ_ONLY_WITH_GAPS'},
                        {'unmapped_units': ['missing']}, {'targets': {'repo': 'other-pin'}}):
            self.assertIsNone(backend_scope_feedback(record, location, {**receipt, **changes}, targets))
        changed = deepcopy(location); changed['units'][0]['location_notes'] = 'Changed mapping.'
        self.assertIsNone(backend_scope_feedback(record, changed, receipt, targets))
        self.assertIsNone(backend_scope_feedback(record, location, receipt, {'repo': 'other-pin'}))


if __name__ == '__main__':
    unittest.main()
