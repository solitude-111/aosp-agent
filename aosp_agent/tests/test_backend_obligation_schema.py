"""The handoff constrains model-authored obligations to the controller IDs."""
from pathlib import Path
import json
import unittest

from jsonschema import ValidationError, validate

from aosp_agent.assessment_repair import digest
from aosp_agent.location_handoff import backend_report_schema
from engine_fixtures import FIXED, GitFixture, write_counter
import test_location_handoff as handoff


def obligation(ident):
    return {'id': ident, 'disposition': 'edit', 'target_indices': [1], 'reason': 'Required behavior.'}


class BackendObligationSchemaTest(unittest.TestCase):
    execute = handoff.LocationHandoffTest.execute

    def test_scope_only_schema_allows_only_controller_ids(self):
        allowed = 'f001-h001:guard:1'
        report = {'edits': [], 'repair_obligations': [obligation(allowed)], 'repository_requests': [],
                  'location_gaps': [], 'new_files': [], 'flag_cleanup_support': []}
        schema = backend_report_schema([{'id': allowed}], reused_impact=True)
        validate(report, schema)
        for invalid in ([obligation('f001-h001')], [obligation(allowed), obligation(allowed)]):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                validate({**report, 'repair_obligations': invalid}, schema)
        empty_schema = backend_report_schema([], reused_impact=True)
        validate({**report, 'repair_obligations': []}, empty_schema)
        with self.assertRaises(ValidationError):
            validate(report, empty_schema)
        validate(report, schema)

    def test_inapplicable_obligation_is_corrected_in_existing_report_turn(self):
        with GitFixture() as fx:
            report = handoff.impact_reply(fx, 'AFFECTED',
                                         [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            report['repair_obligations'] = [obligation('f001-h001')]
            repair = {'base_sha256': digest(report), 'replacements': [
                {'path': '/repair_obligations', 'value_json': '[]'},
            ]}
            result, calls, scopes = self.execute(fx, report, max_attempts=2, extras=[
                (repair, None),
                ('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED)),
            ])
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)
            self.assertEqual(sum(name == 'sdk-location-handoff.jsonl' for name, _ in scopes), 1)
            self.assertEqual([call['read_only'] for call in calls], [True, True, True, True, False])
            self.assertIn('/repair_obligations', calls[3]['prompt'])
            round_dir = Path(result['final_round_record']).parent
            child = json.loads((round_dir / 'repositories/repo/run.json').read_text())
            rejection, = child['impact_report_rejections']
            self.assertEqual(rejection['diagnostic']['path'], '/repair_obligations')
            self.assertEqual(rejection['diagnostic']['constraint'], 'maxItems')


if __name__ == '__main__':
    unittest.main()
