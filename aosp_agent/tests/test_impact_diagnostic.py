"""Repeated file citations retain exact rejection locations and full rechecks."""
from copy import deepcopy
import json
import unittest

from aosp_agent.assessment_repair import apply_repair, digest, repair_prompt
from aosp_agent.engine import AospBackportAgent
from aosp_agent.impact_proof import AssessmentError, assessment_diagnostic, evidence_error
from aosp_agent.prompts import IMPACT_SCHEMA
from engine_fixtures import BASELINE, FIXED, GitFixture


class ImpactDiagnosticTest(unittest.TestCase):
    def test_untyped_compatibility_error_does_not_guess_first_same_file_entry(self):
        raw = {'impact': {'evidence': [
            {'revision': 'target', 'path': 'same/File.java', 'line_start': 10, 'line_end': 11},
            {'revision': 'target', 'path': 'same/File.java', 'line_start': 20, 'line_end': 21}]}}
        message = 'evidence excerpt does not exist in target:same/File.java:20-21'
        fallback = assessment_diagnostic(AssessmentError(message), raw, wrapped=True)
        self.assertEqual(fallback['path'], '/impact/evidence')
        exact = assessment_diagnostic(evidence_error(message, 1, 'excerpt'), raw, wrapped=True)
        self.assertEqual(exact['path'], '/impact/evidence/1/excerpt')
        self.assertIn('/impact/evidence/1/excerpt', repair_prompt(raw, json.dumps(exact)))

    def test_grounding_identifies_actual_entry_and_field_across_repeated_paths(self):
        with GitFixture() as fixture:
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case())
            agent.prepare()
            cases = [({'excerpt': 'return absent_value'}, 'excerpt'),
                     ({'line_end': 999}, 'line_end'),
                     ({'path': 'outside.py'}, 'path'),
                     ({'revision': 'target', 'path': 'missing.py'}, 'path')]
            for updates, field in cases:
                with self.subTest(updates=updates):
                    raw = fixture.assessment()
                    raw['evidence'][2].update(updates)
                    with self.assertRaises(AssessmentError) as raised:
                        agent._ground_assessment(deepcopy(raw))
                    diagnostic = assessment_diagnostic(raised.exception, {'impact': raw}, wrapped=True)
                    self.assertEqual(diagnostic['path'], '/impact/evidence/2/' + field)
                    self.assertEqual(diagnostic['category'], 'EVIDENCE_UNGROUNDED')

    def test_repair_may_fix_another_entry_but_does_not_skip_rejected_evidence(self):
        with GitFixture() as fixture:
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case())
            agent.prepare()
            agent._current_hunks = agent.inspect()['hunks']
            raw = fixture.assessment()
            raw['evidence'][2]['excerpt'] = 'return missing_donor_behavior'
            raw['evidence'].append({**raw['evidence'][0], 'excerpt': 'return missing_target_behavior'})
            donor_fixed = apply_repair(raw, {'base_sha256': digest(raw), 'replacements': [
                {'path': '/evidence/2/excerpt', 'value_json': json.dumps(FIXED.rstrip('\n'))}]},
                schema=IMPACT_SCHEMA)
            with self.assertRaises(AssessmentError) as same_revision:
                agent._ground_assessment(deepcopy(donor_fixed))
            self.assertEqual(assessment_diagnostic(same_revision.exception, donor_fixed)['path'],
                             '/evidence/3/excerpt')
            other = apply_repair(raw, {'base_sha256': digest(raw), 'replacements': [
                {'path': '/evidence/3/excerpt', 'value_json': json.dumps(BASELINE.rstrip('\n'))}]},
                schema=IMPACT_SCHEMA)
            with self.assertRaises(AssessmentError) as raised:
                agent._ground_assessment(deepcopy(other))
            self.assertEqual(assessment_diagnostic(raised.exception, other)['path'], '/evidence/2/excerpt')
            corrected = apply_repair(other, {'base_sha256': digest(other), 'replacements': [
                {'path': '/evidence/2/excerpt', 'value_json': json.dumps(FIXED.rstrip('\n'))}]},
                schema=IMPACT_SCHEMA)
            self.assertEqual(agent._ground_assessment(deepcopy(corrected))['status'], 'AFFECTED')


if __name__ == '__main__':
    unittest.main()
