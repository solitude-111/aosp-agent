"""Regression for bounded correction without bypassing evidence gates."""
import copy
import json
import unittest

from aosp_agent.assessment_repair import apply_repair, digest
from aosp_agent.engine import AssessmentError
from aosp_agent.mapping_plan import MappingEvidenceError
from engine_fixtures import GitFixture, BASELINE, git
from test_diff_workflow import QueueRuntime
import test_diff_workflow as workflow
from test_scope_evidence import closure_for
from mapped_impact_fixtures import proof_groups_for


def repair(raw, changes):
    return {'base_sha256': digest(raw), 'replacements': [
        {'path': path, 'value_json': json.dumps(value)} for path, value in changes]}


class AssessmentRepairTest(unittest.TestCase):
    def setup_assessment(self, fx):
        fixture = workflow.DiffWorkflowTest()
        agent = fixture.agent(fx)
        return agent, fixture.assessment(agent)

    def test_qualified_parameter_signatures_still_require_the_function(self):
        with GitFixture() as fx:
            agent, raw = self.setup_assessment(fx)
            for symbol in ('normalize_count(value)', 'Counter.normalize_count(int value)',
                           'Counter::normalize_count(int)', 'Counter#normalize_count'):
                raw['units'][0]['targets'][0]['symbol'] = symbol
                self.assertEqual(agent.ground(raw)['status'], 'AFFECTED')
            for symbol in ('Counter.unknown(int)', 'normalize_count explanation', 'normalize_count() extra'):
                raw['units'][0]['targets'][0]['symbol'] = symbol
                with self.assertRaisesRegex(AssessmentError, 'named function'):
                    agent.ground(raw)

    def test_import_region_is_data_and_constructor_signature_is_accepted(self):
        with GitFixture() as fx:
            source = 'import example.Value;\nclass Counter {\n Counter(int value) {}\n}\n'
            (fx.repo / 'Counter.java').write_text(source)
            git(fx.repo, 'add', 'Counter.java'); git(fx.repo, 'commit', '-qm', 'fixture class')
            agent, raw = self.setup_assessment(fx)
            unit = raw['units'][0]
            target = unit['targets'][0]
            target.update(path='repo/Counter.java', symbol='import block', line_start=1, line_end=1,
                          relationship='data_or_configuration')
            unit['evidence'][0].update(path=target['path'], line_start=1, line_end=1,
                                       excerpt=source.splitlines()[0])
            self.assertEqual(agent.ground(raw)['writable_paths'], ['repo/Counter.java'])
            target['relationship'] = 'same_function'
            with self.assertRaisesRegex(AssessmentError, 'named function'):
                agent.ground(raw)
            target.update(symbol='Counter(int value)', line_start=3, line_end=3)
            unit['evidence'][0].update(line_start=3, line_end=3, excerpt=source.splitlines()[2])
            self.assertEqual(agent.ground(raw)['status'], 'AFFECTED')

    def test_batch_reports_mapping_and_repeated_bad_quotes_together(self):
        with GitFixture() as fx:
            agent, raw = self.setup_assessment(fx)
            unit = agent.units[0]
            raw['units'][0]['evidence'].append({'origin': 'patch_before', 'path': unit['old_path'],
                'line_start': min(unit['before']), 'line_end': max(unit['before']),
                'excerpt': '\n'.join(unit['before'].values()), 'claim': 'Original donor behavior.'})
            raw['scope_closure'] = closure_for(raw)
            raw['proof_groups'] = proof_groups_for(raw)
            raw['units'][0]['targets'][0]['symbol'] = 'invented'
            target = copy.deepcopy(raw['units'][0]['targets'][0]); target['line_end'] = 999
            raw['units'][0]['targets'].append(target)
            for row in (raw['units'][0], raw['scope_closure']['units'][0], raw['proof_groups'][0]['impact']):
                row['evidence'][0]['excerpt'] = 'fabricated quote'
            with self.assertRaises(MappingEvidenceError) as caught:
                agent.ground(raw)
            errors = caught.exception.errors
            self.assertEqual(len(errors), 5)
            self.assertIn('pinned file has 2 lines', errors[1]['error'])
            self.assertEqual(errors[-1]['path'], '/proof_groups/0/impact/evidence/0')

    def test_small_correction_preserves_unchanged_evidence_and_runs_full_grounding(self):
        with GitFixture() as fx:
            agent, raw = self.setup_assessment(fx)
            raw['units'][0]['targets'][0]['symbol'] = 'wrong'
            change = repair(raw, [('/units/0/targets/0/symbol', 'normalize_count')])
            fixed = apply_repair(raw, change)
            self.assertEqual(raw['units'][0]['targets'][0]['symbol'], 'wrong')
            self.assertEqual(fixed['units'][0]['evidence'], raw['units'][0]['evidence'])
            runtime = QueueRuntime([(raw, None), (change, None)])
            agent.factory = runtime.factory
            result = agent.run(max_attempts=2, impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED', result)
            self.assertEqual(len(result['assessment_rejections']), 1)
            self.assertIn('/units/0/targets/0', runtime.calls[1]['prompt'])
            self.assertLess(len(json.dumps(change)), 400)
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertTrue((agent.run_dir / 'assessment-repair-2.json').exists())
            self.assertEqual(json.loads((agent.run_dir / 'assessment-2.json').read_text()), fixed)

    def test_atomic_repair_rejects_stale_unknown_overlapping_and_invalid_paths(self):
        with GitFixture() as fx:
            _, raw = self.setup_assessment(fx)
            original = copy.deepcopy(raw)
            cases = [repair(raw, [('/writable_paths', ['outside'])]),
                     repair(raw, [('/units/-1/status', 'UNKNOWN')]),
                     repair(raw, [('/units/00/status', 'UNKNOWN')]),
                     repair(raw, [('/units/99/status', 'UNKNOWN')]),
                     repair(raw, [('/units/0/missing', 'x')]),
                     repair(raw, [('/units/0/status', 'UNKNOWN'), ('/units', [])]),
                     repair(raw, [('/reasoning~2', 'x')])]
            stale = repair(raw, []); stale['base_sha256'] = 'stale'; cases.append(stale)
            malformed = repair(raw, [('/reasoning', 'x')])
            malformed['replacements'][0]['value_json'] = 'NaN'; cases.append(malformed)
            for change in cases:
                with self.subTest(change=change), self.assertRaises(AssessmentError):
                    apply_repair(raw, change)
                self.assertEqual(raw, original)

    def test_merged_result_cannot_drop_units_or_fake_source(self):
        with GitFixture() as fx:
            agent, raw = self.setup_assessment(fx)
            for changes in ([('/units', [])], [('/units/0/evidence/0/excerpt', 'fake source')]):
                candidate = apply_repair(raw, repair(raw, changes))
                with self.assertRaises(AssessmentError):
                    agent.ground(candidate)
            candidate = apply_repair(raw, repair(raw, [('/scope_closure', closure_for(raw))]))
            self.assertEqual(agent.ground(candidate)['status'], 'AFFECTED')

    def test_bad_correction_does_not_replace_the_last_assessment(self):
        with GitFixture() as fx:
            agent, raw = self.setup_assessment(fx)
            raw['units'][0]['targets'][0]['symbol'] = 'wrong'
            invalid = repair(raw, [('/units/0/targets/0/symbol', 'normalize_count'), ('/status', 'AFFECTED')])
            valid = repair(raw, [('/units/0/targets/0/symbol', 'normalize_count')])
            runtime = QueueRuntime([(raw, None), (invalid, None), (valid, None)])
            agent.factory = runtime.factory
            self.assertEqual(agent.run(max_attempts=3, impact_only=True)['status'], 'AFFECTED')
            self.assertFalse((agent.run_dir / 'assessment-2.json').exists())

