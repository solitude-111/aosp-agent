"""Counterexamples for causal proof provenance and complete repair coverage."""
import copy
import unittest
from unittest.mock import patch

from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.impact_proof import CausalityChecks
from aosp_agent.mapped_impact import ImpactProofError, check_impact_proofs
from aosp_agent.mapping_plan import _shape
from aosp_agent.diff_prompts import ASSESSMENT_SCHEMA
from aosp_agent.project_first import ProjectFirstAgent
from engine_fixtures import GitFixture, BASELINE, PARTIAL, FIXED, CHECK_LOWER
from test_diff_workflow import diff, QueueRuntime
from mapped_impact_fixtures import proof_groups_for
import test_project_first as routing


class MappedImpactTest(unittest.TestCase):
    def setup_proofs(self, fx, *, support=False):
        content = diff('counter.py', BASELINE, PARTIAL)
        content += (diff('check_lower.py', CHECK_LOWER, CHECK_LOWER + 'assert normalize_count(5) == 5\n') if support
                    else diff('counter.py', PARTIAL, FIXED))
        controller = DiffBackportAgent(content.encode(), fx.repo, fx.run_root,
                                       repository_keys=['repo'], lazy_reads=True)
        rows = []
        for number, unit in enumerate(controller.units, 1):
            unit['id'] = f's{number:03}:' + unit['id']
            unit['source_id'] = f's{number:03}'
            is_test = support and number == 2
            target = CHECK_LOWER if is_test else BASELINE
            target_path = 'repo/check_lower.py' if is_test else 'repo/counter.py'
            evidence = [{'origin': 'target', 'path': target_path, 'line_start': 1,
                         'line_end': len(target.splitlines()), 'excerpt': target.strip(), 'claim': 'Original target behavior'}]
            for side, origin, path in (('before', 'patch_before', unit['old_path']), ('after', 'patch_after', unit['new_path'])):
                evidence.append({'origin': origin, 'path': path, 'line_start': min(unit[side]),
                    'line_end': max(unit[side]), 'excerpt': '\n'.join(unit[side].values()), 'claim': 'Exact source step'})
            rows.append({'id': unit['id'], 'status': 'AFFECTED', 'invariant': 'Bound ordinary counter values.',
                'reasoning': 'The counter repair and its normal regression belong together.', 'absence_basis': 'none',
                'candidate_resolution': 'The mapped target contains the counter operation.', 'evidence': evidence,
                'targets': [{'path': target_path, 'symbol': 'normalize_count', 'line_start': 1,
                    'line_end': len(target.splitlines()), 'action': 'edit', 'relationship': 'test' if is_test else 'same_function',
                    'reason': 'Counter operation or its direct imported regression.'}]})
        assessment = {'units': rows, 'new_files': [], 'reasoning': 'Both source steps remain explicit.', 'limitations': []}
        assessment['proof_groups'] = proof_groups_for(assessment)
        # The mapper must use the namespaced units as well.
        controller.mapper.units = controller.units
        return controller, assessment

    def merge_groups(self, assessment, support=False):
        first, second = copy.deepcopy(assessment['proof_groups'])
        offset = len(first['impact']['evidence'])
        first['unit_ids'] += second['unit_ids']
        first['impact']['evidence'] += second['impact']['evidence']
        if support:
            first['support_links'] = [{'unit_id': second['unit_ids'][0], 'supports': first['primary_unit_ids'],
                'reason': 'The regression imports and checks the repaired counter function.',
                'evidence': [1] + list(range(offset + 1, offset + len(second['impact']['evidence']) + 1))}]
        else:
            first['primary_unit_ids'] += second['primary_unit_ids']
            for key in ('donor_fault_evidence', 'donor_fix_evidence', 'target_fault_evidence', 'target_harm_evidence'):
                first['impact']['causal_chain'][key] += [offset + i for i in second['impact']['causal_chain'][key]]
            for step, other in zip(first['impact']['proof_steps'], second['impact']['proof_steps']):
                step['evidence'] += [offset + i for i in other['evidence']]
        assessment['proof_groups'] = [first]

    def test_namespaced_core_repairs_use_the_same_causal_rules(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx)
            _shape(assessment, ASSESSMENT_SCHEMA)
            original, calls = CausalityChecks._validate_impact_causality, []
            def checked(owner, proof):
                calls.append(type(owner).__name__)
                return original(owner, proof)
            with patch.object(CausalityChecks, '_validate_impact_causality', checked):
                result = check_impact_proofs(controller, controller.ground(assessment), required=True)
            self.assertEqual(calls, ['MappedProofChecks', 'MappedProofChecks'])
            self.assertEqual(result['status'], 'GROUNDED_CAUSAL_PROOFS')
            self.assertEqual(len(result['groups']), 2)

    def test_supporting_regression_keeps_own_evidence_and_core_link(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx, support=True)
            self.merge_groups(assessment, support=True)
            _shape(assessment, ASSESSMENT_SCHEMA)
            result = check_impact_proofs(controller, controller.ground(assessment), required=True)
            self.assertEqual(result['groups'][0]['support_units'], [controller.units[1]['id']])

    def test_missing_duplicate_or_uncovered_units_are_rejected(self):
        for mode in ('missing', 'duplicate', 'empty'):
            with self.subTest(mode=mode), GitFixture() as fx:
                controller, assessment = self.setup_proofs(fx)
                if mode == 'missing':
                    assessment['proof_groups'].pop()
                elif mode == 'duplicate':
                    assessment['proof_groups'][1] = copy.deepcopy(assessment['proof_groups'][0])
                else:
                    assessment['proof_groups'] = []
                with self.assertRaisesRegex(ImpactProofError, 'every source unit exactly once'):
                    check_impact_proofs(controller, assessment, required=True)

    def test_same_path_cannot_borrow_another_source_namespace(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx)
            second = assessment['proof_groups'][1]['impact']
            second['evidence'][1]['unit_id'] = controller.units[0]['id']
            with self.assertRaisesRegex(ImpactProofError, 'another source unit/group'):
                check_impact_proofs(controller, assessment, required=True)

    def test_context_only_donor_quote_cannot_prove_fix_causality(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx)
            donor = assessment['proof_groups'][0]['impact']['evidence'][1]
            donor.update(line_start=1, line_end=1, excerpt='def normalize_count(value):')
            with self.assertRaisesRegex(ImpactProofError, 'changed lines'):
                check_impact_proofs(controller, assessment, required=True)

    def test_each_primary_needs_its_own_fault_fix_and_harm_roles(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx)
            self.merge_groups(assessment)
            impact = assessment['proof_groups'][0]['impact']
            impact['causal_chain']['target_harm_evidence'] = [1]
            with self.assertRaisesRegex(ImpactProofError, 'own causal role'):
                check_impact_proofs(controller, assessment, required=True)

    def test_framework_assumptions_are_rejected_by_shared_gate(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx)
            assessment['proof_groups'][0]['impact']['causal_chain']['external_behavior_assumptions'] = ['Trust an unseen caller']
            with self.assertRaisesRegex(ImpactProofError, 'uncited repository/framework behavior'):
                check_impact_proofs(controller, assessment, required=True)

    def test_support_cycles_missing_source_or_missing_core_endpoint_are_rejected(self):
        for mode in ('cycle', 'no_primary', 'missing_source', 'missing_core'):
            with self.subTest(mode=mode), GitFixture() as fx:
                controller, assessment = self.setup_proofs(fx, support=True)
                self.merge_groups(assessment, support=True)
                group = assessment['proof_groups'][0]; link = group['support_links'][0]
                if mode == 'cycle':
                    link['supports'] = [link['unit_id']]
                elif mode == 'no_primary':
                    group['primary_unit_ids'] = []
                elif mode == 'missing_source':
                    link['evidence'] = [1, 4]
                else:
                    link['evidence'] = [4, 5, 6]
                with self.assertRaises(ImpactProofError):
                    check_impact_proofs(controller, assessment, required=True)

    def test_proof_status_cannot_override_mapping_status(self):
        with GitFixture() as fx:
            controller, assessment = self.setup_proofs(fx)
            assessment['proof_groups'][0]['impact']['status'] = 'NOT_AFFECTED'
            with self.assertRaisesRegex(ImpactProofError, 'conflicts'):
                check_impact_proofs(controller, assessment, required=True)

    def test_missing_proof_stops_before_candidate_creation(self):
        with GitFixture() as fx:
            fixture = routing.ProjectFirstTest()
            assessment = fixture.assessment(); assessment.pop('proof_groups')
            runtime = QueueRuntime([(assessment, None)])
            agent = ProjectFirstAgent(fixture.source(), fx.source_root, fx.run_root, catalog=fixture.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, max_rounds=1)
            with patch.object(DiffBackportAgent, '_prepare_children', side_effect=AssertionError('ungrounded migration')):
                result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'INCONCLUSIVE', result)
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(result['causal_evidence']['status'], 'UNRESOLVED')
            self.assertFalse((agent.run_dir / 'rounds/r01/workspace').exists())
