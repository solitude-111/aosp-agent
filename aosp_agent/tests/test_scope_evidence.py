import copy
import unittest

from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.engine import AssessmentError
from aosp_agent.scope_evidence import check_scope
from engine_fixtures import GitFixture, BASELINE, FIXED
from test_diff_workflow import diff
import test_diff_workflow as workflow


def closure_for(assessment):
    return {'units': [{
        'unit_id': u['id'], 'security_operation': u['invariant'],
        'entrypoint_and_flow': 'Caller value flows through the mapped counter.',
        'dependencies_checked': sorted({t['path'].split('/')[0] for t in u['targets']}),
        'unresolved_questions': [], 'evidence': copy.deepcopy(u['evidence']),
        'proof_steps': [{'role': role, 'reasoning': 'The mapped operation is directly visible in this region.',
                         'evidence': ([n for n, e in enumerate(u['evidence'], 1) if e['origin'] == 'target']
                                      if role == 'dependency' else [1])}
                        for role in ('entrypoint', 'state_flow', 'security_condition', 'dependency')],
    } for u in assessment['units']]}


class ScopeEvidenceTest(unittest.TestCase):
    def setup_scope(self, fx):
        agent = DiffBackportAgent(diff('counter.py', BASELINE, FIXED).encode(), fx.repo, fx.run_root,
                                 repository_keys=['repo'], lazy_reads=True)
        assessment = workflow.DiffWorkflowTest().assessment(agent)
        assessment['units'][0]['evidence'].append({
            'origin': 'patch_before', 'path': 'counter.py', 'line_start': 1, 'line_end': 2,
            'excerpt': BASELINE.strip(), 'claim': 'Donor operation before the fix.'})
        assessment['scope_closure'] = closure_for(assessment)
        return agent, assessment

    def test_complete_mapped_obligations_are_grounded_not_formally_proven(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            result = check_scope(agent, agent.ground(assessment), required=True)
            self.assertEqual(result['status'], 'GROUNDED_MODEL_SCOPE')
            self.assertIn('not a whole-program', result['limitation'])

    def test_import_only_unmapped_evidence_cannot_close_scope(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            row = assessment['scope_closure']['units'][0]
            row['evidence'][0].update(path='repo/check_lower.py', line_end=1,
                                      excerpt='from counter import normalize_count')
            with self.assertRaisesRegex(AssessmentError, 'within this unit target mappings'):
                check_scope(agent, assessment, required=True)

    def test_empty_dependency_claim_cannot_close_mapped_project(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            assessment['scope_closure']['units'][0]['dependencies_checked'] = []
            with self.assertRaisesRegex(AssessmentError, 'evidenced mapped projects'):
                check_scope(agent, assessment, required=True)

    def test_missing_security_obligation_cannot_close_scope(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            assessment['scope_closure']['units'][0]['proof_steps'].pop()
            with self.assertRaisesRegex(AssessmentError, 'obligations'):
                check_scope(agent, assessment, required=True)

    def test_source_only_security_obligation_cannot_close_scope(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            assessment['scope_closure']['units'][0]['proof_steps'][2]['evidence'] = [2]
            with self.assertRaisesRegex(AssessmentError, 'mapped target evidence'):
                check_scope(agent, assessment, required=True)

    def test_open_question_blocks_final_scope(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            row = assessment['scope_closure']['units'][0]
            row['unresolved_questions'] = ['Does the cross-project caller preserve the bounds?']
            row['proof_steps'] = []
            self.assertEqual(check_scope(agent, assessment, required=True)['status'], 'OPEN_QUESTIONS')

    def test_expansion_requires_exact_evidence(self):
        with GitFixture() as fx:
            agent, assessment = self.setup_scope(fx)
            assessment.pop('scope_closure')
            evidence = copy.deepcopy(assessment['units'][0]['evidence'][0])
            assessment['repository_requests'] = [{'unit_id': agent.units[0]['id'], 'repository': 'peer',
                                                   'reason': 'Inspect caller', 'evidence': [evidence]}]
            self.assertEqual(check_scope(agent, assessment, required=True)['status'], 'EXPANSION_REQUIRED')
            evidence['excerpt'] = 'invented source'
            with self.assertRaisesRegex(AssessmentError, 'mismatches'):
                check_scope(agent, assessment, required=True)
