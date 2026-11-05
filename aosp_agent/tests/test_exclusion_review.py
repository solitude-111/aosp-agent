"""Generic old/new representation regressions, without CVE labels or exploits."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.engine import AssessmentError
from aosp_agent.exclusion_review import ground_review, review_prompt
from aosp_agent.mapped_run import from_case
from engine_fixtures import BASELINE, FIXED, GitFixture, git
import test_diff_workflow as workflow


ABSENT = 'def normalize_count(value):\n    raise NotImplementedError("count operation disabled")\n'


class ExclusionReviewTest(unittest.TestCase):
    def agent(self, fx, *, absent=False, dataset=False):
        if absent:
            (fx.repo / 'counter.py').write_text(ABSENT)
            git(fx.repo, 'commit', '-qam', 'disable the fixture operation')
        if dataset:
            case = replace(fx.case(), target_commit=git(fx.repo, 'rev-parse', 'HEAD'))
            return from_case(case, fx.source_root, fx.run_root, auto_validation=False,
                             model='writer', mapping_model='mapper')
        return DiffBackportAgent(workflow.diff('new/metrics.py', BASELINE, FIXED).encode(),
                                 fx.source_root, fx.run_root, auto_validation=False,
                                 model='writer', mapping_model='mapper')

    def proposal(self, agent):
        raw = workflow.DiffWorkflowTest().assessment(agent, 'NOT_AFFECTED')
        unit = raw['units'][0]
        unit['absence_basis'] = 'feature_absent'
        content = agent.by_key['repo'].read('counter.py').splitlines()
        unit['evidence'][0]['excerpt'] = '\n'.join(content[:2])
        second = copy.deepcopy(unit['evidence'][0])
        second.update(line_start=2, line_end=2, excerpt=content[1])
        unit['evidence'].append(second)
        return raw

    def review(self, agent, verdict='UNKNOWN', *, key='repo'):
        unit = agent.units[0]
        content = agent.by_key[key].read('counter.py').splitlines()
        evidence = [
            {'origin': 'target', 'path': f'{key}/counter.py', 'line_start': 1, 'line_end': 2,
             'excerpt': '\n'.join(content[:2]), 'claim': 'Existing entry point and value flow.'},
            {'origin': 'target', 'path': f'{key}/counter.py', 'line_start': 2, 'line_end': 2,
             'excerpt': content[1], 'claim': 'Existing operation or rejecting statement.'},
        ]
        for side, origin, path in [('before', 'patch_before', unit['old_path']),
                                   ('after', 'patch_after', unit['new_path'])]:
            evidence.append({'origin': origin, 'path': path,
                'line_start': min(unit[side]), 'line_end': max(unit[side]),
                'excerpt': '\n'.join(unit[side].values()), 'claim': 'Donor count operation and changed bounds.'})
        return {'units': [{
            'id': unit['id'], 'verdict': verdict,
            'security_operation': 'Process a caller supplied count within the allowed bounds.',
            'representation': 'absent' if verdict == 'CONFIRMED_ABSENT' else 'equivalent',
            'old_entrypoint_analysis': 'Inspect the existing normalize_count entry point.',
            'old_state_flow_analysis': 'The entry either returns its input or rejects the operation.',
            'blocking_analysis': 'Only an actual rejection can establish absence; a missing helper cannot.',
            'entrypoint_evidence': [1], 'state_flow_evidence': [1], 'blocking_evidence': [2],
            'donor_evidence': [3, 4], 'evidence': evidence,
            'unresolved_assumptions': [],
        }], 'limitations': ['Synthetic source fixture only.']}

    def wire(self, agent, mapping_replies, review_replies):
        mapping = workflow.QueueRuntime([(r, None) for r in mapping_replies])
        reviewer = workflow.QueueRuntime([(r, None) for r in review_replies])
        options = []
        def factory(**kwargs):
            options.append(kwargs)
            return reviewer if Path(kwargs['events_path']).name.startswith('sdk-exclusion-review-') else mapping
        agent.factory = factory
        return mapping, reviewer, options

    def test_two_excerpts_no_longer_allow_early_negative_without_review(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            proposal = self.proposal(agent)
            # This satisfied the old structural check and exited NOT_AFFECTED.
            self.assertEqual(agent.ground(proposal)['status'], 'NOT_AFFECTED')
            mapping, review, options = self.wire(agent, [proposal], [self.review(agent, 'COUNTERPART_POSSIBLE')])
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(result['exclusion_reviews'][0]['status'], 'REMAP_REQUIRED')
            self.assertFalse(agent.workspace.exists())
            self.assertTrue(all(c['read_only'] for c in mapping.calls + review.calls))
            self.assertEqual([o['model'] for o in options], ['mapper', 'mapper'])
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_found_old_counterpart_returns_to_mapping_instead_of_forcing_affected(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            mapping, reviewer, _ = self.wire(agent,
                [self.proposal(agent), workflow.DiffWorkflowTest().assessment(agent)],
                [self.review(agent, 'COUNTERPART_POSSIBLE')])
            result = agent.run(max_attempts=2, impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED')
            self.assertEqual(len(mapping.calls), 2)
            self.assertEqual(len(reviewer.calls), 1)
            self.assertIn('old-operation counterparts', mapping.calls[1]['prompt'])
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_real_absent_operation_can_pass_in_both_entry_modes(self):
        for dataset in (False, True):
            with self.subTest(dataset=dataset), GitFixture() as fx:
                agent = self.agent(fx, absent=True, dataset=dataset)
                self.wire(agent, [self.proposal(agent)], [self.review(agent, 'CONFIRMED_ABSENT')])
                result = agent.run(max_attempts=1)
                self.assertEqual(result['status'], 'NOT_AFFECTED')
                self.assertEqual(result['exclusion_reviews'][0]['status'], 'CONFIRMED_ABSENT')
                self.assertFalse(agent.workspace.exists())
                stored = json.loads((agent.run_dir / 'exclusion-review-1.json').read_text())
                self.assertEqual(stored['units'][0]['verdict'], 'CONFIRMED_ABSENT')

    def test_unresolved_proof_does_not_become_a_negative_after_attempts_exhaust(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            proposal = self.proposal(agent)
            mapping, reviewer, _ = self.wire(agent, [proposal, proposal], [self.review(agent), self.review(agent)])
            result = agent.run(max_attempts=2)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(len(mapping.calls), 2)
            self.assertEqual(len(reviewer.calls), 2)
            self.assertEqual(len(result['exclusion_reviews']), 2)
            self.assertFalse(agent.children)

    def test_declared_equivalent_representation_cannot_confirm_feature_absence(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            review = self.review(agent, 'CONFIRMED_ABSENT')
            review['units'][0]['representation'] = 'equivalent'
            with self.assertRaisesRegex(AssessmentError, 'absent operation'):
                ground_review(agent, agent.ground(self.proposal(agent)), review)

    def test_unresolved_assumption_cannot_confirm_absence(self):
        with GitFixture() as fx:
            agent = self.agent(fx, absent=True)
            review = self.review(agent, 'CONFIRMED_ABSENT')
            review['units'][0]['unresolved_assumptions'] = ['Unknown external dispatch behavior.']
            with self.assertRaisesRegex(AssessmentError, 'unresolved assumptions'):
                ground_review(agent, agent.ground(self.proposal(agent)), review)

    def test_type_declaration_does_not_prove_old_operation_is_absent(self):
        with GitFixture() as fx:
            (fx.repo / 'types.h').write_text('struct legacy_state {\n    int count;\n};\n')
            git(fx.repo, 'add', 'types.h'); git(fx.repo, 'commit', '-qm', 'legacy data definition')
            agent = self.agent(fx)
            review = self.review(agent, 'CONFIRMED_ABSENT')
            review['units'][0]['evidence'][1].update(path='repo/types.h', line_start=1, line_end=3,
                excerpt='struct legacy_state {\n    int count;\n};')
            with self.assertRaisesRegex(AssessmentError, 'blocking_evidence.*executable'):
                ground_review(agent, agent.ground(self.proposal(agent)), review)

    def test_strings_inside_functions_do_not_count_as_executable_proof(self):
        with GitFixture() as fx:
            content = 'def unrelated():\n    """return if while throw"""\n    pass\n'
            (fx.repo / 'notes.py').write_text(content)
            git(fx.repo, 'add', 'notes.py'); git(fx.repo, 'commit', '-qm', 'nonexecuting notes')
            agent = self.agent(fx)
            review = self.review(agent, 'CONFIRMED_ABSENT')
            review['units'][0]['evidence'][1].update(path='repo/notes.py', line_start=2, line_end=2,
                                                    excerpt='    """return if while throw"""')
            with self.assertRaisesRegex(AssessmentError, 'blocking_evidence.*executable'):
                ground_review(agent, agent.ground(self.proposal(agent)), review)

    def test_invalid_review_evidence_exhausts_to_unknown_and_is_preserved(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            review = self.review(agent, 'CONFIRMED_ABSENT')
            review['units'][0]['evidence'][1]['excerpt'] = 'return missing_oracle_answer'
            self.wire(agent, [self.proposal(agent)], [review])
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertIn('excerpt mismatches', result['exclusion_reviews'][0]['error'])
            self.assertTrue((agent.run_dir / 'exclusion-review-1.json').exists())

    def test_review_must_cover_every_excluded_unit(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            with self.assertRaisesRegex(AssessmentError, 'every proposed'):
                ground_review(agent, agent.ground(self.proposal(agent)), {'units': [], 'limitations': []})

    def test_source_evidence_cannot_be_replaced_by_more_target_quotes(self):
        with GitFixture() as fx:
            agent = self.agent(fx, absent=True)
            review = self.review(agent, 'CONFIRMED_ABSENT')
            review['units'][0]['donor_evidence'] = [1, 2]
            with self.assertRaisesRegex(AssessmentError, 'before/after diff evidence'):
                ground_review(agent, agent.ground(self.proposal(agent)), review)

    def test_counterpart_evidence_can_cross_repository_boundaries(self):
        with GitFixture() as fx:
            git(fx.source_root, 'clone', '-q', str(fx.repo), str(fx.source_root / 'peer'))
            agent = self.agent(fx)
            self.wire(agent, [self.proposal(agent)], [self.review(agent, 'COUNTERPART_POSSIBLE', key='peer')])
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertIn('peer/counter.py', result['exclusion_review_blocked_by'])
            self.assertFalse(agent.workspace.exists())

    def test_review_prompt_has_no_dataset_or_historical_answer(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            agent.record['known_answer'] = 'HIDDEN_REFERENCE_VERDICT'
            prompt = review_prompt(agent, agent.ground(self.proposal(agent)), [])
            self.assertNotIn('HIDDEN_REFERENCE_VERDICT', prompt)
            self.assertIn('prerequisite commit', prompt)
            self.assertIn('across repositories', prompt)

    def test_unreviewed_exclusion_blocks_a_mixed_affected_plan(self):
        with GitFixture() as fx:
            patch = workflow.diff('new/one.py', BASELINE, FIXED) + workflow.diff('new/two.py', BASELINE, FIXED)
            agent = DiffBackportAgent(patch.encode(), fx.source_root, fx.run_root, auto_validation=False)
            proposal = self.proposal(agent)
            second = copy.deepcopy(proposal['units'][0])
            second['id'] = agent.units[1]['id']
            for evidence in second['evidence']:
                if evidence['origin'] != 'target':
                    evidence['path'] = 'new/two.py'
            proposal['units'][0].update(status='AFFECTED', absence_basis='none')
            proposal['units'].append(second)
            review = self.review(agent)
            review['units'][0]['id'] = agent.units[1]['id']
            for evidence in review['units'][0]['evidence']:
                if evidence['origin'] != 'target':
                    evidence['path'] = 'new/two.py'
            self.wire(agent, [proposal], [review])
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertFalse(agent.workspace.exists())
            stored = json.loads((agent.run_dir / 'assessment.json').read_text())
            self.assertEqual([u['status'] for u in stored['units']], ['AFFECTED', 'UNKNOWN'])

    def test_review_turn_still_audits_original_source(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            mapping = workflow.QueueRuntime([(self.proposal(agent), None)])
            reviewer = workflow.QueueRuntime([(self.review(agent),
                lambda cwd: (fx.repo / 'counter.py').write_text(FIXED))])
            agent.factory = lambda **kw: reviewer if 'exclusion-review' in str(kw['events_path']) else mapping
            with self.assertRaisesRegex(RuntimeError, 'original repository changed'):
                agent.run(max_attempts=1)
            self.assertEqual(agent.record['status'], 'FAILED')
