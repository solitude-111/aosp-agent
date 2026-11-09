"""Project routing/expansion integration without real SDK calls or CVE labels."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aosp_agent import discovery
from aosp_agent.discovery import diff_units
from aosp_agent.project_catalog import Project, ProjectCatalog
from aosp_agent.project_first import ProjectFirstAgent
from engine_fixtures import GitFixture, git, BASELINE, FIXED
from test_diff_workflow import diff, QueueRuntime
from test_scope_evidence import closure_for
from mapped_impact_fixtures import proof_groups_for
import test_diff_workflow as workflow


class ProjectFirstTest(unittest.TestCase):
    def test_initial_routing_semantic_error_is_corrected_before_any_project_read(self):
        with GitFixture() as fx:
            catalog = self.catalog(fx)
            with patch.object(catalog, 'pin', wraps=catalog.pin) as pin:
                runtime = QueueRuntime([(self.plan(['typo-project']), lambda _: self.assertFalse(pin.called)),
                    (self.plan(), lambda _: self.assertFalse(pin.called)), (self.assessment(), None)])
                agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                    runtime_factory=runtime.factory, auto_validation=False)
                result = agent.run(impact_only=True, max_attempts=2)
            self.assertEqual(result['status'], 'AFFECTED', result)
            self.assertEqual(len(runtime.calls), 3)
            self.assertEqual(len(result['routing_rejections']), 1)
            self.assertIn('not in the target catalogue', runtime.calls[1]['prompt'])
            self.assertIn('source_units', runtime.calls[1]['prompt'])

    def test_invalid_routing_exhausts_shared_limits_without_a_full_scan(self):
        for model_limit, expected in ((10, 'ROUTING_UNRESOLVED'), (1, 'BUDGET_EXHAUSTED')):
            with self.subTest(model_limit=model_limit), GitFixture() as fx:
                catalog = self.catalog(fx)
                wrong = self.plan(); wrong['obligations'] = []
                runtime = QueueRuntime([(wrong, None), (wrong, None)])
                agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                    runtime_factory=runtime.factory, max_model_turns=model_limit)
                with patch.object(catalog, 'pin', side_effect=AssertionError('invalid route admitted')):
                    result = agent.run(impact_only=True, max_attempts=2)
                self.assertEqual(result['status'], 'INCONCLUSIVE', result)
                self.assertEqual(result['impact_decision'], 'UNKNOWN')
                self.assertEqual(result['completion_blocked_by'], expected)
                self.assertEqual(result['rounds'], [])
                self.assertEqual(len(runtime.calls), min(model_limit, 2))

    def test_replanning_correction_keeps_admitted_projects_without_another_router(self):
        with GitFixture() as fx:
            catalog = self.catalog(fx, peer=True)
            unresolved = self.assessment()
            unresolved['scope_closure']['units'][0]['unresolved_questions'] = ['Check the counter operation again']
            runtime = QueueRuntime([(self.plan(), None), (unresolved, None), (self.assessment(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                runtime_factory=runtime.factory, auto_validation=False, max_projects=2)
            with patch.object(agent, '_plan', wraps=agent._plan) as route:
                result = agent.run(impact_only=True, max_attempts=2)
            self.assertEqual(result['status'], 'AFFECTED', result)
            self.assertEqual(set(catalog.pins), {'repo'})
            self.assertEqual(route.call_count, 1)
            self.assertEqual(len(runtime.calls), 3)
            self.assertIn('Check the counter operation again', runtime.calls[2]['prompt'])
            self.assertEqual([r['projects'] for r in result['rounds']], [['repo'], ['repo']])
            plan = json.loads((agent.run_dir / 'routing-plan-2.json').read_text())
            self.assertEqual(plan['retained_projects'], ['repo'])

    def test_coverage_replan_repairs_the_prior_assessment_with_precise_blockers(self):
        from aosp_agent.assessment_repair import digest
        with GitFixture() as fx:
            prior = self.assessment()
            correction = {'base_sha256': digest(prior), 'replacements': []}
            runtime = QueueRuntime([(prior, None), (correction, None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, auto_validation=False)
            seen = []

            def backend(controller, assessment, **kwargs):
                seen.append(controller)
                if len(seen) == 1:
                    controller.record.update(status='VALIDATION_FAILED', coverage_blockers=[{
                        'unit_id': 'f001-h001', 'path': 'repo/counter.py', 'symbol': 'normalize_count',
                        'line_start': 1, 'line_end': 2, 'error': 'missing guard at exact target region'}])
                else:
                    controller.record['status'] = 'PATCH_UNVERIFIED'
                controller._save()
                return controller.record

            with patch('aosp_agent.text_backend.run_text_backends', side_effect=backend):
                result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)
            self.assertEqual(len(runtime.calls), 2)
            self.assertIn('missing guard at exact target region', runtime.calls[1]['prompt'])
            self.assertIn(digest(prior), runtime.calls[1]['prompt'])
            self.assertTrue(seen[1].record['assessment_reused_for_coverage_replan'])
            self.assertEqual([r['projects'] for r in result['rounds']], [['repo'], ['repo']])

    def test_causal_retries_reuse_a_grounded_mapping_and_recheck_the_proof(self):
        from aosp_agent.assessment_repair import digest
        from aosp_agent.resume import resume_project
        for resume in (False, True):
            with self.subTest(resume=resume), GitFixture() as fx:
                prior = self.assessment()
                chain = prior['proof_groups'][0]['impact']['causal_chain']
                harm = chain['target_harm_evidence']
                chain['target_harm_evidence'] = [999]
                repair = {'base_sha256': digest(prior), 'replacements': [{
                    'path': '/proof_groups/0/impact/causal_chain/target_harm_evidence',
                    'value_json': json.dumps(harm)}]}
                runtime = QueueRuntime([(prior, None)] + ([] if resume else [(repair, None)]))
                agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                    repository_keys=['repo'], runtime_factory=runtime.factory, max_rounds=1 if resume else 2,
                    auto_validation=False)
                result = agent.run(impact_only=True, max_attempts=1)
                if resume:
                    self.assertEqual(result['impact_decision'], 'UNKNOWN')
                    self.assertIn('grounded_mapping', result)
                    runtime = QueueRuntime([(repair, None)])
                    result = resume_project(agent.run_dir / 'run.json', runtime_factory=runtime.factory)
                self.assertEqual(result['impact_decision'], 'AFFECTED', result)
                self.assertEqual(result['impact_analysis']['status'], 'CONFIRMED')
                self.assertIn('verified mappings and unresolved causal proof', runtime.calls[-1]['prompt'])
                self.assertIn(digest(prior), runtime.calls[-1]['prompt'])

    def test_unconfirmed_coverage_does_not_erase_affect_on_replan_exhaustion(self):
        from aosp_agent.diff_engine import DiffBackportAgent
        with GitFixture() as fx:
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                                     repository_keys=['repo'], max_rounds=2)
            review = {'status': 'UNRESOLVED', 'coverage_gaps': [
                {'obligation_id': 'hold', 'path_id': 'cancellation', 'reason': 'No cleanup evidence.'}]}
            with patch.object(DiffBackportAgent, 'run', side_effect=[
                    {'status': 'VALIDATION_FAILED', 'impact_decision': 'AFFECTED',
                     'repair_obligation_review': review, 'obligation_remap_required': True},
                    {'status': 'INCONCLUSIVE', 'impact_decision': 'UNKNOWN',
                     'replan_required': 'CAUSAL_EVIDENCE_UNRESOLVED'}]):
                result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['repair_obligation_review'], review)

    def test_confirmed_impact_survives_budget_exhaustion_during_migration_replan(self):
        with GitFixture() as fx:
            runtime = QueueRuntime([(self.assessment(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, auto_validation=False,
                max_model_turns=1)

            def backend(controller, assessment, **kwargs):
                self.assertEqual(controller.record['impact_analysis']['status'], 'CONFIRMED')
                controller.record.update(status='VALIDATION_FAILED', replan_required='MIGRATION_MAPPING_UNRESOLVED')
                controller._save()
                return controller.record

            with patch('aosp_agent.text_backend.run_text_backends', side_effect=backend):
                result = agent.run(max_attempts=1)

            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['impact_analysis']['status'], 'CONFIRMED')
            self.assertEqual(result['impact_analysis']['targets'], {'repo': fx.target})
            self.assertEqual(Path(result['impact_analysis']['round_record']).parent.name, 'r01')
            self.assertEqual(result['migration']['status'], 'INTERRUPTED')
            self.assertEqual(result['budget_interruption']['stage'], 'IMPACT_ANALYSIS')
            for phase in ('DISCOVERY', 'IMPACT_ANALYSIS', 'MIGRATION'):
                self.assertGreater(result['stage_read_usage'][phase]['operations'], 0)
                self.assertGreater(result['stage_read_usage'][phase]['git_output_bytes'], 0)
            self.assertEqual(result, json.loads((agent.run_dir / 'run.json').read_text()))

    def catalog(self, fx, peer=False):
        projects = [Project('repo', 'platform/repo', fx.target)]
        if peer:
            root = fx.source_root / 'peer'; root.mkdir(); git(root, 'init', '-q')
            (root / 'helper.py').write_text(BASELINE)
            git(root, 'add', '.'); git(root, 'commit', '-qm', 'peer')
            projects.append(Project('peer', 'platform/peer', git(root, 'rev-parse', 'HEAD')))
        return ProjectCatalog(fx.source_root, projects, {'scope': 'synthetic_pinned_metadata'})

    def source(self):
        return diff('counter.py', BASELINE, FIXED).encode()

    def plan(self, projects=('repo',)):
        return {'summary': 'Inspect the counter operation before choosing migration.',
                'projects': [{'key': k, 'reason': 'Counter source ownership hint'} for k in projects],
                'obligations': [{'unit_id': 'f001-h001', 'security_operation': 'Bound the caller count',
                                 'questions': ['Where is the old counter implementation?']}],
                'unresolved_questions': []}

    def assessment(self, peer=False):
        stub = SimpleNamespace(units=diff_units(self.source().decode()))
        assessment = workflow.DiffWorkflowTest().assessment(stub)
        unit = assessment['units'][0]
        unit['evidence'].append({'origin': 'patch_before', 'path': 'counter.py',
                                'line_start': 1, 'line_end': 2, 'excerpt': BASELINE.strip(), 'claim': 'Donor before'})
        if peer:
            unit['targets'].append({**unit['targets'][0], 'path': 'peer/helper.py', 'action': 'read_dependency'})
            unit['evidence'].append({**unit['evidence'][0], 'path': 'peer/helper.py'})
        assessment['scope_closure'] = closure_for(assessment)
        assessment['proof_groups'] = proof_groups_for(assessment)
        return assessment

    def test_preanalysis_precedes_project_git_reads_and_unrelated_broken_repo_is_untouched(self):
        with GitFixture() as fx:
            catalog = self.catalog(fx)
            broken = fx.source_root / 'unused'; broken.mkdir(); (broken / '.git').write_text('gitdir: missing\n')
            catalog.projects['unused'] = Project('unused', 'platform/unused', 'HEAD')
            reads = []
            original = discovery.local_git
            def traced(root, *args, **kwargs):
                self.assertNotEqual(Path(root), broken)
                reads.append(args)
                return original(root, *args, **kwargs)
            runtime = QueueRuntime([(self.plan(), lambda _: self.assertEqual(reads, [])), (self.assessment(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                                      runtime_factory=runtime.factory, auto_validation=False)
            with patch.object(discovery, 'local_git', side_effect=traced):
                result = agent.run(impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED', result)
            self.assertEqual(result['selected_projects'], ['repo'])
            self.assertEqual(len(runtime.calls), 2)

    def test_grounded_expansion_creates_a_second_round_with_both_projects(self):
        with GitFixture() as fx:
            catalog = self.catalog(fx, peer=True)
            first = self.assessment()
            first.pop('scope_closure')
            first['repository_requests'] = [{'repository': 'peer', 'unit_id': 'f001-h001',
                'reason': 'Inspect the helper counterpart before concluding.', 'evidence': [first['units'][0]['evidence'][0]]}]
            runtime = QueueRuntime([(self.plan(), None), (first, None), (self.assessment(peer=True), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                                      runtime_factory=runtime.factory, auto_validation=False)
            result = agent.run(impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED', result)
            self.assertEqual(result['selected_projects'], ['repo', 'peer'])
            self.assertEqual([r['projects'] for r in result['rounds']], [['repo'], ['repo', 'peer']])
            self.assertEqual(result['model_turns']['used'], 3)
            self.assertFalse((agent.run_dir / 'rounds/r01/workspace').exists())
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_invalid_requested_project_cannot_expand_outside_catalogue(self):
        with GitFixture() as fx:
            first = self.assessment(); first.pop('scope_closure')
            first['repository_requests'] = [{'repository': '../escape', 'unit_id': 'f001-h001',
                'reason': 'Claimed dependency', 'evidence': [first['units'][0]['evidence'][0]]}]
            runtime = QueueRuntime([(self.plan(), None), (first, None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                                      runtime_factory=runtime.factory)
            result = agent.run()
            self.assertEqual(result['status'], 'FAILED')
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(len(result['rounds']), 1)

    def test_backend_dependency_uses_catalogue_pin_not_checkout_head(self):
        with GitFixture() as fx:
            catalog = self.catalog(fx, peer=True)
            pinned = catalog.projects['peer'].revision
            peer = fx.source_root / 'peer'
            (peer / 'helper.py').write_text(FIXED)
            git(peer, 'add', '.'); git(peer, 'commit', '-qm', 'newer unrelated checkout state')
            runtime = QueueRuntime([(self.assessment(peer=True), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                                      repository_keys=['repo', 'peer'], runtime_factory=runtime.factory,
                                      auto_validation=False)
            result = agent.run(impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED', result)
            child = json.loads((agent.run_dir / 'rounds/r01/repositories/repo/run.json').read_text())
            self.assertEqual(child['dependency_repositories']['peer']['head'], pinned)
            self.assertNotEqual(child['dependency_repositories']['peer']['head'], git(peer, 'rev-parse', 'HEAD'))

    def test_open_scope_exhaustion_stays_unknown(self):
        with GitFixture() as fx:
            assessment = self.assessment()
            assessment['scope_closure']['units'][0]['unresolved_questions'] = ['Unresolved external caller']
            runtime = QueueRuntime([(self.plan(), None), (assessment, None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                                      runtime_factory=runtime.factory, max_rounds=1)
            result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'UNKNOWN')
            self.assertEqual(result['completion_blocked_by'], 'REPLANNING_BUDGET_EXHAUSTED')
            self.assertEqual(result['impact_analysis']['status'], 'EVIDENCE_INSUFFICIENT')

    def test_confirmed_causal_path_does_not_wait_for_migration_scope(self):
        with GitFixture() as fx:
            assessment = self.assessment()
            assessment['scope_closure']['units'][0]['migration_questions'] = ['Which test target covers the change?']
            runtime = QueueRuntime([(assessment, None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, max_rounds=1)
            result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['impact_analysis']['status'], 'CONFIRMED')
            self.assertEqual(result['causal_evidence']['status'], 'GROUNDED_CLOSED_POSITIVE_GROUPS')
            self.assertEqual(result['scope_evidence']['migration_questions'][0]['question'],
                             'Which test target covers the change?')
            self.assertEqual(result['migration']['status'], 'INTERRUPTED')
            self.assertFalse((agent.run_dir / 'rounds/r01/workspace').exists())

    def test_output_exhaustion_during_migration_keeps_confirmed_impact(self):
        from aosp_agent.output_budget import write_bytes
        with GitFixture() as fx:
            runtime = QueueRuntime([(self.assessment(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, auto_validation=False,
                max_output_bytes=4 * 1024 * 1024)

            def backend(controller, assessment, **kwargs):
                write_bytes(controller.run_dir / 'sdk-migration.jsonl', b'x' * (4 * 1024 * 1024))

            with patch('aosp_agent.text_backend.run_text_backends', side_effect=backend):
                result = agent.run()
            saved = json.loads((agent.run_dir / 'run.json').read_text())
            for record in (result, saved):
                self.assertEqual(record['status'], 'BLOCKED')
                self.assertEqual(record['delivery_status'], 'BLOCKED')
                self.assertEqual(record['impact_decision'], 'AFFECTED')
                self.assertEqual(record['impact_analysis']['targets'], {'repo': fx.target})
                self.assertEqual(record['budget_interruption']['stage'], 'MIGRATION')
                self.assertEqual(record['migration']['status'], 'INTERRUPTED')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_unrelated_scope_error_does_not_discard_a_grounded_causal_group(self):
        with GitFixture() as fx:
            patch_bytes = self.source() + diff('optional.py', BASELINE, FIXED).encode()
            assessment = self.assessment()
            unit_id = diff_units(patch_bytes.decode())[1]['id']
            assessment['units'].append({**assessment['units'][0], 'id': unit_id, 'status': 'UNKNOWN',
                                        'evidence': [], 'targets': []})
            assessment['scope_closure']['units'].append({
                **assessment['scope_closure']['units'][0], 'unit_id': unit_id, 'evidence': [], 'proof_steps': []})
            assessment['proof_groups'] = proof_groups_for(assessment)
            runtime = QueueRuntime([(assessment, None)])
            agent = ProjectFirstAgent(patch_bytes, fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, max_rounds=1)
            result = agent.run()
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['causal_evidence']['groups'][0]['unit_ids'], ['f001-h001'])
            self.assertIn(unit_id, result['migration_scope_error'])
            self.assertEqual(result['delivery_status'], 'BLOCKED')

    def test_missing_whole_proof_coverage_keeps_the_independent_positive_proof(self):
        with GitFixture() as fx:
            assessment = self.assessment()
            unit = assessment['units'][0]
            dependency = 'repo/check_lower.py'
            unit['targets'].append({
                **unit['targets'][0], 'path': dependency, 'symbol': 'test input dependency',
                'relationship': 'dependency', 'action': 'read_dependency', 'line_start': 1, 'line_end': 1})
            unit['evidence'].append({
                **unit['evidence'][0], 'path': dependency, 'line_start': 1, 'line_end': 1,
                'excerpt': (fx.repo / 'check_lower.py').read_text().splitlines()[0]})
            assessment['scope_closure'] = closure_for(assessment)
            runtime = QueueRuntime([(assessment, None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=runtime.factory, max_rounds=1)
            result = agent.run()
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['scope_evidence']['status'], 'GROUNDED_MODEL_SCOPE')
            self.assertEqual(result['causal_evidence']['status'], 'GROUNDED_CLOSED_POSITIVE_GROUPS')
            self.assertIn('every mapped target region', result['migration_scope_error'])
            self.assertEqual(result['delivery_status'], 'BLOCKED')
            self.assertFalse((agent.run_dir / 'rounds/r01/workspace').exists())

    def test_resume_only_requests_corrections_to_a_checked_pinned_assessment(self):
        from aosp_agent.assessment_repair import digest
        from aosp_agent.diff_prompts import ASSESSMENT_RESPONSE_SCHEMA
        from aosp_agent.resume import resume_project
        with GitFixture() as fx:
            assessment = self.assessment()
            assessment['scope_closure']['units'][0]['migration_questions'] = ['Which test target covers the change?']
            assessment['limitations'] = ['ordinary preserved background ' * 6000]
            first = QueueRuntime([(assessment, None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                repository_keys=['repo'], runtime_factory=first.factory, auto_validation=False, max_rounds=1)
            old = agent.run(max_attempts=1)
            evidence = Path(old['impact_analysis']['round_record']).parent / 'assessment.json'
            saved = json.loads(evidence.read_text())
            prior = {k: v for k, v in saved.items() if k in ASSESSMENT_RESPONSE_SCHEMA['properties']}
            correction = {'base_sha256': digest(prior), 'replacements': [{
                'path': '/scope_closure/units/0/migration_questions', 'value_json': '[]'}]}
            runtime = QueueRuntime([(correction, None)])

            def backend(controller, grounded, **kwargs):
                controller.record.update(status='PATCH_UNVERIFIED')
                controller._save()
                return controller.record

            with patch('aosp_agent.text_backend.run_text_backends', side_effect=backend):
                result = resume_project(agent.run_dir / 'run.json', runtime_factory=runtime.factory)
            self.assertEqual(len(runtime.calls), 1)
            self.assertIn('Which test target covers the change?', runtime.calls[0]['prompt'])
            self.assertIn('accepted-assessment-sections.txt', runtime.calls[0]['prompt'])
            self.assertNotIn(assessment['limitations'][0], runtime.calls[0]['prompt'])
            self.assertEqual(result['impact_decision'], 'AFFECTED')
            self.assertEqual(result['resumption_policy'], 'checked_assessment_repair_and_fresh_candidates')
            self.assertNotEqual(Path(result['impact_analysis']['round_record']).parent, evidence.parent)

    def test_model_turn_exhaustion_is_unknown_and_durable(self):
        with GitFixture() as fx:
            runtime = QueueRuntime([(self.plan(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                                      runtime_factory=runtime.factory, max_model_turns=1)
            result = agent.run()
            self.assertEqual(result['status'], 'INCONCLUSIVE')
            self.assertEqual(result['completion_blocked_by'], 'BUDGET_EXHAUSTED')
            self.assertEqual(result, json.loads((agent.run_dir / 'run.json').read_text()))

    def test_replanning_uses_new_round_records_and_workspaces(self):
        with GitFixture() as fx:
            runtime = QueueRuntime([(self.plan(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                                      runtime_factory=runtime.factory)
            seen, contexts = [], []
            class Executor:
                def __init__(self, patch, target, run_root, **options):
                    self.run_dir = Path(run_root) / options['task_id']; self.run_dir.mkdir(parents=True)
                    seen.append(self.run_dir)
                    contexts.append(options['assessment_context'])
                def run(self, **kwargs):
                    return ({'status': 'INCONCLUSIVE', 'impact_decision': 'UNKNOWN',
                             'replan_required': 'BACKEND_MAPPING_CONFLICT'} if len(seen) == 1 else
                            {'status': 'AFFECTED', 'impact_decision': 'AFFECTED'})
            with patch('aosp_agent.project_first.DiffBackportAgent', Executor):
                result = agent.run(impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED')
            self.assertNotEqual(seen[0], seen[1])
            self.assertIn('BACKEND_MAPPING_CONFLICT', contexts[1])
            self.assertEqual(len(runtime.calls), 1)
