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

    def test_replanning_correction_accounts_for_already_admitted_projects(self):
        with GitFixture() as fx:
            catalog = self.catalog(fx, peer=True)
            unresolved = self.assessment()
            unresolved['scope_closure']['units'][0]['unresolved_questions'] = ['Check the counter operation again']
            runtime = QueueRuntime([(self.plan(), None), (unresolved, None),
                (self.plan(['peer']), None), (self.plan(), None), (self.assessment(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=catalog,
                runtime_factory=runtime.factory, auto_validation=False, max_projects=1)
            result = agent.run(impact_only=True, max_attempts=2)
            self.assertEqual(result['status'], 'AFFECTED', result)
            self.assertEqual(set(catalog.pins), {'repo'})
            self.assertEqual(result['routing_rejections'][0]['round'], 2)
            self.assertEqual(len(runtime.calls), 5)

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
            runtime = QueueRuntime([(self.plan(), None), (self.plan(), None)])
            agent = ProjectFirstAgent(self.source(), fx.source_root, fx.run_root, catalog=self.catalog(fx),
                                      runtime_factory=runtime.factory)
            seen = []
            class Executor:
                def __init__(self, patch, target, run_root, **options):
                    self.run_dir = Path(run_root) / options['task_id']; self.run_dir.mkdir(parents=True)
                    seen.append(self.run_dir)
                def run(self, **kwargs):
                    return ({'status': 'INCONCLUSIVE', 'impact_decision': 'UNKNOWN',
                             'replan_required': 'BACKEND_MAPPING_CONFLICT'} if len(seen) == 1 else
                            {'status': 'AFFECTED', 'impact_decision': 'AFFECTED'})
            with patch('aosp_agent.project_first.DiffBackportAgent', Executor):
                result = agent.run(impact_only=True)
            self.assertEqual(result['status'], 'AFFECTED')
            self.assertNotEqual(seen[0], seen[1])
            self.assertIn('BACKEND_MAPPING_CONFLICT', runtime.calls[1]['prompt'])
