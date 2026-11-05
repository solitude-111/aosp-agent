from dataclasses import asdict, replace
import json
import copy
from pathlib import Path
import sys
import unittest

from aosp_agent.case import Case
from aosp_agent.mapped_run import from_case
from aosp_agent.mapping_plan import MappingPlan
from aosp_agent.hunk_scope import changed_lines_in_region
from engine_fixtures import BASELINE, FIXED, GitFixture, ScriptedRuntime, git, write_counter
import test_diff_workflow as diff_fixtures
from test_diff_workflow import QueueRuntime


class MappingPipelineTest(unittest.TestCase):
    def test_candidate_sibling_tokens_cannot_cover_another_mapping_region(self):
        patch = '@@ -10,1 +10,2 @@\n-oldCall();\n+newGuard();\n+otherGuard();\n'
        self.assertEqual(changed_lines_in_region(patch, 1, 3, added=True), [])
        self.assertEqual(changed_lines_in_region(patch, 10, 12, added=True), ['newGuard();', 'otherGuard();'])
        # A single replacement crossing the boundary is not attributable.
        crossing = '@@ -3,2 +3,1 @@\n-oldOne();\n-oldTwo();\n+bothGuards();\n'
        self.assertEqual(changed_lines_in_region(crossing, 1, 3, added=True), [])

    def wire(self, agent, fx, *, impact=None, edit=None):
        mapping = QueueRuntime([(diff_fixtures.DiffWorkflowTest().assessment(agent), None)])
        backend = ScriptedRuntime(impact or fx.assessment(), [edit or write_counter(FIXED)])
        options = []
        def factory(**kwargs):
            options.append(kwargs)
            return mapping if Path(kwargs['events_path']).name == 'sdk-assessment.jsonl' else backend
        agent.factory = factory
        return mapping, backend, options

    def test_dataset_answers_are_ignored_and_backend_ledger_is_retained(self):
        with GitFixture() as fx:
            supplied = replace(fx.case(), files=('SECRET_ANSWER_PATH.py',),
                               validation=(('MUST_NOT_EXECUTE_DATASET_ANSWER',),))
            agent = from_case(supplied, fx.source_root, fx.run_root,
                              model='patch-model', mapping_model='mapping-model')
            mapping, backend, options = self.wire(agent, fx)
            result = agent.run(verify=True)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(result['execution_path'], 'mapping_then_run_backend')
            child = agent.children['repo']
            self.assertEqual(child.case.files, ('counter.py',))
            self.assertEqual(child.record['hunk_results'][0]['status'], 'implemented')
            self.assertEqual(child.case.source_commit, fx.donor)
            self.assertTrue(child.record['donor_git'])
            prompts = '\n'.join(c['prompt'] for c in mapping.calls + backend.calls)
            self.assertNotIn('SECRET_ANSWER_PATH', prompts)
            self.assertNotIn('MUST_NOT_EXECUTE_DATASET_ANSWER', prompts)
            self.assertEqual([o['model'] for o in options], ['mapping-model', 'patch-model'])
            stored = json.loads((child.run_dir / 'runtime-case.json').read_text())
            self.assertEqual(stored['files'], ['counter.py'])
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_explicit_functional_check_and_existing_causal_gate_both_run(self):
        with GitFixture() as fx:
            agent = from_case(fx.case(), fx.source_root, fx.run_root,
                              validation={'repo': [[sys.executable, '-B', 'verify_contract.py']]})
            mapping, backend, _ = self.wire(agent, fx)
            result = agent.run(verify=True)
            self.assertEqual(result['status'], 'VALIDATED')
            self.assertEqual(len(mapping.calls), 1)
            self.assertEqual([c['read_only'] for c in backend.calls], [True, False, True])
            self.assertIn('causal_chain', agent.children['repo'].record['assessment'])

    def test_moved_donor_path_maps_to_existing_target_in_run_backend(self):
        with GitFixture() as fx:
            git(fx.repo, 'mv', 'counter.py', 'modern.py')
            git(fx.repo, 'commit', '-qm', 'donor moves the implementation')
            parent = git(fx.repo, 'rev-parse', 'HEAD')
            (fx.repo / 'modern.py').write_text(FIXED)
            git(fx.repo, 'commit', '-qam', 'donor fixes the moved implementation')
            donor = git(fx.repo, 'rev-parse', 'HEAD')
            git(fx.repo, 'checkout', '--detach', '-q', fx.target)
            supplied = replace(fx.case(), source_commit=donor, source_parent=parent,
                               files=('modern.py',))
            agent = from_case(supplied, fx.source_root, fx.run_root)
            impact = fx.assessment()
            for entry in impact['evidence']:
                if entry['revision'].startswith('source_'):
                    entry['path'] = 'modern.py'
            self.wire(agent, fx, impact=impact)
            result = agent.run(verify=True, mechanical=False)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            child = agent.children['repo']
            self.assertEqual(child._donor_targets('modern.py'), {'counter.py'})
            self.assertFalse((child.worktree / 'modern.py').exists())
            self.assertIn('counter.py', Path(result['patches']['repo']['file']).read_text())

    def test_mapping_cannot_bypass_run_causal_assessment(self):
        with GitFixture() as fx:
            agent = from_case(fx.case(), fx.source_root, fx.run_root)
            bad_impact = fx.assessment()
            bad_impact['causal_chain']['external_behavior_assumptions'] = ['unverified behavior']
            _, backend, _ = self.wire(agent, fx, impact=bad_impact)
            result = agent.run(verify=True, max_attempts=1)
            self.assertEqual(result['status'], 'FAILED')
            self.assertIn('repo', result['repository_errors'])
            self.assertTrue(all(c['read_only'] for c in backend.calls))
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_writer_cannot_modify_controller_plans(self):
        with GitFixture() as fx:
            agent = from_case(fx.case(), fx.source_root, fx.run_root)
            def edit(worktree):
                write_counter(FIXED)(worktree)
                (agent.run_dir / 'mapping-plan.json').write_text('{}')
            self.wire(agent, fx, edit=edit)
            with self.assertRaisesRegex(RuntimeError, 'controller-owned plan'):
                agent.run(max_attempts=1)

    def test_case_may_omit_answer_paths_and_inspection_never_starts_model(self):
        with GitFixture() as fx:
            raw = json.loads(json.dumps(asdict(fx.case())))
            raw.pop('files'); raw.pop('validation')
            case = Case.from_dict(raw)
            self.assertEqual(case.files, ())
            agent = from_case(case, fx.source_root, fx.run_root,
                              runtime_factory=lambda **kw: self.fail('model must not start'))
            result = agent.run(inspect_only=True)
            self.assertEqual(result['status'], 'DISCOVERED')
            self.assertFalse(agent.workspace.exists())

    def test_plan_returns_copies_and_records_fixed_revisions(self):
        with GitFixture() as fx:
            agent = from_case(fx.case(), fx.source_root, fx.run_root)
            assessment = agent.ground(diff_fixtures.DiffWorkflowTest().assessment(agent))
            plan = MappingPlan.create(assessment, agent.repos, agent.units, agent.donor)
            assessment['writable_paths'].append('repo/injected.py')
            snapshot = plan.data()
            snapshot['assessment']['writable_paths'].append('repo/also-injected.py')
            self.assertEqual(plan.files('repo'), ('counter.py',))
            self.assertEqual(plan.data()['targets']['repo'], fx.target)

    def test_repository_failure_is_isolated_and_joint_success_is_not_invented(self):
        for first_fails in (True, False):
            with self.subTest(first_fails=first_fails), GitFixture() as fx:
                second = fx.source_root / 'repo2'
                second.mkdir()
                git(second, 'init', '-q')
                for name in ('counter.py', 'verify_contract.py', '.gitignore'):
                    (second / name).write_text((fx.repo / name).read_text())
                git(second, 'add', '.')
                git(second, 'commit', '-qm', 'independent target')
                validation = {key: [[sys.executable, '-B', 'verify_contract.py']] for key in ('repo', 'repo2')}
                agent = from_case(fx.case(), fx.source_root, fx.run_root, validation=validation)
                raw = diff_fixtures.DiffWorkflowTest().assessment(agent)
                target = copy.deepcopy(raw['units'][0]['targets'][0])
                target['path'] = 'repo2/counter.py'
                raw['units'][0]['targets'].append(target)
                evidence = copy.deepcopy(raw['units'][0]['evidence'][0])
                evidence['path'] = target['path']
                raw['units'][0]['evidence'].append(evidence)
                mapping = QueueRuntime([(raw, None)])
                first_impact = fx.assessment()
                if first_fails:
                    first_impact['causal_chain']['external_behavior_assumptions'] = ['unverified behavior']
                backends = {'repo': ScriptedRuntime(first_impact, [write_counter(FIXED)]),
                            'repo2': ScriptedRuntime(fx.assessment(), [write_counter(FIXED)])}
                def factory(**kwargs):
                    path = Path(kwargs['events_path'])
                    return mapping if path.name == 'sdk-assessment.jsonl' else backends[path.parent.name]
                agent.factory = factory
                result = agent.run(verify=True, max_attempts=1)
                self.assertEqual(result['repository_statuses']['repo2'], 'VALIDATED')
                self.assertEqual(result['status'], 'FAILED' if first_fails else 'PATCH_UNVERIFIED')
                if not first_fails:
                    self.assertEqual(result['combined_verification'], 'NOT_CONFIGURED')
                self.assertEqual(result['hunk_ledger'][0]['expected_repositories'], ['repo', 'repo2'])
