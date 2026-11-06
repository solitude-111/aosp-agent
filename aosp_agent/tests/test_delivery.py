"""Actual temporary builds retain PASS without treating review failure as delivery."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from aosp_agent.delivery import update_delivery
from aosp_agent.engine import AospBackportAgent
from aosp_agent.joint_validation import assess_joint_impact
from aosp_agent.prompts import POST_FIX_SCHEMA
from aosp_agent.runtime_batch import RuntimeBatch
from engine_fixtures import BASELINE, FIXED, GitFixture, ScriptedRuntime, write_counter, git
import test_joint_validation as joint_fixtures
import test_project_first as routing_fixtures
import test_runtime_entrypoints as entry_fixtures
import test_diff_workflow as workflow_fixtures
from test_diff_workflow import QueueRuntime


def review(risk='low'):
    return dict(overall_risk=risk, affected_callers=[], behavior_changes=[], compatibility_risks=[],
                performance_notes=[], test_recommendations=[], reasoning='Ordinary fixture code review.')


class ReviewRuntime(ScriptedRuntime):
    def __init__(self, fx, response):
        super().__init__(fx.assessment(), [write_counter(FIXED)])
        self.response = response

    def run(self, prompt, read_only, output_schema=None):
        if output_schema == POST_FIX_SCHEMA:
            return {'status': 'completed', 'output': self.response, 'final_response': json.dumps(self.response)}
        return super().run(prompt, read_only, output_schema)


def builder(fx):
    script = fx.root / 'build.py'
    script.write_text('import os,sys\nfrom pathlib import Path\n'
        + f'sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})\n'
        + 'from aosp_agent.build_transaction import transaction\n'
        + 'if "--build-only" not in sys.argv:\n'
        + f'    raise SystemExit(transaction({str(fx.source_root)!r}, {str(fx.root / "build.lock")!r}, '
          '[sys.executable, __file__, "--build-only"]))\n'
        + 'source = Path(os.environ["AOSP_AGENT_TARGET_REPO"]) / "counter.py"\n'
        + 'compile(source.read_text(), str(source), "exec")\n')
    return {'stage': 'android_module_build', 'argv': [sys.executable, str(script)], 'artifacts': []}


class DeliveryTest(unittest.TestCase):
    def run_single(self, fx, response):
        agent = AospBackportAgent(fx.source_root, fx.run_root,
            replace(fx.case(), validation_checks=(builder(fx),)), runtime_factory=ReviewRuntime(fx, response).factory)
        result = agent.run(verify=True, max_attempts=1)
        self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
        self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
        self.assertEqual(result['final_verification']['status'], 'PASS')
        self.assertTrue(result['final_verification']['sufficient_for_validated'])
        self.assertEqual(result['build_validation']['status'], 'PASS')
        self.assertEqual(json.loads((agent.run_dir / 'run.json').read_text())['delivery_status'], result['delivery_status'])
        return agent, result

    def test_real_local_build_keeps_pass_but_high_medium_and_invalid_review_need_attention(self):
        for response in (review('high'), review('medium'), {}):
            with self.subTest(response=response), GitFixture() as fx:
                _, result = self.run_single(fx, response)
                self.assertEqual(result['status'], 'NEEDS_REVIEW')
                self.assertEqual(result['delivery_status'], 'NEEDS_REVIEW')
                self.assertNotEqual(result['review_status']['status'], 'PASSED')

    def test_low_review_allows_handoff_and_stale_patch_review_cannot(self):
        with GitFixture() as fx:
            agent, result = self.run_single(fx, review())
            self.assertEqual(result['status'], 'VALIDATED')
            self.assertEqual(result['delivery_status'], 'READY_FOR_HANDOFF')
            self.assertFalse(result['delivery']['runtime_security_proven'])
            # Keep the real successful build receipt, but simulate a review
            # referring to another candidate. No model/build rerun is needed.
            result['post_fix_review']['patch_sha256'] = '0' * 64
            agent._write_record()
            self.assertEqual(result['status'], 'NEEDS_REVIEW')
            self.assertEqual(result['review_status']['status'], 'STALE')
            self.assertEqual(result['build_validation']['status'], 'PASS')

    def test_new_candidate_invalidates_old_build_and_review(self):
        with GitFixture() as fx:
            agent, result = self.run_single(fx, review())
            (agent.worktree / 'counter.py').write_text(FIXED.replace('max(0, min(value, 10))', 'min(10, max(value, 0))'))
            agent.export_patch(2)
            agent._write_record()
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            self.assertFalse(result['build_validation']['candidate_bound'])
            self.assertEqual(result['review_status']['status'], 'STALE')
            self.assertEqual(result['delivery_status'], 'UNVERIFIED')

    def test_failed_scope_or_lifecycle_cannot_be_promoted_by_good_evidence(self):
        with GitFixture() as fx:
            _, record = self.run_single(fx, review())
            for status in ('BLOCKED', 'FAILED', 'CANCELLED', 'VALIDATION_FAILED', 'MIGRATION_INCOMPLETE', 'INCONCLUSIVE'):
                candidate = copy.deepcopy(record); candidate['status'] = status
                update_delivery(candidate)
                self.assertEqual(candidate['status'], status)
                self.assertEqual(candidate['delivery_status'], 'BLOCKED')
            record['completion_blocked_by'] = 'INCOMPLETE_OBJECT_RETRIEVAL'
            update_delivery(record)
            self.assertEqual(record['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(record['delivery_status'], 'UNVERIFIED')

    def test_joint_build_and_each_peer_review_are_independent_obligations(self):
        helper = joint_fixtures.JointValidationTest()
        for response in (review('high'), {}):
            with self.subTest(response=response), GitFixture() as fx:
                runner = helper.build_runner(fx)
                validation = {key: [{'stage': 'android_module_build', 'argv': [str(runner), 'module_' + key],
                                    'artifacts': ['out-artifacts/modules.txt']}] for key in ('repo', 'repo2')}
                agent = helper.controller(fx, validation=validation, runner=runner)
                result = agent.run(verify=True, max_attempts=1)
                self.assertEqual(result['delivery_status'], 'READY_FOR_HANDOFF', result)
                for key, child in agent.children.items():
                    child.record.pop('post_fix_bundle_sha256', None)
                    child.runtime_factory = QueueRuntime([(response if key == 'repo2' else review(), None)]).factory
                assess_joint_impact(agent)
                agent._save()
                self.assertEqual(result['status'], 'NEEDS_REVIEW')
                self.assertEqual(result['build_validation']['status'], 'PASS')
                self.assertEqual(result['joint_verification']['status'], 'PASS')
                self.assertEqual(result['delivery_status'], 'NEEDS_REVIEW')
                for child in agent.children.values():
                    self.assertEqual((child.repo / 'counter.py').read_text(), BASELINE)

    def test_project_first_batch_propagates_review_status_and_continues_next_row(self):
        with GitFixture() as fx:
            entry_fixtures.manifest(fx)
            path = fx.root / 'input.jsonl'
            path.write_text(json.dumps(entry_fixtures.row(fx)) + '\n' + json.dumps(entry_fixtures.row(fx)))
            def factory(**kwargs):
                name = Path(kwargs['events_path']).name
                if name == 'sdk-assessment.jsonl':
                    return QueueRuntime([(routing_fixtures.ProjectFirstTest().assessment(), None)])
                if name == 'sdk-post-fix.jsonl':
                    return QueueRuntime([(review('high'), None)])
                return ReviewRuntime(fx, review('high'))
            runner = RuntimeBatch(path, fx.source_root, fx.run_root, fx.root / 'donors',
                donor_map={entry_fixtures.ORIGIN: str(fx.repo)}, runtime_factory=factory,
                agent_options={'repository_keys': ['repo'], 'auto_validation': False, 'validation': {'repo': [builder(fx)]}})
            result = runner.run(verify=True, max_attempts=1)
            self.assertEqual(result['status'], 'COMPLETED', result)
            self.assertEqual(result['counts'], {'NEEDS_REVIEW': 2}, result)
            self.assertEqual(result['delivery_counts'], {'NEEDS_REVIEW': 2})
            for row in result['rows']:
                for path in (row['record'], row['execution_record']):
                    saved = json.loads(Path(path).read_text())
                    self.assertEqual(saved['status'], 'NEEDS_REVIEW', saved)
                    self.assertEqual(saved['build_validation']['status'], 'PASS')
                from aosp_agent.resume import resume_project
                from aosp_agent.lifecycle import RecoveryBlocked
                with self.assertRaisesRegex(RecoveryBlocked, 'already terminal'):
                    resume_project(row['execution_record'])
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_text_backend_single_build_plus_generic_joint_check_preserves_real_coverage(self):
        helper = workflow_fixtures.DiffWorkflowTest()
        for risk, code in (('low', 0), ('high', 0), ('low', 9)):
            with self.subTest(risk=risk, code=code), GitFixture() as fx:
                agent = helper.agent(fx, validation={'repo': [builder(fx)]})
                script = fx.root / 'joint_check.py'; script.write_text(f'raise SystemExit({code})\n')
                agent.joint_validation = [[sys.executable, str(script)]]
                runtime = QueueRuntime([(helper.assessment(agent), None),
                    (helper.coverage(agent), lambda cwd: (cwd / 'repo/counter.py').write_text(FIXED)),
                    (review(risk), None)])
                agent.factory = runtime.factory
                result = agent.run(verify=True, max_attempts=1)
                expected = 'VALIDATION_FAILED' if code else 'NEEDS_REVIEW' if risk == 'high' else 'VALIDATED'
                self.assertEqual(result['status'], expected, result)
                self.assertEqual(result['build_validation']['status'], 'FAIL' if code else 'PASS')
                self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_cli_exposes_pending_review_and_uses_nonzero_exit_code(self):
        from aosp_agent.__main__ import _main, exit_status
        import contextlib
        import io
        self.assertEqual(exit_status('NEEDS_REVIEW'), 7)
        with GitFixture() as fx:
            agent, _ = self.run_single(fx, review('high'))
            output = io.StringIO()
            with patch.object(sys, 'argv', ['agent', 'status', '--record', str(agent.run_dir / 'run.json')]), contextlib.redirect_stdout(output):
                self.assertEqual(_main(), 0)  # Reading a status succeeded.
            saved = json.loads(output.getvalue())
            self.assertEqual(saved['delivery_status'], 'NEEDS_REVIEW')
            self.assertEqual(saved['build_validation']['status'], 'PASS')
