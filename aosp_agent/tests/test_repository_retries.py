import copy
from pathlib import Path
import sys
import unittest

from aosp_agent.diff_engine import DiffBackportAgent
from engine_fixtures import BASELINE, FIXED, GitFixture, git
import test_diff_workflow as fixture

UNRELATED = BASELINE.replace('return value', 'return -value')


class RepositoryRetryTest(unittest.TestCase):
    def setup_agent(self, fx, *, validation=None, joint=None):
        git(fx.source_root, 'clone', '-q', '--no-hardlinks', str(fx.repo), str(fx.source_root / 'repo2'))
        path = fx.root / 'input.patch'
        path.write_text(fixture.diff('modern.py', BASELINE, FIXED))
        agent = DiffBackportAgent(path, fx.source_root, fx.run_root, auto_validation=False,
                                  validation=validation, joint_validation=joint)
        raw = fixture.DiffWorkflowTest().assessment(agent)
        target = copy.deepcopy(raw['units'][0]['targets'][0])
        target['path'] = 'repo2/counter.py'
        raw['units'][0]['targets'].append(target)
        evidence = copy.deepcopy(raw['units'][0]['evidence'][0])
        evidence['path'] = target['path']
        raw['units'][0]['evidence'].append(evidence)
        return agent, raw

    def turn(self, agent, key, content=FIXED):
        coverage = fixture.DiffWorkflowTest().coverage(agent, content)
        coverage['coverage'][0]['evidence'][0]['path'] = key + '/counter.py'
        return coverage, lambda cwd: (cwd / key / 'counter.py').write_text(content)

    def attach(self, agent, assessment, turns):
        runtimes = {key: fixture.QueueRuntime(value) for key, value in turns.items()}
        mapping = fixture.QueueRuntime([(assessment, None)])
        def factory(**kwargs):
            name = Path(kwargs['events_path']).stem
            return mapping if name == 'sdk-assessment' else runtimes[name[len('sdk-migration-'):]]
        agent.factory = factory
        return runtimes

    def test_failed_repository_retries_without_revisiting_successful_peer(self):
        with GitFixture() as fx:
            agent, raw = self.setup_agent(fx)
            runtimes = self.attach(agent, raw, {'repo': [self.turn(agent, 'repo')],
                'repo2': [self.turn(agent, 'repo2', UNRELATED), self.turn(agent, 'repo2')]})
            result = agent.run(max_attempts=2)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED')
            self.assertEqual(len(runtimes['repo'].calls), 1)
            self.assertEqual(len(runtimes['repo2'].calls), 2)
            self.assertEqual(set(result['patches']), {'repo', 'repo2'})
            self.assertTrue(all(c for c in result['hunk_ledger'][0]['backend_claims'].values()))
            self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')

    def test_exhaustion_in_first_repository_does_not_skip_second(self):
        with GitFixture() as fx:
            agent, raw = self.setup_agent(fx)
            runtimes = self.attach(agent, raw, {'repo': [self.turn(agent, 'repo', UNRELATED)],
                                               'repo2': [self.turn(agent, 'repo2')]})
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'MIGRATION_INCOMPLETE')
            self.assertEqual(result['repository_statuses']['repo2'], 'PATCH_UNVERIFIED')
            self.assertEqual(len(runtimes['repo2'].calls), 1)
            self.assertIn('repo2', result['patches'])

    def test_runtime_failure_is_local_but_writing_another_candidate_is_fatal(self):
        for foreign_edit in (False, True):
            with self.subTest(foreign_edit=foreign_edit), GitFixture() as fx:
                agent, raw = self.setup_agent(fx)
                coverage, _ = self.turn(agent, 'repo')
                def edit(cwd):
                    if foreign_edit:
                        (cwd / 'repo2/counter.py').write_text(FIXED)
                    else:
                        raise RuntimeError('simulated runtime outage')
                runtimes = self.attach(agent, raw, {'repo': [(coverage, edit)], 'repo2': [self.turn(agent, 'repo2')]})
                if foreign_edit:
                    with self.assertRaisesRegex(RuntimeError, 'another candidate'):
                        agent.run(max_attempts=1)
                    self.assertFalse(runtimes['repo2'].calls)
                else:
                    result = agent.run(max_attempts=1)
                    self.assertEqual(result['status'], 'FAILED')
                    self.assertEqual(result['repository_statuses']['repo2'], 'PATCH_UNVERIFIED')

    def test_shared_hunk_still_requires_each_repository_obligation(self):
        with GitFixture() as fx:
            agent, raw = self.setup_agent(fx)
            wrong = self.turn(agent, 'repo')[0]
            self.attach(agent, raw, {'repo': [self.turn(agent, 'repo')],
                'repo2': [(wrong, lambda cwd: (cwd / 'repo2/counter.py').write_text(FIXED))]})
            result = agent.run(max_attempts=1)
            self.assertEqual(result['status'], 'MIGRATION_INCOMPLETE')
            self.assertIn('outside the unit writable mapping', result['coverage_error'])

    def test_joint_failure_uses_remaining_per_repository_budget(self):
        with GitFixture() as fx:
            check = fx.root / 'joint.py'
            check.write_text('from pathlib import Path\nassert "# coordinated" in Path("repo2/counter.py").read_text()\n')
            agent, raw = self.setup_agent(fx, joint=[[sys.executable, str(check)]])
            repair, _ = self.turn(agent, 'repo2')
            runtimes = self.attach(agent, raw, {'repo': [self.turn(agent, 'repo'), self.turn(agent, 'repo')],
                'repo2': [self.turn(agent, 'repo2'),
                          (repair, lambda cwd: (cwd / 'repo2/counter.py').write_text(FIXED + '# coordinated\n'))]})
            result = agent.run(max_attempts=2, verify=True)
            self.assertEqual(result['status'], 'VALIDATED', result)
            self.assertEqual(result['joint_attempt'], 2)
            self.assertEqual(result['joint_attempt_results'][0]['status'], 'FAIL')
            self.assertEqual(result['combined_verification'], 'PASS')
            self.assertEqual([len(r.calls) for r in runtimes.values()], [2, 2])
            self.assertTrue(all(child.record['attempt'] <= 2 for child in agent.children.values()))

    def test_joint_retry_exhaustion_never_becomes_validated(self):
        with GitFixture() as fx:
            check = fx.root / 'joint.py'
            check.write_text('raise SystemExit(7)\n')
            agent, raw = self.setup_agent(fx, joint=[[sys.executable, str(check)]])
            runtimes = self.attach(agent, raw, {key: [self.turn(agent, key), self.turn(agent, key)]
                                               for key in ('repo', 'repo2')})
            result = agent.run(max_attempts=2, verify=True)
            self.assertEqual(result['status'], 'VALIDATION_FAILED')
            self.assertEqual(result['joint_attempt'], 2)
            self.assertEqual([len(r.calls) for r in runtimes.values()], [2, 2])
