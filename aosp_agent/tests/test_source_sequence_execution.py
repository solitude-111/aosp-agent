"""Execute both ordinary repair steps through the real text backend and verifier."""
import json
import sys
from types import SimpleNamespace
import unittest

from aosp_agent.discovery import diff_units
from aosp_agent.project_catalog import Project, ProjectCatalog
from aosp_agent.project_first import ProjectFirstAgent
from aosp_agent.runtime_input import RuntimeInput, resolve_sources
from engine_fixtures import GitFixture, git, BASELINE, PARTIAL, FIXED
from test_diff_workflow import QueueRuntime
from test_scope_evidence import closure_for
from mapped_impact_fixtures import proof_groups_for
import test_diff_workflow as workflow


class SourceSequenceExecutionTest(unittest.TestCase):
    def test_two_dependent_steps_keep_distinct_obligations_and_validate_final_patch(self):
        with GitFixture() as fx:
            commits = []
            for text in (PARTIAL, FIXED):
                (fx.repo / 'counter.py').write_text(text)
                git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'next count bound')
                commits.append(git(fx.repo, 'rev-parse', 'HEAD'))
            git(fx.repo, 'checkout', '--detach', '-q', fx.target)
            origin = 'https://android.googlesource.com/platform/repo'
            task = RuntimeInput.parse({'source_commit_sequence': commits,
                'source_parent_sequence': [fx.target, commits[0]], 'donor_repositories': [origin],
                'target_revision': 'synthetic-target'})
            resolved = resolve_sources(task, fx.root / 'donors', donor_map={origin: fx.repo})
            self.assertEqual(resolved['status'], 'READY')
            self.assertEqual(resolved['dependency_edges'], [{'before': 's001', 'after': 's002', 'basis': 'direct_parent'}])
            sequence = resolved['sources']
            data = ''.join(s['patch'].rstrip('\n') + '\n' for s in sequence).encode()
            units = [{**u, 'id': s['id'] + ':' + u['id'], 'source_id': s['id']}
                     for s in sequence for u in diff_units(s['patch'])]
            rows = []
            for unit in units:
                row = workflow.DiffWorkflowTest().assessment(SimpleNamespace(units=[unit]))['units'][0]
                row['evidence'][1].update(excerpt='\n'.join(unit['after'].values()),
                                           line_start=min(unit['after']), line_end=max(unit['after']))
                row['evidence'].append({'origin': 'patch_before', 'path': unit['old_path'],
                    'line_start': min(unit['before']), 'line_end': max(unit['before']),
                    'excerpt': '\n'.join(unit['before'].values()), 'claim': 'This source step before repair'})
                rows.append(row)
            assessment = {'reasoning': 'Both bounds are required in the final candidate.',
                          'limitations': ['Ordinary local function fixture only'], 'units': rows, 'new_files': []}
            assessment['scope_closure'] = closure_for(assessment)
            assessment['proof_groups'] = proof_groups_for(assessment)
            coverage = {'summary': 'Both bounds implemented.', 'limitations': [], 'coverage': [
                {'id': u['id'], 'status': 'implemented', 'explanation': 'Final implementation enforces both bounds.',
                 'evidence': [{'path': 'repo/counter.py', 'line_start': 1, 'line_end': 2,
                               'excerpt': FIXED.strip()}]} for u in units]}
            review = {'overall_risk': 'low', 'affected_callers': [], 'behavior_changes': [],
                      'compatibility_risks': [], 'performance_notes': [], 'test_recommendations': [],
                      'reasoning': 'Both source steps are present in the reviewed final candidate.'}
            runtime = QueueRuntime([(assessment, None),
                                    (coverage, lambda cwd: (cwd / 'repo/counter.py').write_text(FIXED)),
                                    (review, None)])
            options = []
            def factory(**kwargs):
                options.append(kwargs)
                return runtime
            catalog = ProjectCatalog(fx.source_root, [Project('repo', 'platform/repo', fx.target)], {})
            agent = ProjectFirstAgent(data, fx.source_root, fx.run_root, catalog=catalog, source_sequence=sequence,
                                      repository_keys=['repo'], runtime_factory=factory, auto_validation=False,
                                      model='fixture-model', model_provider='fixture-provider',
                                      validation={'repo': [[sys.executable, '-B', 'verify_contract.py']]})
            result = agent.run(verify=True, max_attempts=1)
            self.assertEqual(result['status'], 'PATCH_UNVERIFIED', result)
            self.assertEqual(result['post_fix_review']['status'], 'COMPLETED')
            self.assertEqual(result['post_fix_impact']['repo'], review)
            self.assertEqual(len(runtime.calls), 3)
            self.assertTrue(runtime.calls[-1]['read_only'])
            self.assertEqual(options[-1]['model_provider'], 'fixture-provider')
            self.assertEqual(options[-1]['model'], 'fixture-model')
            self.assertIn('s001', runtime.calls[-1]['prompt'])
            self.assertIn('s002', runtime.calls[-1]['prompt'])
            self.assertNotIn('has been generated and validated', runtime.calls[-1]['prompt'])
            final = json.loads((agent.run_dir / 'rounds/r01/run.json').read_text())
            self.assertEqual({row['id'] for row in final['hunk_ledger']}, {'s001:f001-h001', 's002:f001-h001'})
            self.assertEqual(final['patch_replay'], 'pass')
            self.assertEqual(final['causal_evidence']['contract'], 'shared_run_impact_rules')
            self.assertEqual({u for g in final['causal_evidence']['groups'] for u in g['unit_ids']},
                             {'s001:f001-h001', 's002:f001-h001'})
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
            self.assertIn('donor:<source-id>', runtime.calls[1]['prompt'])
