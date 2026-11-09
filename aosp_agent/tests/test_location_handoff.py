"""Exercise location-only handoff with actual pinned Git source and replay."""
import json
from pathlib import Path
import unittest

from aosp_agent.resume import resume_project
from aosp_agent.runtime_batch import RuntimeBatch
from engine_fixtures import BASELINE, FIXED, GitFixture, git, write_counter
from test_diff_workflow import QueueRuntime
import test_project_first as routing_fixtures
from test_runtime_entrypoints import ORIGIN, manifest, row


def location():
    unit = routing_fixtures.ProjectFirstTest().assessment()['units'][0]
    return {'primary_repository': 'repo', 'units': [
        {k: unit[k] for k in ('id', 'targets', 'evidence')} | {'location_notes': 'Pinned counterpart.'}],
        'new_files': [], 'repository_requests': []}


def impact_reply(fx, decision, edits=None):
    return {'impact': fx.assessment(decision), 'edits': edits or [], 'repair_obligations': [],
            'repository_requests': [], 'location_gaps': [], 'new_files': [], 'flag_cleanup_support': []}


class LocationHandoffTest(unittest.TestCase):
    def execute(self, fx, response, *, located=None, extras=(), turns=None, max_rounds=1,
                resume=False, prepared_manifest=False, verify=False):
        if not prepared_manifest:
            manifest(fx)
        data = fx.root / 'input.jsonl'
        data.write_text(json.dumps(row(fx)) + '\n')
        events, scopes = [], []
        scripted = {
            'sdk-routing-1.jsonl': [(routing_fixtures.ProjectFirstTest().plan(), None)],
            'sdk-location-handoff.jsonl': [(located or location(), None)],
            'sdk-events.jsonl': [(response, None), *extras],
            **(turns or {}),
        }

        class Runtime(QueueRuntime):
            def run(self, prompt, read_only, output_schema):
                events.append({'prompt': prompt, 'read_only': read_only})
                result = super().run(prompt, read_only, output_schema)
                parsed = json.loads(result['final_response'])
                if isinstance(parsed, str):
                    result['final_response'] = parsed
                return result

        def factory(**kwargs):
            name = Path(kwargs['events_path']).name
            scopes.append((name, kwargs['read_scope'].writable))
            if not scripted.get(name):
                self.fail(f'unexpected model turn: {name}')
            queue = scripted[name]
            answer = queue.pop(0)
            return Runtime([answer])

        agent = RuntimeBatch(data, fx.source_root, fx.run_root, fx.root / 'donors',
                             donor_map={ORIGIN: str(fx.repo)}, runtime_factory=factory,
                             agent_options={'locate_first': True, 'max_rounds': max_rounds})
        result = agent.run(max_attempts=1, verify=verify)['rows'][0]
        if resume:
            self.assertEqual(result['status'], 'INCONCLUSIVE', result)
            result = resume_project(result['execution_record'], runtime_factory=factory)
        self.assertEqual(git(fx.repo, 'status', '--porcelain'), '')
        self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)
        return result, events, scopes

    def test_four_field_batch_hands_off_and_exports_after_backend_impact(self):
        with GitFixture() as fx:
            response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            outcome, calls, scopes = self.execute(fx, response, extras=[
                ('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED))])
            self.assertEqual(outcome['status'], 'PATCH_UNVERIFIED', outcome)
            self.assertEqual(outcome['impact_analysis']['origin'], 'backend')
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            self.assertEqual(outcome['patches']['repo']['replay'], 'pass')
            self.assertEqual([call['read_only'] for call in calls], [True, True, True, False])
            self.assertIn('Do not judge affectedness', calls[1]['prompt'])
            self.assertIn(response['impact']['reasoning'], calls[3]['prompt'])
            self.assertFalse(scopes[2][1])
            self.assertEqual([Path(path).name for path in scopes[3][1]], ['counter.py'])

    def test_unknown_impact_with_a_grounded_location_does_not_open_writes(self):
        with GitFixture() as fx:
            outcome, calls, scopes = self.execute(fx, impact_reply(fx, 'UNKNOWN'))
            self.assertEqual(outcome['location_handoff']['status'], 'READY')
            self.assertEqual(outcome['completion_blocked_by'], 'BACKEND_IMPACT_UNRESOLVED')
            self.assertEqual(outcome['impact_decision'], 'UNKNOWN')
            self.assertFalse(outcome['patches'])
            self.assertTrue(all(call['read_only'] for call in calls))
            self.assertTrue(all(not paths for _, paths in scopes))

    def test_read_only_region_cannot_be_promoted_to_an_edit(self):
        with GitFixture() as fx:
            candidate = location()
            candidate['units'][0]['targets'][0]['action'] = 'read_dependency'
            response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            outcome, calls, scopes = self.execute(fx, response, located=candidate)
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            self.assertEqual(outcome['migration']['status'], 'INTERRUPTED')
            self.assertIn('backend edit exceeds grounded location scope', outcome['migration_scope_error'])
            self.assertTrue(all(call['read_only'] for call in calls))
            self.assertTrue(all(not paths for _, paths in scopes))

    def test_backend_exclusion_needs_independent_confirmation(self):
        with GitFixture() as fx:
            review = {'units': [{
                'id': 'f001-h001', 'verdict': 'UNKNOWN', 'security_operation': 'Bound caller count.',
                'representation': 'unknown', 'old_entrypoint_analysis': 'The caller remains unresolved.',
                'old_state_flow_analysis': 'The reviewer could not establish the data flow.',
                'blocking_analysis': 'Protection was not confirmed.',
                'entrypoint_evidence': [], 'state_flow_evidence': [], 'blocking_evidence': [],
                'donor_evidence': [], 'evidence': [], 'unresolved_assumptions': ['Caller coverage'],
            }], 'limitations': []}
            outcome, calls, scopes = self.execute(fx, impact_reply(fx, 'NOT_AFFECTED'), turns={
                'sdk-exclusion-review-1.jsonl': [(review, None)]})
            self.assertEqual(outcome['completion_blocked_by'], 'BACKEND_EXCLUSION_UNRESOLVED', outcome)
            self.assertEqual(outcome['impact_decision'], 'UNKNOWN')
            self.assertTrue(all(call['read_only'] for call in calls))
            self.assertIn(('sdk-exclusion-review-1.jsonl', ()), scopes)

    def test_scope_replan_reuses_the_backend_impact_at_unchanged_pins(self):
        with GitFixture() as fx:
            incomplete = impact_reply(fx, 'AFFECTED')
            incomplete['location_gaps'] = ['Locate the normalization return statement.']
            resolved = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            del resolved['impact']
            outcome, calls, scopes = self.execute(fx, incomplete, max_rounds=2, turns={
                'sdk-location-handoff.jsonl': [(location(), None), (location(), None)],
            }, extras=[(resolved, None),
                       ('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED))])
            self.assertEqual(outcome['status'], 'PATCH_UNVERIFIED', outcome)
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            self.assertEqual(len(outcome['rounds']), 2)
            self.assertIn(incomplete['location_gaps'][0], calls[3]['prompt'])
            self.assertIn('Return only the edit scope', calls[4]['prompt'])
            self.assertIn(incomplete['impact']['reasoning'], calls[5]['prompt'])
            self.assertFalse(scopes[4][1])
            record = Path(outcome['final_round_record']).parent / 'repositories/repo/run.json'
            self.assertTrue(json.loads(record.read_text())['backend_impact_reused'])

    def test_resume_reuses_the_checked_backend_impact_receipt(self):
        with GitFixture() as fx:
            incomplete = impact_reply(fx, 'AFFECTED')
            resolved = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            del resolved['impact']
            outcome, calls, _ = self.execute(fx, incomplete, resume=True, turns={
                'sdk-location-handoff.jsonl': [(location(), None), (location(), None)],
            }, extras=[(resolved, None),
                       ('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED))])
            self.assertEqual(outcome['status'], 'PATCH_UNVERIFIED', outcome)
            self.assertTrue(outcome['resumed_from'])
            self.assertEqual(len(calls), 6)
            self.assertIn('Return only the edit scope', calls[4]['prompt'])

    def test_open_location_gap_keeps_replayed_draft_without_build_or_delivery(self):
        with GitFixture() as fx:
            response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            response['location_gaps'] = ['Find the target registration in the older layout.']
            outcome, calls, _ = self.execute(fx, response, verify=True, extras=[
                ('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED))])
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            self.assertEqual(outcome['verification']['repo']['blocked_by'], 'MIGRATION_SCOPE_UNRESOLVED')
            self.assertEqual(outcome['delivery']['status'], 'BLOCKED')
            self.assertEqual(outcome['draft_candidates'][0]['patches']['repo']['replay'], 'pass')
            self.assertIn(response['location_gaps'][0], calls[-1]['prompt'])

    def test_pinned_read_only_dependency_does_not_require_a_worktree(self):
        with GitFixture() as fx:
            root = manifest(fx)
            peer = fx.source_root / 'peer'
            peer.mkdir()
            git(peer, 'init', '-q')
            (peer / 'helper.py').write_text(BASELINE)
            git(peer, 'add', 'helper.py')
            git(peer, 'commit', '-qm', 'pinned helper')
            peer_pin = git(peer, 'rev-parse', 'HEAD')
            default = root / 'default.xml'
            default.write_text(default.read_text().replace('</manifest>',
                f'<project name="platform/peer" path="peer" revision="{peer_pin}"/></manifest>'))
            git(root, 'add', 'default.xml')
            git(root, 'commit', '-qm', 'add pinned dependency')
            git(root, 'tag', '--force', 'release-target')
            candidate = location()
            targets = candidate['units'][0]['targets']
            targets.append({**targets[0], 'path': 'peer/helper.py', 'action': 'read_dependency'})
            evidence = candidate['units'][0]['evidence']
            evidence.append({**evidence[0], 'path': 'peer/helper.py'})
            response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            response['impact']['evidence'][0]['path'] = 'peer/helper.py'
            outcome, _, scopes = self.execute(fx, response, located=candidate, prepared_manifest=True, turns={
                'sdk-routing-1.jsonl': [(routing_fixtures.ProjectFirstTest().plan(('repo', 'peer')), None)],
            }, extras=[('HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.', write_counter(FIXED))])
            self.assertEqual(outcome['status'], 'PATCH_UNVERIFIED', outcome)
            self.assertEqual(git(peer, 'status', '--porcelain'), '')
            round_dir = Path(outcome['final_round_record']).parent
            self.assertFalse((round_dir / 'repositories/peer').exists())
            child = json.loads((round_dir / 'repositories/repo/run.json').read_text())
            self.assertEqual(child['dependency_repositories']['peer']['head'], peer_pin)
            self.assertEqual(child['assessment']['evidence'][0]['path'], 'peer/helper.py')
            self.assertEqual([Path(path).name for path in scopes[-1][1]], ['counter.py'])

    def test_read_only_donor_context_requires_a_grounded_coverage_disposition(self):
        for grounded in (False, True):
            with self.subTest(grounded=grounded), GitFixture() as fx:
                git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
                (fx.repo / 'z').mkdir()
                (fx.repo / 'z' / 'METADATA').write_text('version: 1\n')
                git(fx.repo, 'add', 'z/METADATA')
                git(fx.repo, 'commit', '--amend', '--no-edit', '-q')
                fx.donor = git(fx.repo, 'rev-parse', 'HEAD')
                git(fx.repo, 'checkout', '--detach', '-q', fx.target)
                route = routing_fixtures.ProjectFirstTest().plan()
                route['obligations'].append({'unit_id': 'f002-h001', 'security_operation': 'Version metadata.',
                                              'questions': ['Does the declaration need to be migrated?']})
                candidate = location()
                candidate['units'].append({'id': 'f002-h001', 'targets': [], 'evidence': [],
                                           'location_notes': 'No target anchor for donor metadata.'})
                response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
                evidence = 'metadata_only' if grounded else 'no_target_counterpart'
                outcome, calls, _ = self.execute(fx, response, located=candidate, turns={
                    'sdk-routing-1.jsonl': [(route, None)],
                }, extras=[(f'HUNK-RESULT f001-h001 implemented evidence=ordinary Fixed.\n'
                            f'HUNK-RESULT f002-h001 need_not_ported evidence={evidence} Version only.',
                            write_counter(FIXED))])
                self.assertEqual(outcome['impact_decision'], 'AFFECTED')
                self.assertIn('version: 1', calls[2]['prompt'])
                child_path = Path(outcome['final_round_record']).parent / 'repositories/repo/run.json'
                child = json.loads(child_path.read_text())
                skips = {entry['id']: entry.get('reason') for entry in child['mechanical_migration']['hunks']}
                self.assertEqual(skips['f002-h001'], 'read_only_donor_context')
                if grounded:
                    self.assertEqual(outcome['patches']['repo']['replay'], 'pass')
                else:
                    self.assertNotIn(outcome['status'], ('PATCH_UNVERIFIED', 'VALIDATED'))
                    self.assertTrue((child_path.parent / 'candidate-1.patch').is_file())
