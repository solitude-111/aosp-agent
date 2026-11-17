"""Exercise location-only handoff with actual pinned Git source and replay."""
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aosp_agent.assessment_repair import digest
from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.resume import resume_project
from aosp_agent.runtime_batch import RuntimeBatch
from aosp_agent.sdk_runtime import CodexRuntimeError
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


def unassociated_reference(fx):
    path = 'verify_contract.py'
    excerpt = (fx.repo / path).read_text().splitlines()[0]
    return {'origin': 'target', 'path': 'repo/' + path, 'line_start': 1, 'line_end': 1,
            'excerpt': excerpt, 'claim': 'An example call outside the mapped locations.'}


class LocationHandoffTest(unittest.TestCase):
    def execute(self, fx, response, *, located=None, extras=(), turns=None, max_rounds=1,
                resume=False, prepared_manifest=False, verify=False, max_attempts=1,
                input_changes=None, agent_options=None):
        if not prepared_manifest:
            manifest(fx)
        data = fx.root / 'input.jsonl'
        data.write_text(json.dumps(row(fx, **(input_changes or {}))) + '\n')
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
            runtime = Runtime([])
            runtime.replies = scripted[name]
            return runtime

        agent = RuntimeBatch(data, fx.source_root, fx.run_root, fx.root / 'donors',
                             donor_map={ORIGIN: str(fx.repo)}, runtime_factory=factory,
                             agent_options={'locate_first': True, 'max_rounds': max_rounds,
                                            **(agent_options or {})})
        result = agent.run(max_attempts=max_attempts, verify=verify)['rows'][0]
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
            round_record = json.loads(Path(outcome['final_round_record']).read_text())
            self.assertEqual(round_record['source_search_paths'], {'repo': ['counter.py']})

    def test_unassociated_reference_is_logged_and_excluded_from_handoff(self):
        with GitFixture() as fx:
            candidate = location()
            extra = unassociated_reference(fx)
            candidate['units'][0]['evidence'].insert(0, extra)
            outcome, calls, _ = self.execute(fx, impact_reply(fx, 'UNKNOWN'), located=candidate)
            self.assertEqual(outcome['location_handoff']['status'], 'READY')
            self.assertEqual(outcome['completion_blocked_by'], 'BACKEND_IMPACT_UNRESOLVED')
            self.assertNotIn(extra['path'], calls[2]['prompt'])
            round_path = Path(outcome['final_round_record'])
            raw = json.loads((round_path.parent / 'location-attempt-1.json').read_text())
            grounded = json.loads((round_path.parent / 'grounded-location.json').read_text())
            record = json.loads(round_path.read_text())
            self.assertEqual(raw, candidate)
            self.assertEqual(grounded['units'][0]['targets'], candidate['units'][0]['targets'])
            self.assertEqual(grounded['units'][0]['evidence'], candidate['units'][0]['evidence'][1:])
            self.assertEqual(record['source_search_paths'], {'repo': ['counter.py']})
            self.assertEqual(record['location_unassociated_evidence'], [{
                'unit_id': 'f001-h001', 'evidence_index': 0, 'reason': 'TARGET_PATH_NOT_MAPPED',
                'path': extra['path'], 'line_start': 1, 'line_end': 1, 'attempt': 1}])

    def test_unassociated_reference_cannot_replace_required_source_evidence(self):
        for missing in (True, False):
            with self.subTest(missing=missing), GitFixture() as fx:
                candidate = location()
                unit = candidate['units'][0]
                unit['evidence'].insert(0, unassociated_reference(fx))
                index = next(i for i, e in enumerate(unit['evidence']) if e['path'] == 'repo/counter.py')
                if missing:
                    unit['evidence'].pop(index)
                else:
                    unit['evidence'][index]['excerpt'] = 'Incorrect pinned source.'
                outcome, calls, _ = self.execute(fx, None, located=candidate)
                self.assertEqual(outcome['completion_blocked_by'], 'LOCATION_UNRESOLVED', outcome)
                self.assertEqual(outcome['impact_analysis']['status'], 'NOT_STARTED')
                self.assertEqual(len(calls), 2)
                record = json.loads(Path(outcome['final_round_record']).read_text())
                expected = ('target mapping lacks an excerpt' if missing
                            else f'/units/0/evidence/{index}')
                self.assertIn(expected, record['location_rejections'][0])

    def test_unknown_impact_with_a_grounded_location_does_not_open_writes(self):
        with GitFixture() as fx:
            outcome, calls, scopes = self.execute(fx, impact_reply(fx, 'UNKNOWN'))
            self.assertEqual(outcome['location_handoff']['status'], 'READY')
            self.assertEqual(outcome['completion_blocked_by'], 'BACKEND_IMPACT_UNRESOLVED')
            self.assertEqual(outcome['impact_decision'], 'UNKNOWN')
            self.assertFalse(outcome['patches'])
            self.assertTrue(all(call['read_only'] for call in calls))
            self.assertTrue(all(not paths for _, paths in scopes))

    def test_location_correction_reuses_unaffected_fields(self):
        with GitFixture() as fx:
            candidate = location()
            candidate['units'][0]['targets'][0]['line_end'] = 100
            repair = {'base_sha256': digest(candidate), 'replacements': [
                {'path': '/units/0/targets/0/line_end', 'value_json': '2'},
            ]}
            outcome, calls, _ = self.execute(fx, impact_reply(fx, 'UNKNOWN'), max_attempts=2, turns={
                'sdk-location-handoff.jsonl': [(candidate, None), (repair, None)],
            })
            self.assertEqual(outcome['location_handoff']['status'], 'READY')
            self.assertIn('Return only base_sha256 and replacements', calls[2]['prompt'])
            record = Path(outcome['final_round_record']).parent
            self.assertEqual(json.loads((record / 'grounded-location.json').read_text()), location())

    def test_partial_locations_can_reach_impact_without_opening_writes(self):
        with GitFixture() as fx:
            candidate = location()
            unit = candidate['units'][0]
            unit['targets'].append({**unit['targets'][0], 'line_end': 100})
            outcome, calls, scopes = self.execute(fx, impact_reply(fx, 'AFFECTED'), located=candidate)
            self.assertEqual(outcome['location_handoff']['scope'], 'READ_ONLY_WITH_GAPS')
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            self.assertIn('invalid target mapping range', outcome['migration_scope_error'])
            self.assertTrue(all(call['read_only'] for call in calls))
            self.assertTrue(all(not paths for _, paths in scopes))

    def test_backend_timeout_is_persisted_before_single_source_audit(self):
        for audit_fails in (False, True):
            with self.subTest(audit_fails=audit_fails), GitFixture() as fx:
                audits = []
                original = DiffBackportAgent._audit_peers

                def timeout(_workspace):
                    raise CodexRuntimeError('Operation exceeded 900 seconds', kind='TIMEOUT')

                def audit(controller, key, before):
                    saved = json.loads((controller.run_dir / 'run.json').read_text())
                    self.assertEqual(saved['repository_errors'][key]['kind'], 'MODEL_TIMEOUT')
                    audits.append(key)
                    if audit_fails:
                        raise subprocess.TimeoutExpired(['git', 'status'], 45)
                    return original(controller, key, before)

                with patch.object(DiffBackportAgent, '_audit_peers', audit):
                    outcome, calls, scopes = self.execute(fx, None, turns={
                        'sdk-events.jsonl': [(None, timeout)],
                    }, verify=True)
                self.assertEqual(audits, ['repo'])
                self.assertEqual(outcome['status'], 'BLOCKED' if audit_fails else 'INCONCLUSIVE', outcome)
                self.assertEqual(outcome['completion_blocked_by'],
                                 'SOURCE_AUDIT_UNVERIFIED' if audit_fails else 'MODEL_TIMEOUT')
                self.assertEqual(outcome['repository_errors']['repo']['kind'], 'MODEL_TIMEOUT')
                self.assertEqual(outcome['impact_analysis']['reason'], 'MODEL_TIMEOUT')
                self.assertFalse(outcome.get('patches'))
                self.assertTrue(all(call['read_only'] for call in calls))
                self.assertTrue(all(not paths for _, paths in scopes))
                if audit_fails:
                    error = outcome['source_audit_errors']['repo']
                    self.assertEqual((error['status'], error['type']), ('UNVERIFIED', 'TimeoutExpired'))

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

    def test_exclusion_challenge_rechecks_impact_without_repeating_location(self):
        for second_status in ('UNKNOWN', 'NOT_AFFECTED'):
            with self.subTest(second_status=second_status), GitFixture() as fx:
                review = {'units': [{
                    'id': 'f001-h001', 'verdict': 'COUNTERPART_POSSIBLE', 'security_operation': 'Limit a caller count.',
                    'representation': 'equivalent', 'old_entrypoint_analysis': 'The legacy function receives the value.',
                    'old_state_flow_analysis': 'The input reaches the return unchanged.',
                    'blocking_analysis': 'The legacy operation may be equivalent despite the missing helper.',
                    'entrypoint_evidence': [1], 'state_flow_evidence': [1], 'blocking_evidence': [1],
                    'donor_evidence': [], 'evidence': [{
                        'origin': 'target', 'path': 'repo/counter.py', 'line_start': 2, 'line_end': 2,
                        'excerpt': BASELINE.splitlines()[1].strip(), 'claim': 'The target returns its input.',
                    }], 'unresolved_assumptions': ['The caller is still unverified.'],
                }], 'limitations': []}
                outcome, calls, scopes = self.execute(fx, impact_reply(fx, 'NOT_AFFECTED'),
                    max_rounds=3, extras=[(impact_reply(fx, second_status), None)], turns={
                        'sdk-exclusion-review-1.jsonl': [(review, None)] * 2})
                self.assertEqual(outcome['impact_decision'], 'UNKNOWN', outcome)
                self.assertEqual(outcome['completion_blocked_by'],
                                 'BACKEND_IMPACT_UNRESOLVED' if second_status == 'UNKNOWN'
                                 else 'BACKEND_EXCLUSION_CHALLENGED')
                self.assertEqual(sum(name == 'sdk-location-handoff.jsonl' for name, _ in scopes), 1)
                self.assertEqual(len(outcome['rounds']), 2)
                self.assertEqual(len(calls), 5 if second_status == 'UNKNOWN' else 6)
                self.assertIn('Recheck the disputed', calls[4]['prompt'])
                self.assertIn(review['units'][0]['blocking_analysis'], calls[4]['prompt'])
                self.assertTrue(all(call['read_only'] for call in calls))
                final_round = json.loads(Path(outcome['final_round_record']).read_text())
                self.assertTrue(final_round['location_reused'])
                self.assertEqual(final_round['impact_recheck']['units'], ['f001-h001'])

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

    def test_bad_repair_contract_retries_only_plan_with_verified_no_edit_support(self):
        from aosp_agent.location_handoff import BackendHandoff, backend_scope_feedback

        for supported in (False, True):
            with self.subTest(supported=supported), GitFixture() as fx:
                located = location()
                located['units'].append({'id': 'f002-h001', 'targets': [], 'evidence': [],
                                         'location_notes': 'No flag declaration in target.'})
                pins = {'repo': fx.target}
                receipt = {'status': 'READY', 'targets': pins, 'unmapped_units': ['f002-h001']}
                record = {'location_handoff': receipt, 'impact_analysis': {'status': 'CONFIRMED'}}
                controller = SimpleNamespace(record=record, grounded_location=located,
                                             guarded_obligations=[], units=[], _save=lambda: None)
                handoff = object.__new__(BackendHandoff)
                handoff.controller = controller
                handoff.location = located
                handoff.confirm = lambda *args: None
                report = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
                report['repair_obligations'] = [{'id': 'f001-h001'}]
                child = SimpleNamespace(record={})
                flags = {'f002-h001': {'unit_id': 'f002-h001'}} if supported else {}
                with patch('aosp_agent.location_handoff.ground_flag_support', return_value=flags):
                    self.assertFalse(handoff.accept(child, report['impact'], report, impact_only=False))
                    diagnostic = record['migration_scope_diagnostic']
                    self.assertEqual(diagnostic['path'], '/repair_obligations')
                    self.assertEqual(diagnostic['expected_ids'], [])
                    self.assertEqual(diagnostic['submitted_ids'], ['f001-h001'])
                    self.assertEqual(child.record['completion_blocked_by'], 'MIGRATION_SCOPE_UNRESOLVED')
                    retry = backend_scope_feedback(record, located, receipt, pins)
                    if not supported:
                        self.assertEqual(record['replan_required'], 'LOCATION_SCOPE_UNRESOLVED')
                        self.assertIsNone(retry)
                        continue
                    self.assertEqual(record['replan_required'], 'BACKEND_SCOPE_CORRECTION_REQUIRED')
                    self.assertEqual(retry['diagnostic'], diagnostic)
                    self.assertEqual(retry['previous_scope_report']['edits'], report['edits'])
                    self.assertIsNone(backend_scope_feedback(record, located, receipt, {'repo': fx.donor}))
                    report['repair_obligations'] = []
                    self.assertTrue(handoff.accept(child, report['impact'], report, impact_only=False))
                    self.assertEqual(handoff.flag_support, flags)

    def test_read_only_replan_cannot_drop_a_confirmed_fault(self):
        with GitFixture() as fx:
            located = location()
            located['units'][0]['targets'][0]['action'] = 'read_dependency'
            outcome, calls, _ = self.execute(fx, impact_reply(fx, 'AFFECTED'), located=located)
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            stopped = json.loads(Path(outcome['final_round_record']).read_text())
            self.assertEqual(stopped['completion_blocked_by'], 'MIGRATION_SCOPE_UNRESOLVED')
            self.assertIn('missing edit locations for confirmed donor fault: f001-h001', stopped['migration_scope_error'])
            self.assertFalse(outcome.get('patches'))
            self.assertTrue(all(call['read_only'] for call in calls))

    def test_selected_read_dependency_reaches_location_replan_with_pinned_coordinates(self):
        with GitFixture() as fx:
            located = location()
            target = located['units'][0]['targets'][0]
            target['action'] = 'read_dependency'
            response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            outcome, calls, _ = self.execute(fx, response, located=located)
            self.assertEqual(outcome['impact_decision'], 'AFFECTED')
            self.assertFalse(outcome.get('patches'))
            self.assertTrue(all(call['read_only'] for call in calls))
            gap, = outcome['location_gaps']
            self.assertEqual(gap['unit_id'], 'f001-h001')
            self.assertEqual(gap['path'], target['path'])
            self.assertEqual((gap['line_start'], gap['line_end']),
                             (target['line_start'], target['line_end']))

    def test_candidate_cannot_claim_confirmed_fault_needs_no_patch(self):
        with GitFixture() as fx:
            response = impact_reply(fx, 'AFFECTED', [{'unit_id': 'f001-h001', 'target_indices': [1]}])
            outcome, _, _ = self.execute(fx, response, extras=[
                ('HUNK-RESULT f001-h001 need_not_ported evidence=already_present', write_counter(FIXED)),
            ])
            self.assertEqual(outcome['delivery_status'], 'BLOCKED')
            record = Path(outcome['final_round_record']).parent / 'repositories/repo/run.json'
            child = json.loads(record.read_text())
            self.assertEqual(child['status'], 'VALIDATION_FAILED')
            self.assertTrue(any('confirmed donor fault requires a covered target edit' in str(e)
                                for e in child['events']))

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
