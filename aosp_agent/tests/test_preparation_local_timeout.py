"""Local preparation time is finite, explicit, and subordinate to shared budgets."""
import json
from unittest import TestCase, mock

from engine_fixtures import GitFixture
from test_preparation import MemoryMounts, setup
from aosp_agent.execution_budget import ExecutionBudget
from aosp_agent.preparation import PreparationManager, PreparationError
from aosp_agent.runtime_input import RuntimeInput
from aosp_agent.server_config import validate_config
from aosp_agent.tool_io import ToolIO


class PreparationLocalTimeoutTest(TestCase):
    def test_timeout_policy_preserves_explicit_limits_and_cleanliness_gate(self):
        with GitFixture() as fixture:
            raw, row = setup(fixture)
            self.assertEqual(validate_config(raw)['preparation']['local_command_timeout'], 60)
            for invalid in (0, -1, True, None, 1.5, float('inf')):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    validate_config({**raw, 'preparation': {**raw['preparation'],
                                                         'local_command_timeout': invalid}})
            original_run, observed = ToolIO.run, []

            def observed_run(io, argv, **kwargs):
                observed.append((list(argv), kwargs['timeout']))
                return original_run(io, argv, **kwargs)

            manager = PreparationManager(raw, overlays=MemoryMounts())
            with mock.patch.object(ToolIO, 'run', autospec=True, side_effect=observed_run):
                manager._git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertEqual(observed[-1][1], 60)
                raw['preparation']['local_command_timeout'] = 120
                manager = PreparationManager(raw, overlays=MemoryMounts())
                manager._git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertEqual(observed[-1][1], 120)
                # Named-reference, advertisement, fetch and switch callers keep
                # their explicit limits, independently of the local default.
                for explicit in (3, 30, 600, 120):
                    manager._git(fixture.repo, 'rev-parse', 'HEAD', timeout=explicit)
                    self.assertEqual(observed[-1][1], explicit)
                manager.seconds_used = manager.policy['max_seconds'] - 7
                manager._git(fixture.repo, 'rev-parse', 'HEAD')
                self.assertLessEqual(observed[-1][1], 7)
                self.assertGreater(observed[-1][1], 6)
                manager.seconds_used = 0
                ledger = ExecutionBudget(fixture.run_root / 'case', 'fixture',
                                         limits={'execution_seconds': 2})
                with ledger.active():
                    manager._git(fixture.repo, 'rev-parse', 'HEAD')
                    self.assertGreater(observed[-1][1], 0)
                    self.assertLessEqual(observed[-1][1], 2)
                self.assertEqual(ledger.snapshot()['consumed']['tool_operations'], 1)

                manager.freeze_inputs([(1, json.dumps(row))], fixture.run_root)
                prepared = manager.prepare(RuntimeInput.parse(row), fixture.run_root / 'row')
                try:
                    changed = fixture.repo / 'counter.py'
                    changed.write_text(changed.read_text() + '\n# dirty fixture\n')
                    with self.assertRaises(PreparationError) as caught:
                        prepared.materialize('repo')
                    self.assertEqual(caught.exception.kind, 'TARGET_BASELINE_DIRTY')
                    status = [argv for argv, _ in observed if 'status' in argv][-1]
                    self.assertIn('core.fsmonitor=false', status)
                    self.assertIn('--untracked-files=normal', status)
                    self.assertNotIn('repo', prepared.materialized)
                finally:
                    manager.release(prepared)
