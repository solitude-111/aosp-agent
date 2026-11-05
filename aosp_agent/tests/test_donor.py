import json
import unittest
from pathlib import Path

from aosp_agent.donor import verify_donor
from aosp_agent.diff_engine import DiffBackportAgent
from aosp_agent.agent_tools import RunContext
from engine_fixtures import GitFixture, git


class DonorTest(unittest.TestCase):
    def test_pins_and_restores_history_tools_without_worktree(self):
        with GitFixture() as fx:
            patch = git(fx.repo, 'diff', fx.target, fx.donor) + '\n'
            path = fx.root / 'input.patch'
            path.write_text(patch)
            agent = DiffBackportAgent(path, fx.repo, fx.run_root, donor_repo=fx.repo,
                                      source_commit=fx.donor, source_parent=fx.target)
            result = agent.run(inspect_only=True)
            self.assertEqual(result['source_provenance']['status'], 'VERIFIED')
            context = RunContext(agent.run_dir)
            self.assertEqual(context.check_ref(fx.donor, 'donor'), fx.donor)
            self.assertTrue((agent.run_dir / 'bin/hunk-history').is_file())
            self.assertFalse(agent.workspace.exists())
            self.assertIn('LOCAL_ONLY', json.dumps(result))

    def test_rejects_mismatched_patch_and_wrong_parent(self):
        with GitFixture() as fx:
            patch = git(fx.repo, 'diff', fx.target, fx.donor) + '\n'
            with self.assertRaisesRegex(ValueError, 'does not match'):
                verify_donor(fx.repo, fx.donor, fx.target, patch.replace('min(value, 10)', 'min(value, 11)'))
            with self.assertRaisesRegex(ValueError, 'direct parent'):
                verify_donor(fx.repo, fx.donor, fx.donor, patch)

    def test_partial_identity_cannot_silently_downgrade(self):
        with self.assertRaisesRegex(ValueError, 'together'):
            verify_donor(Path('.'), None, None, '')
        self.assertEqual(verify_donor(None, None, None, '')['history'], 'NOT_AVAILABLE')
