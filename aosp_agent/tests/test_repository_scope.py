import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from aosp_agent import discovery
from aosp_agent.diff_engine import DiffBackportAgent
from engine_fixtures import BASELINE, FIXED, GitFixture, git
import test_diff_workflow as workflow


class RepositoryScopeTest(unittest.TestCase):
    def test_explicit_scope_does_not_enumerate_or_read_unselected_repository(self):
        with GitFixture() as fx:
            broken = fx.source_root / 'unused'; broken.mkdir()
            (broken / '.git').write_text('gitdir: unavailable\n')
            original = discovery.local_git
            def guarded(root, *args, **kwargs):
                self.assertNotEqual(Path(root), broken)
                return original(root, *args, **kwargs)
            with (patch('aosp_agent.diff_engine.repository_roots', side_effect=AssertionError('must not walk whole tree')),
                  patch.object(discovery, 'local_git', side_effect=guarded)):
                agent = DiffBackportAgent(workflow.diff('new.py', BASELINE, FIXED).encode(), fx.source_root,
                                         fx.run_root, repository_keys=['repo'])
                result = agent.run(inspect_only=True)
            self.assertEqual(result['status'], 'DISCOVERED')
            self.assertEqual(result['analysis_scope']['projects'], ['repo'])
            self.assertFalse(result['analysis_scope']['whole_tree_discovery_evaluated'])
            self.assertEqual([r.key for r in agent.repos], ['repo'])

    def test_selected_unavailable_project_is_required_not_quarantined(self):
        with GitFixture() as fx:
            original = discovery.local_git
            def broken(root, *args, **kwargs):
                if args[0] == 'ls-tree':
                    raise subprocess.CalledProcessError(128, ['git', 'ls-tree'])
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=broken), self.assertRaisesRegex(ValueError, 'pinned target'):
                DiffBackportAgent(workflow.diff('new.py', BASELINE, FIXED).encode(), fx.source_root,
                                  fx.run_root, repository_keys=['repo'])

    def test_explicit_multi_project_scope_keeps_both(self):
        with GitFixture() as fx:
            peer = fx.source_root / 'peer'; peer.mkdir(); git(peer, 'init', '-q')
            (peer / 'helper.py').write_text('def helper():\n    return 1\n')
            git(peer, 'add', '.'); git(peer, 'commit', '-qm', 'peer')
            agent = DiffBackportAgent(workflow.diff('new.py', BASELINE, FIXED).encode(), fx.source_root,
                                     fx.run_root, repository_keys=['repo', 'peer', 'repo'])
            self.assertEqual({r.key for r in agent.repos}, {'repo', 'peer'})
            self.assertEqual(set(agent.before), {'repo', 'peer'})

    def test_cli_accepts_project_scope_without_launching_model(self):
        with GitFixture() as fx:
            patch_file = fx.root / 'input.patch'; patch_file.write_text(workflow.diff('new.py', BASELINE, FIXED))
            run = subprocess.run([sys.executable, '-m', 'aosp_agent', 'diff', '--patch', str(patch_file),
                                  '--target-root', str(fx.source_root), '--run-root', str(fx.run_root),
                                  '--repository', 'repo', '--inspect-only'], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(run.stdout)
            self.assertEqual(result['status'], 'DISCOVERED')
            record = json.loads(Path(result['record']).read_text())
            self.assertEqual(record['analysis_scope']['projects'], ['repo'])
