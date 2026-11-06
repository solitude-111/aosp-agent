import json
from pathlib import Path
import unittest

from aosp_agent.runtime_input import RuntimeInput, load_jsonl, resolve_sources
from engine_fixtures import GitFixture, git


ORIGIN = 'https://android.googlesource.com/platform/repo'


class RuntimeInputTest(unittest.TestCase):
    def row(self, fx, **changes):
        return dict({'source_commit_sequence': [fx.donor], 'source_parent_sequence': [fx.target],
                     'donor_repositories': [ORIGIN], 'target_revision': 'release-target'}, **changes)

    def test_multiple_donors_are_candidates_not_positional_pairs(self):
        with GitFixture() as fx:
            unrelated = 'https://android.googlesource.com/platform/unrelated'
            task = RuntimeInput.parse(self.row(fx, donor_repositories=[unrelated, ORIGIN, ORIGIN]))
            result = resolve_sources(task, fx.root / 'cache', donor_map={ORIGIN: fx.repo})
            self.assertEqual(len(task.donors), 2)
            self.assertEqual(result['status'], 'READY')
            self.assertEqual(result['sources'][0]['source_candidates'][0]['origin'], ORIGIN)
            self.assertEqual(result['sources'][0]['candidate_failures'][0]['origin'], unrelated)
            self.assertFalse(result['network_access'])

    def test_mirror_containment_is_not_unique_project_ownership(self):
        with GitFixture() as fx:
            mirror = 'https://mirror.example.invalid/platform/repo'
            task = RuntimeInput.parse(self.row(fx, donor_repositories=[ORIGIN, mirror]))
            result = resolve_sources(task, fx.root, donor_map={ORIGIN: fx.repo, mirror: fx.repo})
            self.assertEqual(result['status'], 'READY')
            self.assertFalse(result['sources'][0]['unique_project'])
            self.assertEqual(len(result['sources'][0]['source_candidates']), 2)

    def test_multiple_commits_in_one_donor_preserve_all_steps(self):
        with GitFixture() as fx:
            git(fx.repo, 'checkout', '--detach', '-q', fx.donor)
            (fx.repo / 'counter.py').write_text('def normalize_count(value):\n    return max(1, min(value, 9))\n')
            git(fx.repo, 'commit', '-qam', 'follow-up')
            second = git(fx.repo, 'rev-parse', 'HEAD')
            task = RuntimeInput.parse(self.row(fx, source_commit_sequence=[fx.donor, second],
                                              source_parent_sequence=[fx.target, fx.donor]))
            result = resolve_sources(task, fx.root, donor_map={ORIGIN: fx.repo})
            self.assertEqual(result['status'], 'READY')
            self.assertEqual([s['source_commit'] for s in result['sources']], [fx.donor, second])
            self.assertEqual(result['dependency_edges'], [{'before': 's001', 'after': 's002', 'basis': 'direct_parent'}])

    def test_missing_or_wrong_parent_never_yields_partial_ready(self):
        with GitFixture() as fx:
            task = RuntimeInput.parse(self.row(fx, source_commit_sequence=[fx.donor, fx.target],
                                              source_parent_sequence=[fx.target, fx.donor]))
            result = resolve_sources(task, fx.root, donor_map={ORIGIN: fx.repo})
            self.assertEqual(result['status'], 'INPUT_UNRESOLVED')
            self.assertEqual(len(result['sources']), 1)
            self.assertEqual(result['problems'][0]['step'], 2)

    def test_jsonl_load_rejects_unpaired_steps_and_answer_fields(self):
        with GitFixture() as fx:
            path = fx.root / 'input.jsonl'
            path.write_text(json.dumps(self.row(fx)) + '\n\n' + json.dumps(self.row(fx)) + '\n')
            rows = load_jsonl(path)
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].task_id, rows[1].task_id)
            for changes in ({'source_parent_sequence': []}, {'impact': 'AFFECTED'},
                            {'target_revision': '--all'}, {'donor_repositories': ['https://user:secret@example.invalid/repo']}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    RuntimeInput.parse(self.row(fx, **changes))

    def test_donor_directory_cannot_inherit_parent_repository(self):
        with GitFixture() as fx:
            nested = fx.repo / 'not-a-repository'; nested.mkdir()
            result = resolve_sources(RuntimeInput.parse(self.row(fx)), fx.root, donor_map={ORIGIN: nested})
            self.assertEqual(result['status'], 'INPUT_UNRESOLVED')
            self.assertIn('not a repository root', result['problems'][0]['candidates'][0]['detail'])
