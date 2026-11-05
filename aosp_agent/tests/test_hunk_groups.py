import hashlib
import unittest

from aosp_agent.hunk_groups import review_groups
from aosp_agent.patches import split_hunks
from aosp_agent.engine import AospBackportAgent
from engine_fixtures import GitFixture, ScriptedRuntime, write_counter, FIXED


class HunkGroupTest(unittest.TestCase):
    def large_diff(self):
        return ('diff --git a/code.c b/code.c\n--- a/code.c\n+++ b/code.c\n' + ''.join(
            f'@@ -{n * 4 + 1} +{n * 4 + 1} @@\n-old_{n}();\n+if (limit_{n}) new_{n}();\n' for n in range(64)))

    def test_64_hunks_are_batched_without_dropping_or_merging_obligations(self):
        hunks = split_hunks(self.large_diff())
        report = review_groups(hunks)
        self.assertEqual(len(report['groups']), 8)
        self.assertEqual([i for g in report['groups'] for i in g['hunk_ids']], [h['id'] for h in hunks])
        self.assertEqual(report['required_hunk_ids'], [h['id'] for h in hunks])
        self.assertFalse(report['exclusion_authority'])
        for entry, hunk in zip(report['entries'], hunks):
            self.assertEqual(entry['patch_sha256'], hashlib.sha256(hunk['patch'].encode()).hexdigest())
            for e in entry['hint_evidence']:
                self.assertEqual(hunk['patch'].splitlines()[e['patch_line'] - 1], e['text'])

    def test_build_test_and_unsupported_changes_remain_review_obligations(self):
        diff = ('diff --git a/Android.bp b/Android.bp\n--- a/Android.bp\n+++ b/Android.bp\n@@ -1 +1 @@\n-old\n+new\n'
                'diff --git a/tests/a.bin b/tests/a.bin\nBinary files a/tests/a.bin and b/tests/a.bin differ\n')
        report = review_groups(split_hunks(diff))
        self.assertEqual(report['total_hunks'], 2)
        self.assertEqual(report['entries'][0]['role_hint'], 'build_configuration')
        self.assertEqual(report['entries'][1]['operation'], 'unsupported')
        self.assertTrue(all(e['requires_individual_review'] for e in report['entries']))

    def test_grouping_does_not_excuse_a_missing_ledger_declaration(self):
        with GitFixture() as fx:
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case())
            agent.prepare()
            agent._current_hunks = split_hunks(self.large_diff())
            review_groups(agent._current_hunks)
            result = agent._check_hunk_results('', [], '')
            self.assertFalse(result['ok'])
            self.assertEqual(len(result['coverage']['missing']), 64)

    def test_version_copy_hint_never_removes_diff_from_actual_model_prompt(self):
        with GitFixture() as fx:
            runtime = ScriptedRuntime(fx.assessment(), [write_counter(FIXED)])
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case(), runtime_factory=runtime.factory)
            agent.prepare()
            inspection = agent.inspect()
            metadata = '\ndiff --git a/METADATA b/METADATA\n--- a/METADATA\n+++ b/METADATA\n@@ -1 +1 @@\n-3.44.3\n+3.44.5\n'
            inspection['source_diff'] += metadata
            agent.commit_message = 'copy sqlite version'
            agent._codex_workflow(inspection, verify=False, max_attempts=1, mechanical=False, impact_only=True)
            prompt = runtime.calls[0]['prompt']
            self.assertIn('+3.44.5', prompt)
            self.assertIn('Controller review batches', prompt)
            self.assertEqual(agent.record['donor_diff_preprocessed']['filtered_hunks'], 0)

    def test_duplicate_id_is_rejected(self):
        h = split_hunks(self.large_diff())[0]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            review_groups([h, h])
