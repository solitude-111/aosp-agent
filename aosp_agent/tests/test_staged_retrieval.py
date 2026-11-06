"""Progressive immutable reads preserve uncertainty and moved implementations."""
import copy
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent import discovery
from aosp_agent.diff_prompts import assessment_prompt
from aosp_agent.discovery import Locator, diff_units, repositories
from aosp_agent.retrieval import ObjectCache
from engine_fixtures import GitFixture, git
from test_diff_workflow import diff


BEFORE = ('class Counter {\n int acceptCount(int requestedCount) {\n'
          '  return storage.queueCount(requestedCount);\n }\n}\n')
AFTER = BEFORE.replace('  return', '  if (requestedCount < 0) return 0;\n  return')


class StagedRetrievalTest(unittest.TestCase):
    def seed(self, fx, files):
        for path, content in files.items():
            target = fx.repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'ordinary retrieval fixture')

    def locate(self, fx, path, *, cache=None, scan_limit=100):
        repo = repositories(fx.repo, lazy=True, cache=cache)[0]
        units = diff_units(diff(path, BEFORE, AFTER))
        with patch.object(discovery, 'local_git', wraps=discovery.local_git) as reads:
            result = Locator([repo], units, scan_limit=scan_limit).locate()
        return repo, result, [c.args[1:] for c in reads.call_args_list]

    def test_direct_text_anchor_defers_search_without_claiming_scope_or_impact(self):
        with GitFixture() as fx:
            self.seed(fx, {'services/Counter.java': BEFORE, 'other/Counter.java': BEFORE})
            repo, result, calls = self.locate(fx, 'services/Counter.java')
            self.assertFalse(repo.files.complete)
            self.assertFalse(any(c[0] == 'grep' or c[0] == 'ls-tree' and '-r' in c for c in calls))
            self.assertEqual(sum(c[0] == 'show' for c in calls), 1)
            self.assertEqual(result['impact'], 'UNASSESSED')
            scope = result['units'][0]['retrieval'][0]
            self.assertEqual(scope['stage'], 'DIRECT_FILES')
            self.assertEqual(scope['project_search'], 'DEFERRED')
            self.assertFalse(scope['scope_complete'])
            self.assertFalse(scope['absence_proven'])
            self.assertEqual(scope['text_anchors'][0]['semantic_identity'], 'UNASSESSED')
            # The unchanged second copy is unsearched, not certified irrelevant.
            self.assertEqual([c['path'] for c in result['units'][0]['candidates']], ['services/Counter.java'])

    def test_renamed_neighbor_uses_scoped_search_not_full_project_search(self):
        with GitFixture() as fx:
            self.seed(fx, {'services/Legacy.java': BEFORE, 'other/Other.java': BEFORE})
            repo, result, calls = self.locate(fx, 'services/Modern.java')
            searches = [c for c in calls if c[0] == 'grep']
            self.assertTrue(searches)
            self.assertLessEqual(len(searches), 3)
            self.assertTrue(all(c[-1] == ':(literal)services' for c in searches))
            self.assertFalse(repo.files.complete)
            self.assertEqual(result['units'][0]['retrieval'][0]['stage'], 'NEARBY_DIRECTORIES')
            self.assertIn('services/Legacy.java', [c['path'] for c in result['units'][0]['candidates']])
            self.assertNotIn('other/Other.java', [c['path'] for c in result['units'][0]['candidates']])

    def test_unrelated_exact_name_escalates_and_keeps_remote_directory_implementation(self):
        with GitFixture() as fx:
            self.seed(fx, {'services/Modern.java': 'class Modern { int unrelated() { return 7; } }\n',
                           'legacy/Implementation.java': BEFORE})
            _, result, calls = self.locate(fx, 'services/Modern.java')
            self.assertTrue(any(c[0] == 'grep' and c[-1] == '--' for c in calls))
            self.assertIn('legacy/Implementation.java', [c['path'] for c in result['units'][0]['candidates']])
            scope = result['units'][0]['retrieval'][0]
            self.assertEqual(scope['stage'], 'ADMITTED_PROJECT')
            self.assertFalse(scope['scope_complete'])

    def test_global_path_hint_can_avoid_global_content_search(self):
        with GitFixture() as fx:
            self.seed(fx, {'old/Counter.java': BEFORE})
            repo, result, calls = self.locate(fx, 'new/Counter.java')
            self.assertTrue(repo.files.complete)
            self.assertFalse(any(c[0] == 'grep' for c in calls))
            self.assertEqual(result['units'][0]['retrieval'][0]['stage'], 'PROJECT_PATHS')
            self.assertEqual(result['units'][0]['retrieval'][0]['project_search'], 'DEFERRED')

    def test_scoped_tree_cache_is_pinned_and_does_not_become_full_inventory(self):
        with GitFixture() as fx:
            self.seed(fx, {'services/Counter.java': BEFORE, 'other/Counter.java': BEFORE})
            cache_root = fx.root / 'cache'
            repo = repositories(fx.repo, lazy=True, cache=ObjectCache(cache_root))[0]
            first = repo.files.paths_under('services')
            self.assertEqual(set(first), {'services/Counter.java'})
            self.assertFalse(repo.files.complete)
            second = repositories(fx.repo, lazy=True, cache=ObjectCache(cache_root))[0]
            (fx.repo / 'services' / 'Counter.java').write_text('uncommitted change')
            with patch.object(discovery, 'local_git', side_effect=AssertionError('reuse pinned subtree')):
                self.assertEqual(second.files.paths_under('services'), first)
            self.assertFalse(second.files.complete)

    def test_direct_read_error_remains_an_error_after_fallback(self):
        with GitFixture() as fx:
            self.seed(fx, {'services/Counter.java': BEFORE})
            original = discovery.local_git
            def fail(root, *args, **kwargs):
                if args[0] == 'show' and args[-1].endswith(':services/Counter.java'):
                    raise subprocess.TimeoutExpired(['git', 'show'], 1)
                return original(root, *args, **kwargs)
            with patch.object(discovery, 'local_git', side_effect=fail):
                _, result, _ = self.locate(fx, 'services/Counter.java')
            self.assertTrue(any(i.get('stage') == 'read' and i.get('error') for i in result['issues']))
            self.assertEqual(result['units'][0]['retrieval'][0]['text_anchors'], [])
            self.assertEqual(result['impact'], 'UNASSESSED')

    def test_file_read_limit_is_shared_across_stages(self):
        with GitFixture() as fx:
            self.seed(fx, {'a/Counter.java': 'class Wrong { int unrelated() { return 7; } }\n',
                           'b/Counter.java': BEFORE, 'c/Counter.java': BEFORE})
            _, result, calls = self.locate(fx, 'missing/Counter.java', scan_limit=1)
            self.assertLessEqual(sum(c[0] == 'show' for c in calls), 1)
            self.assertTrue(any(i.get('status') == 'TRUNCATED' for i in result['issues']))
            self.assertFalse(result['retrieval_summary']['scope_complete'])
            self.assertEqual(result['impact'], 'UNASSESSED')

    def test_deferred_limits_reach_assessment_and_independent_review(self):
        from aosp_agent.exclusion_review import review_prompt
        from types import SimpleNamespace
        with GitFixture() as fx:
            self.seed(fx, {'Counter.java': BEFORE})
            _, result, _ = self.locate(fx, 'Counter.java')
            result.update(source_history={}, target_history=[])
            prompt = assessment_prompt(diff('Counter.java', BEFORE, AFTER), [], result)
            self.assertIn('DEFERRED', prompt)
            self.assertIn('NOT SEARCHED', prompt)
            self.assertIn('semantic_identity', prompt)
            controller = SimpleNamespace(record={'retrieval_summary': copy.deepcopy(result['retrieval_summary'])},
                                         diff='ordinary counter diff', _donor_tools_context=lambda: '')
            review = review_prompt(controller, {'units': [{'id': 'u', 'status': 'NOT_AFFECTED'}]}, [])
            self.assertIn('deferred_project_searches', review)
            self.assertIn('not absent', review)

    def test_model_prompt_bounds_retrieval_metadata_but_keeps_complete_saved_evidence(self):
        with GitFixture() as fx:
            self.seed(fx, {'Counter.java': BEFORE})
            _, result, _ = self.locate(fx, 'Counter.java')
            result.update(source_history={}, target_history=[])
            row = result['units'][0]['retrieval'][0]
            row['text_anchors'] = [{'path': 'nonessential_anchor_marker', 'regions': [1, 2, 3]}] * 5000
            result['units'][0]['retrieval'] = [row] * 20
            prompt = assessment_prompt(diff('Counter.java', BEFORE, AFTER), [], result)
            self.assertNotIn('nonessential_anchor_marker', prompt)
            self.assertIn('"text_anchor_count": 5000', prompt)
            self.assertIn('"retrieval_records_total": 20', prompt)
            self.assertIn('"retrieval_records_truncated": true', prompt)
            self.assertEqual(prompt.count('"text_anchor_count"'), 12)
            self.assertIn('complete scopes and text-anchor', prompt)
            self.assertEqual(len(result['units'][0]['retrieval'][0]['text_anchors']), 5000)
