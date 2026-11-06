"""Selected-project retrieval must preserve moved implementations and consumers."""
import json
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent import discovery
from aosp_agent.build_discovery import discover_build
from aosp_agent.discovery import Locator, diff_units, repositories
from aosp_agent.retrieval import ObjectCache, ReadBudget, BudgetExceeded
from engine_fixtures import GitFixture, git
from test_diff_workflow import diff


class RetrievalTest(unittest.TestCase):
    def test_exact_blob_read_does_not_enumerate_and_cache_survives_new_instance(self):
        with GitFixture() as fx:
            cache = ObjectCache(fx.root / 'objects')
            repo = repositories(fx.repo, lazy=True, cache=cache)[0]
            with patch.object(discovery, 'local_git', wraps=discovery.local_git) as calls:
                expected = repo.read('counter.py')
                self.assertFalse(repo.files.complete)
                self.assertFalse(any('-r' in c.args for c in calls.call_args_list))
            second = repositories(fx.repo, lazy=True, cache=ObjectCache(fx.root / 'objects'))[0]
            with patch.object(discovery, 'local_git', side_effect=AssertionError('cached pinned blob must be reused')):
                self.assertEqual(second.read('counter.py'), expected)
            self.assertEqual(second.files.cache.hits, 3)

    def test_exact_unrelated_file_does_not_hide_moved_implementation(self):
        with GitFixture() as fx:
            before = 'class Legacy {\n int acceptCount(int requestedCount) {\n  return storage.queueCount(requestedCount);\n }\n}\n'
            after = before.replace('  return', '  if (requestedCount < 0) return 0;\n  return')
            (fx.repo / 'Modern.java').write_text('class Modern { int unrelated() { return 7; } }\n')
            (fx.repo / 'Legacy.java').write_text(before)
            git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'old implementation moved')
            repo = repositories(fx.repo, lazy=True)[0]
            report = Locator([repo], diff_units(diff('Modern.java', before, after))).locate()
            self.assertIn('Legacy.java', [c['path'] for c in report['units'][0]['candidates']])
            self.assertFalse(repo.files.complete, 'symbol search should not require a full tree listing')

    def test_build_index_includes_production_consumer_even_if_local_test_owns_source(self):
        with GitFixture() as fx:
            (fx.repo / 'src').mkdir(); (fx.repo / 'app').mkdir()
            (fx.repo / 'src/a.cpp').write_text('int a() { return 0; }\n')
            (fx.repo / 'src/Android.bp').write_text('cc_test { name: "local_test", srcs: ["a.cpp"] }\nfilegroup { name: "shared_src", srcs: ["a.cpp"] }\n')
            (fx.repo / 'app/Android.bp').write_text('cc_library { name: "production", srcs: [":shared_src"] }\n')
            git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'shared production sources')
            repo = repositories(fx.repo, lazy=True, cache=ObjectCache(fx.root / 'objects'))[0]
            result = discover_build(repo, ['src/a.cpp'])
            self.assertEqual(result['status'], 'RESOLVED')
            self.assertEqual({m['name'] for m in result['modules']}, {'local_test', 'production'})
            with patch.object(discovery, 'local_git', side_effect=AssertionError('reuse immutable metadata')):
                self.assertEqual(discover_build(repo, ['src/a.cpp']), result)

    def test_cache_never_persists_read_failures_and_rejects_corruption(self):
        with GitFixture() as fx:
            cache = ObjectCache(fx.root / 'cache')
            args = ('show', fx.target + ':counter.py')
            calls = []
            def run():
                calls.append(1)
                return subprocess.CompletedProcess(args, 128 if len(calls) == 1 else 0, 'verified', '')
            self.assertEqual(cache.query(fx.repo, fx.target, args, run).returncode, 128)
            self.assertEqual(cache.query(fx.repo, fx.target, args, run).returncode, 0)
            self.assertEqual(len(calls), 2)
            path = next(cache.directory.rglob('*.json'))
            row = json.loads(path.read_text()); row['result']['stdout'] = 'corrupt'
            path.write_text(json.dumps(row))
            self.assertEqual(cache.query(fx.repo, fx.target, args, run).stdout, 'verified')
            self.assertEqual(len(calls), 3)

    def test_commit_change_misses_cache_and_workspace_guards_are_fresh(self):
        with GitFixture() as fx:
            cache = ObjectCache(fx.root / 'cache')
            baseline = repositories(fx.repo, lazy=True, cache=cache)[0]
            original = baseline.read('counter.py')
            fixed = repositories(fx.repo, lazy=True, cache=cache, pinned_heads={'repo': fx.donor})[0]
            self.assertNotEqual(original, fixed.read('counter.py'))
            before = baseline.state()
            (fx.repo / 'counter.py').write_text('modified original\n')
            self.assertNotEqual(baseline.state(), before)
            self.assertEqual(baseline.read('counter.py'), original)

    def test_controller_git_budget_blocks_before_second_process(self):
        with GitFixture() as fx:
            budget = ReadBudget(seconds=10, operations=1)
            with budget.active():
                discovery.local_git(fx.repo, 'rev-parse', 'HEAD')
                with self.assertRaises(BudgetExceeded):
                    discovery.local_git(fx.repo, 'rev-parse', 'HEAD')
            self.assertEqual(budget.used, 1)
