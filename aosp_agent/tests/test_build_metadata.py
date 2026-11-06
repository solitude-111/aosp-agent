"""Pinned metadata reuse must preserve unresolved consumers and fresh reads."""
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent import blueprint_literals, build_metadata
from aosp_agent.build_discovery import discover_build
from aosp_agent.discovery import repositories
from aosp_agent.retrieval import ObjectCache
from engine_fixtures import GitFixture, git


def prepare(fx, metadata='java_library {name: "main", srcs: ["*.java"], exclude_srcs: ["B.java"]}', others=0):
    (fx.repo / 'Android.bp').write_text(metadata)
    (fx.repo / 'A.java').write_text('class A {}\n')
    for i in range(others):
        directory = fx.repo / f'other{i}'
        directory.mkdir()
        (directory / 'Android.bp').write_text(f'java_library {{name: "other{i}", srcs: ["C.java"]}}')
    git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'build metadata')
    return repositories(fx.repo, lazy=True, cache=ObjectCache(fx.root / 'objects'))[0]


def index_rows(cache):
    result = []
    for path in cache.directory.rglob('*.json'):
        row = json.loads(path.read_text())
        if json.loads(row['identity'])[3][0] == '@blueprint-metadata-index-v1':
            result.append((path, row))
    return result


class BuildMetadataTest(unittest.TestCase):
    def test_new_instance_reuses_index_without_tree_reads_or_parsing(self):
        with GitFixture() as fx:
            repo = prepare(fx, others=30)
            with patch.object(repo, 'read', wraps=repo.read) as reads:
                before = discover_build(repo, ['A.java'])
            self.assertEqual(before['status'], 'RESOLVED')
            self.assertEqual(reads.call_count, 31)
            second = repositories(fx.repo, lazy=True, cache=ObjectCache(fx.root / 'objects'))[0]
            with patch.object(second, 'read', side_effect=AssertionError('no metadata reads')), \
                 patch.object(second.files, 'enumerate', side_effect=AssertionError('no tree scan')), \
                 patch.object(blueprint_literals, 'parse_metadata', side_effect=AssertionError('no reparse')):
                self.assertEqual(discover_build(second, ['A.java']), before)
            self.assertFalse(second.files.complete)
            self.assertEqual(second.files.cache.hits, 1)

    def test_index_contains_facts_not_cached_path_decisions(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
            with patch.object(repo, 'read', side_effect=AssertionError('reuse metadata')):
                result = discover_build(repo, ['B.java'])
            self.assertEqual(result['status'], 'UNRESOLVED')
            self.assertEqual(result['production_uncovered'], ['B.java'])
            self.assertEqual(result['modules'], [])

    def test_revision_change_invalidates_but_dirty_worktree_cannot_change_pinned_facts(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
            (fx.repo / 'Android.bp').write_text('java_library {name: "main", srcs: ["B.java"]}')
            self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
            git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'different source owner')
            changed = repositories(fx.repo, lazy=True, cache=repo.files.cache)[0]
            self.assertNotEqual(changed.head, repo.head)
            self.assertEqual(discover_build(changed, ['A.java'])['status'], 'UNRESOLVED')
            self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')

    def test_transient_read_failure_is_never_persisted_as_missing_consumer(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            with patch.object(repo, 'read', side_effect=subprocess.TimeoutExpired('git', 1)):
                result = discover_build(repo, ['A.java'])
            self.assertEqual(result['status'], 'UNRESOLVED')
            self.assertTrue(result['issues'])
            self.assertEqual(index_rows(repo.files.cache), [])
            self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')

    def test_immutable_unknown_scope_is_preserved_on_reuse(self):
        with GitFixture() as fx:
            repo = prepare(fx, 'soong_namespace {}\njava_library {name: "main", srcs: ["A.java"]}')
            result = discover_build(repo, ['A.java'])
            self.assertEqual(result['status'], 'UNRESOLVED')
            self.assertTrue(result['unresolved_consumers'])
            self.assertEqual(len(index_rows(repo.files.cache)), 1)
            with patch.object(repo, 'read', side_effect=AssertionError('reuse facts, including unknowns')):
                self.assertEqual(discover_build(repo, ['A.java']), result)

    def test_parser_policy_and_scan_limit_cannot_reuse_more_permissive_index(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            original = discover_build(repo, ['A.java'])
            self.assertEqual(original['status'], 'RESOLVED')
            with patch.object(blueprint_literals, 'MAX_ITEMS', 5):
                limited = discover_build(repo, ['A.java'])
            self.assertEqual(limited['status'], 'UNRESOLVED')
            self.assertNotEqual(limited['metadata_index']['policy'], original['metadata_index']['policy'])
            self.assertEqual(discover_build(repo, ['A.java'], limit=0)['status'], 'UNRESOLVED')
            self.assertEqual(discover_build(repo, ['A.java']), original)

    def test_oversized_index_bypasses_storage_without_losing_valid_facts(self):
        with GitFixture() as fx:
            repo = prepare(fx, 'java_library {name: "main", srcs: ["A.java"], description: "' + 'x' * 3000 + '"}')
            repo.files.cache = ObjectCache(fx.root / 'small', max_entry_bytes=1024, max_bytes=4096)
            for _ in range(2):
                self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
            self.assertEqual(index_rows(repo.files.cache), [])

    def test_invalid_cached_schema_falls_back_to_pinned_source(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            original = discover_build(repo, ['A.java'])
            path, row = index_rows(repo.files.cache)[0]
            row['result']['stdout'] = '{"broken": true}'
            row['sha256'] = hashlib.sha256(json.dumps(row['result'], sort_keys=True).encode()).hexdigest()
            path.write_text(json.dumps(row))
            with patch.object(repo, 'read', wraps=repo.read) as reads:
                self.assertEqual(discover_build(repo, ['A.java']), original)
            self.assertEqual(reads.call_count, 1)

    def test_missing_parser_source_or_unavailable_cache_keeps_uncached_behavior(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            with patch.object(build_metadata, 'parser_identity', side_effect=OSError('source unavailable')):
                self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
            unavailable = fx.root / 'not-a-directory'
            unavailable.write_text('occupied')
            repo.files.cache = ObjectCache(unavailable)
            self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')

    def test_inconsistent_pinned_tree_identity_cannot_use_index(self):
        with GitFixture() as fx:
            repo = prepare(fx)
            discover_build(repo, ['A.java'])
            repo.files.head = 'a' * 40
            with self.assertRaisesRegex(ValueError, 'matching pinned tree'):
                discover_build(repo, ['A.java'])
