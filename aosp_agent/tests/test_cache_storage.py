"""Cache capacity, corruption, contention and write failure are never source facts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from aosp_agent.retrieval import ObjectCache


class CacheStorageTest(unittest.TestCase):
    def query(self, cache, name, text='verified', code=0):
        return cache.query(cache.directory.parent, 'a' * 40, ('show', name),
                           lambda: subprocess.CompletedProcess([], code, text, ''))

    def test_byte_and_entry_caps_with_lru_hits(self):
        with tempfile.TemporaryDirectory() as raw:
            cache = ObjectCache(Path(raw) / 'cache', max_bytes=2400, max_entry_bytes=1200, max_entries=2)
            for name in ('a', 'b'):
                self.query(cache, name, 'x' * 500)
            self.query(cache, 'a', 'unexpected miss')
            self.query(cache, 'c', 'x' * 500)
            hits = cache.hits
            self.assertEqual(self.query(cache, 'a', 'miss').stdout, 'x' * 500)
            self.assertEqual(cache.hits, hits + 1)
            self.assertEqual(self.query(cache, 'b', 'reread').stdout, 'reread')
            self.assertLessEqual(len(list(cache.directory.rglob('*.json'))), 2)
            self.assertLessEqual(sum(p.stat().st_size for p in cache.directory.rglob('*') if p.is_file()), 2400)
            self.assertGreater(cache.evicted, 0)

    def test_oversized_entry_bypasses_cache_without_losing_source_result(self):
        with tempfile.TemporaryDirectory() as raw:
            cache = ObjectCache(Path(raw) / 'cache', max_entry_bytes=700)
            for _ in range(2):
                self.assertEqual(len(self.query(cache, 'large', 'x' * 1000).stdout), 1000)
            self.assertEqual(cache.hits, 0)
            self.assertEqual(list(cache.directory.rglob('*.json')), [])
            self.assertEqual(cache.bypassed, 2)

    def test_existing_writer_cannot_undo_a_tighter_shared_quota(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / 'cache'
            larger = ObjectCache(root, max_bytes=6000, max_entry_bytes=2000)
            for n in range(5): self.query(larger, str(n), 'x' * 500)
            smaller = ObjectCache(root, max_bytes=1500, max_entry_bytes=1200)
            self.query(smaller, 'new', 'x' * 500)
            self.query(larger, 'old-writer', 'x' * 500)
            self.assertEqual(larger.max_bytes, 1500)
            self.assertLessEqual(sum(p.stat().st_size for p in root.rglob('*.json')), 1500)

    def test_legacy_oversized_and_crashed_temporary_entries_are_pruned(self):
        with tempfile.TemporaryDirectory() as raw:
            cache = ObjectCache(Path(raw) / 'cache', max_bytes=2000, max_entry_bytes=1000)
            prefix = cache.directory / 'aa'; prefix.mkdir(parents=True)
            oversized = prefix / ('a' * 64 + '.json')
            with oversized.open('wb') as f: f.truncate(1000000)
            stale = prefix / ('a' * 64 + '.' + 'b' * 32 + '.tmp'); stale.write_text('interrupted')
            self.assertEqual(self.query(cache, 'good').stdout, 'verified')
            self.assertFalse(oversized.exists()); self.assertFalse(stale.exists())
            self.assertGreaterEqual(cache.evicted, 2)

    def test_cache_disk_failure_does_not_erase_success_or_leave_partial_write(self):
        with tempfile.TemporaryDirectory() as raw:
            cache = ObjectCache(Path(raw) / 'cache')
            real_replace = Path.replace
            def fail_entry(path, target):
                if path.name != '.limits.tmp':
                    raise OSError('disk full')
                return real_replace(path, target)
            with patch('aosp_agent.object_cache.Path.replace', fail_entry):
                self.assertEqual(self.query(cache, 'good').stdout, 'verified')
            self.assertEqual(list(cache.directory.rglob('*.tmp')), [])
            self.assertEqual(self.query(cache, 'failed', code=128).returncode, 128)
            self.assertEqual(list(cache.directory.rglob('*.json')), [])

    def test_symlink_prefix_cannot_redirect_cache_reads_or_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); outside = root / 'outside'; outside.mkdir()
            cache = ObjectCache(root / 'cache'); cache.directory.mkdir()
            (cache.directory / 'aa').symlink_to(outside, target_is_directory=True)
            self.assertEqual(self.query(cache, 'read').stdout, 'verified')
            self.assertEqual(list(outside.iterdir()), [])
            self.assertGreater(cache.bypassed, 0)

    def test_slow_cache_maintenance_is_bypassed_once_not_retried_per_source_read(self):
        with tempfile.TemporaryDirectory() as raw:
            cache = ObjectCache(Path(raw) / 'cache')
            with patch.object(cache, '_entries', side_effect=TimeoutError('slow cache')) as scan:
                self.assertEqual(self.query(cache, 'first').stdout, 'verified')
                self.assertEqual(self.query(cache, 'second').stdout, 'verified')
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(cache.data()['unavailable'], 'TimeoutError')
            self.assertFalse(cache.data()['quota_adopted'])

    def test_concurrent_processes_share_capacity_including_temporary_writes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / 'cache'
            script = ('import sys,subprocess\nfrom aosp_agent.retrieval import ObjectCache\n'
                      'c=ObjectCache(sys.argv[1],max_bytes=6000,max_entry_bytes=1200,max_entries=5)\n'
                      'for i in range(20):\n'
                      ' r=c.query(sys.argv[1],"a"*40,("show",sys.argv[2]+str(i)),lambda:subprocess.CompletedProcess([],0,"x"*500,""))\n'
                      ' assert len(r.stdout)==500\n')
            processes = [subprocess.Popen([sys.executable, '-c', script, str(root), str(i)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) for i in range(3)]
            peak = 0
            try:
                deadline = time.monotonic() + 15
                while any(p.poll() is None for p in processes):
                    self.assertLess(time.monotonic(), deadline)
                    sizes = []
                    for path in root.rglob('*'):
                        try:
                            if path.is_file(): sizes.append(path.stat().st_size)
                        except FileNotFoundError:
                            pass
                    # A non-atomic observer may see both names around rename;
                    # the final inventory below is exact under quiescence.
                    peak = max(peak, sum(sizes))
                    time.sleep(.005)
                for process in processes:
                    self.assertEqual(process.returncode, 0, process.stderr.read().decode())
                entries = list(root.rglob('*.json'))
                self.assertTrue(entries)
                self.assertLessEqual(len(entries), 5)
                self.assertLessEqual(sum(p.stat().st_size for p in entries), 6000)
                self.assertEqual(list(root.rglob('*.tmp')), [])
                self.assertLessEqual(peak, 7200)
            finally:
                for process in processes:
                    if process.poll() is None: process.kill()
                    process.wait(); process.stderr.close()
