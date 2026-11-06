"""Build coverage must use Blueprint glob semantics, including exclusions."""
import unittest
from types import SimpleNamespace

from aosp_agent.artifact_roles import nearby_test_consumer
from aosp_agent.blueprint_glob import glob_matches, _compile
from aosp_agent.build_discovery import discover_build
from aosp_agent.validation_plan import make_plan


def repository(metadata):
    files = {'Android.bp': metadata, 'A.java': 'class A {}', 'B.java': 'class B {}'}
    return SimpleNamespace(files=files, read=files.__getitem__, head='pinned-target')


class BlueprintGlobTest(unittest.TestCase):
    def test_character_classes_ranges_negation_and_escapes(self):
        examples = [
            ('[AB].java', 'A.java', True), ('[AB].java', 'C.java', False),
            ('[A-Z].java', 'B.java', True), ('[^A].java', 'A.java', False),
            ('[^A].java', 'B.java', True), ('[!A].java', '!.java', True),
            ('[!A].java', 'B.java', False), ('[z-aA].java', 'A.java', True),
            ('[z-a].java', 'z.java', False), (r'[\-A].java', '-.java', True),
            (r'[\]A].java', '].java', True), (r'\[A\].java', '[A].java', True),
            (r'\?.java', '?.java', True), (r'\*.java', 'A.java', False),
            (r'\*.java', '*.java', True), ('[界文].java', '界.java', True),
        ]
        for pattern, name, expected in examples:
            with self.subTest(pattern=pattern, name=name):
                self.assertEqual(glob_matches(pattern, name), expected)

    def test_recursive_directory_and_file_boundaries(self):
        examples = [
            ('**/*.java', 'A.java', True), ('**/*.java', 'a/b/A.java', True),
            ('a/**/B.java', 'a/B.java', True), ('a/**/B.java', 'a/b/B.java', True),
            ('a/**/B.java', 'b/B.java', False), ('*.java', 'a/A.java', False),
            ('a/?.java', 'a/AB.java', False), ('a/?.java', 'a/界.java', True),
            ('./a//*.java', 'a/A.java', True), ('a/*/', 'a/b', False),
            ('a/*/', 'a/b/', True), ('*.java', '.java', True),
        ]
        for pattern, name, expected in examples:
            with self.subTest(pattern=pattern, name=name):
                self.assertEqual(glob_matches(pattern, name), expected)

    def test_go_byte_star_and_earliest_chunk_semantics(self):
        # Independent Android12 pathtools.Match/local Go results; a Unicode
        # character DP or regex translation disagrees on these valid names.
        self.assertTrue(glob_matches('*??', '界'))
        self.assertTrue(glob_matches('*[^a]?', '界'))
        self.assertFalse(glob_matches(r'a*[^b]?*[\-]', 'a界-'))

    def test_invalid_and_unsafe_patterns_are_not_negative_evidence(self):
        patterns = ('', '[', '[]', '[^]', '[a-]', '[a', '\\', '**', '**.java',
                    'a**/A.java', '**/**/A.java', '/A.java', '../*.java', 'a/../A.java')
        for pattern in patterns:
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                glob_matches(pattern, 'A.java')

    def test_excluded_file_cannot_generate_production_build(self):
        repo = repository('java_library {name: "main", srcs: ["*.java"], exclude_srcs: ["[AB].java"]}')
        build = discover_build(repo, ['A.java'])
        self.assertEqual(build['status'], 'UNRESOLVED')
        self.assertEqual(build['production_uncovered'], ['A.java'])
        self.assertEqual(build['modules'], [])
        self.assertEqual(make_plan(repo, [], {}, ['A.java'], '', build_runner='/trusted/build')['checks'], [])

    def test_character_class_selects_real_consumer_and_retains_unknown_peer(self):
        repo = repository('java_library {name: "main", srcs: ["[AB].java"]}')
        self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
        repo.files['Android.bp'] += '\njava_library {name: "conditional", srcs: ["[AB].java"], target: {android: {enabled: true}}}'
        build = discover_build(repo, ['A.java'])
        self.assertEqual(build['status'], 'UNRESOLVED')
        self.assertEqual(build['unresolved_consumers'][0]['module'], 'conditional')
        self.assertEqual(make_plan(repo, [], {}, ['A.java'], '', build_runner='/trusted/build')['checks'], [])

    def test_invalid_source_or_exclusion_prevents_build_credit(self):
        for properties in ('srcs: ["**.java"]', 'srcs: ["*.java"], exclude_srcs: ["[A-"]',
                           'srcs: ["*.java"], exclude_srcs: ["../A.java"]'):
            with self.subTest(properties=properties):
                repo = repository('java_library {name: "main", ' + properties + '}')
                build = discover_build(repo, ['A.java'])
                self.assertEqual(build['status'], 'UNRESOLVED')
                self.assertTrue(build['unresolved_consumers'])
                self.assertEqual(make_plan(repo, [], {}, ['A.java'], '', build_runner='/trusted/build')['checks'], [])

    def test_excluded_test_cannot_be_classified_as_supplementary(self):
        repo = repository('java_test {name: "tests", srcs: ["*.java"], exclude_srcs: ["[AB].java"]}')
        self.assertIsNone(nearby_test_consumer('A.java', repo.files.get))
        repo.files['Android.bp'] = 'java_test {name: "tests", srcs: ["[AB].java"]}'
        self.assertIsNotNone(nearby_test_consumer('A.java', repo.files.get))
        self.assertEqual(discover_build(repo, ['A.java'])['status'], 'UNRESOLVED')

    def test_filegroup_exclusions_apply_before_consumer_credit(self):
        files = {'src/Android.bp': 'filegroup {name: "sources", srcs: ["*.java"], exclude_srcs: ["[AB].java"]}',
                 'app/Android.bp': 'java_library {name: "main", srcs: [":sources"]}'}
        repo = SimpleNamespace(files=files, read=files.__getitem__)
        self.assertEqual(discover_build(repo, ['src/A.java'])['status'], 'UNRESOLVED')
        self.assertEqual(discover_build(repo, ['src/C.java'])['status'], 'RESOLVED')

    def test_work_and_cache_are_bounded(self):
        with self.assertRaisesRegex(ValueError, 'work limit'):
            glob_matches('?' * 1100, 'a' * 1100)
        with self.assertRaisesRegex(ValueError, 'over-limit'):
            glob_matches('a' * 4097, 'A.java')
        for i in range(300):
            glob_matches(f'{i}*.java', 'A.java')
        self.assertLessEqual(_compile.cache_info().currsize, 256)
