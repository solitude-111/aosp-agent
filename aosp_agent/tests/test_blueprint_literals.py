"""Static build metadata: scope correctness, bounded evaluation and ownership."""
from pathlib import PurePosixPath
import unittest

from aosp_agent.blueprint_literals import parse_metadata
from aosp_agent.build_discovery import discover_build
from aosp_agent.validation_plan import make_plan
from test_validation_plan import Blobs


def file(source, path='Android.bp'):
    return {'path': path, 'source': source}


# Also evaluated outside the test suite by the unmodified Android 12 Blueprint
# parser. These are ordinary build-language examples, never CVE reference data.
ORACLE_CASES = [
    {'id': 'list_variable', 'valid': True, 'files': [file('sources = ["A.java"]\njava_library {name: "main", srcs: sources}') ]},
    {'id': 'append_before_read', 'valid': True, 'files': [file('sources = ["A.java"]\nsources += ["B.java"]\njava_library {name: "main", srcs: sources}')]},
    {'id': 'list_and_string_plus', 'valid': True, 'files': [file('prefix = "src/"\nsources = [prefix + "A.java"] + ["B.java"]\njava_library {name: "ma" + "in", srcs: sources}')]},
    {'id': 'maps_plus', 'valid': True, 'files': [file('left = {inner: {names: ["a"]}, count: 1}\nright = {inner: {names: ["b"]}, count: 2}\njava_library {name: "main", metadata: left + right, srcs: ["A.java"]}')]},
    {'id': 'negative_integer', 'valid': True, 'files': [file('count = -2 + 3\njava_library {name: "main", number: count, srcs: ["A.java"]}')]},
    {'id': 'inherit_and_sibling_isolation', 'valid': True, 'files': [file('sources = ["A.java"]'), file('own = sources + ["B.java"]\njava_library {name: "child", srcs: own}', 'one/Android.bp'), file('java_library {name: "sibling", srcs: sources}', 'two/Android.bp')]},
    {'id': 'nested_inheritance', 'valid': True, 'files': [file('base = ["A.java"]'), file('child = base + ["B.java"]', 'one/Android.bp'), file('java_library {name: "leaf", srcs: child}', 'one/two/Android.bp')]},
    {'id': 'undefined', 'valid': False, 'files': [file('java_library {name: "main", srcs: unknown + ["A.java"]}')]},
    {'id': 'forward_reference', 'valid': False, 'files': [file('java_library {name: "main", srcs: sources}\nsources = ["A.java"]')]},
    {'id': 'duplicate_assignment', 'valid': False, 'files': [file('sources = ["A.java"]\nsources = ["B.java"]')]},
    {'id': 'append_after_use', 'valid': False, 'files': [file('sources = ["A.java"]\njava_library {name: "main", srcs: sources}\nsources += ["B.java"]')]},
    {'id': 'append_undefined', 'valid': False, 'files': [file('sources += ["A.java"]')]},
    {'id': 'append_inherited', 'valid': False, 'files': [file('sources = ["A.java"]'), file('sources += ["B.java"]', 'one/Android.bp')]},
    {'id': 'redefine_inherited', 'valid': False, 'files': [file('sources = ["A.java"]'), file('sources = ["B.java"]', 'one/Android.bp')]},
    {'id': 'alias_freezes_variable', 'valid': False, 'files': [file('sources = ["A.java"]\nalias = sources\nsources += ["B.java"]')]},
    {'id': 'self_append_reads_variable', 'valid': False, 'files': [file('sources = ["A.java"]\nsources += sources')]},
    {'id': 'mixed_types', 'valid': False, 'files': [file('sources = ["A.java"] + "B.java"')]},
    {'id': 'bool_plus', 'valid': False, 'files': [file('flag = true + false')]},
    {'id': 'module_map_plus', 'valid': False, 'files': [file('java_library {name: "main"} + {srcs: ["A.java"]}')]},
    {'id': 'unsupported_call', 'valid': False, 'files': [file('java_library {name: "main", srcs: select("A.java")}')]},
]


def evaluated_files(files):
    scopes, result = {}, []
    for row in sorted(files, key=lambda r: len(PurePosixPath(r['path']).parts)):
        directory = PurePosixPath(row['path']).parent
        ancestor = next((p for p in directory.parents if p in scopes), None)
        modules, issues, exports = parse_metadata(row['source'], row['path'], scopes.get(ancestor))
        if exports is not None:
            scopes[directory] = exports
        result.append({'path': row['path'], 'modules': [{'kind': m['kind'], 'properties': m['properties']} for m in modules],
                       'errors': [i['reason'] for i in issues]})
    return result


class BlueprintLiteralsTest(unittest.TestCase):
    def test_reference_language_examples_and_invalid_mutations(self):
        for case in ORACLE_CASES:
            with self.subTest(case=case['id']):
                rows = evaluated_files(case['files'])
                self.assertEqual(not any(r['errors'] for r in rows), case['valid'], rows)
        rows = evaluated_files(ORACLE_CASES[5]['files'])
        self.assertEqual(rows[1]['modules'][0]['properties']['srcs'], ['A.java', 'B.java'])
        self.assertEqual(rows[2]['modules'][0]['properties']['srcs'], ['A.java'])

    def test_valid_variable_in_other_directory_no_longer_blocks_known_owner(self):
        repo = Blobs({'Android.bp': 'java_library {name: "main", srcs: ["A.java"]}',
                      'unrelated/Android.bp': 'unrelated_sources = ["B.java"]\njava_library {name: "other", srcs: unrelated_sources}'})
        result = discover_build(repo, ['A.java'])
        self.assertEqual(result['status'], 'RESOLVED')
        self.assertEqual([m['name'] for m in result['modules']], ['main'])
        self.assertEqual(result['unresolved_consumers'], [])
        self.assertEqual({m['path'] for m in result['metadata_inputs']}, set(repo.files))
        self.assertTrue(all(len(m['sha256']) == 64 for m in result['metadata_inputs']))
        plan = make_plan(repo, [], {}, ['A.java'], '', build_runner='/trusted/build')
        self.assertEqual(plan['checks'][0]['argv'], ['/trusted/build', 'main'])
        self.assertFalse(plan['runtime_security_proven'])

    def test_undefined_variable_still_blocks_even_with_a_known_owner(self):
        repo = Blobs({'Android.bp': 'java_library {name: "main", srcs: ["A.java"]}',
                      'unrelated/Android.bp': 'java_library {name: "other", srcs: unknown_sources}'})
        result = discover_build(repo, ['A.java'])
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['production_uncovered'], [])
        self.assertIn('undefined Blueprint variable', result['unresolved_consumers'][0]['reason'])
        self.assertEqual(make_plan(repo, [], {}, ['A.java'], '', build_runner='/trusted/build')['checks'], [])

    def test_child_uses_parent_scope_but_paths_belong_to_consumer_directory(self):
        repo = Blobs({'Android.bp': 'sources = ["A.java"]\njava_library {name: "root", srcs: sources}',
                      'A/Android.bp': 'java_library {name: "child", srcs: sources}',
                      'A/deep/Android.bp': 'java_library {name: "leaf", srcs: sources}'})
        # A/ sorts before Android.bp lexically; depth order must load parent first.
        result = discover_build(repo, ['A/deep/A.java'])
        self.assertEqual(result['status'], 'RESOLVED')
        self.assertEqual([m['name'] for m in result['modules']], ['leaf'])

    def test_variable_filegroup_reference_preserves_cross_directory_consumer(self):
        repo = Blobs({'Android.bp': 'group_ref = [":shared"]',
                      'src/Android.bp': 'sources = ["A.java"]\nfilegroup {name: "shared", srcs: sources}',
                      'app/Android.bp': 'java_library {name: "client", srcs: group_ref}'})
        result = discover_build(repo, ['src/A.java'])
        self.assertEqual(result['status'], 'RESOLVED')
        self.assertEqual([m['name'] for m in result['modules']], ['client'])

    def test_bad_parent_and_invalid_late_assignment_cannot_export_partial_scope(self):
        repo = Blobs({'Android.bp': 'sources = ["A.java"]\nbad = missing',
                      'child/Android.bp': 'java_library {name: "main", srcs: sources}'})
        result = discover_build(repo, ['child/A.java'])
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['modules'], [])
        self.assertTrue(any('ancestor' in i['reason'] for i in result['issues']))
        modules, issues, exports = parse_metadata('java_library {name: "main", srcs: ["A.java"]}\nx = missing', 'Android.bp')
        self.assertEqual(modules, [])
        self.assertIsNone(exports)
        self.assertTrue(issues)

    def test_product_conditions_defaults_namespaces_and_includes_remain_unresolved(self):
        cases = [
            'sources = ["A.java"]\njava_library {name: "main", srcs: sources, product_variables: {debuggable: {enabled: true}}}',
            'sources = ["A.java"]\njava_defaults {name: "base", srcs: sources}\njava_library {name: "main", defaults: ["base"]}',
            'soong_namespace {imports: ["other"]}\njava_library {name: "main", srcs: ["A.java"]}',
            'build = ["extra.bp"]\njava_library {name: "main", srcs: ["A.java"]}',
        ]
        for source in cases:
            with self.subTest(source=source):
                result = discover_build(Blobs({'Android.bp': source}), ['A.java'])
                self.assertEqual(result['status'], 'UNRESOLVED')
                self.assertTrue(result['unresolved_consumers'])

    def test_expression_resource_limits_reject_expansion_and_deep_nesting(self):
        expanded = 'v0 = ["A.java"]\n' + '\n'.join(f'v{i} = v{i-1} + v{i-1}' for i in range(1, 30))
        deeply_nested = 'x = ' + '[' * 70 + '"A.java"' + ']' * 70
        for source in (expanded, deeply_nested):
            modules, issues, exports = parse_metadata(source, 'Android.bp')
            self.assertEqual(modules, [])
            self.assertIsNone(exports)
            self.assertIn('limit', issues[0]['reason'])

    def test_package_metadata_and_static_exclusions_do_not_create_test_coverage(self):
        repo = Blobs({'Android.bp': 'package {default_visibility: ["//visibility:public"]}\n'
                      'sources = ["*.java"]\nskips = ["Skip.java"]\n'
                      'java_library {name: "main", srcs: sources, exclude_srcs: skips}'})
        self.assertEqual(discover_build(repo, ['A.java'])['status'], 'RESOLVED')
        self.assertEqual(discover_build(repo, ['Skip.java'])['status'], 'UNRESOLVED')
        repo.files['Android.bp'] = repo.files['Android.bp'].replace('java_library', 'java_test')
        result = discover_build(repo, ['A.java'])
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['production_uncovered'], ['A.java'])
