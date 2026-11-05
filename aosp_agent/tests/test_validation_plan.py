import unittest

from aosp_agent.build_discovery import discover_build, glob_matches, parse_modules
from aosp_agent.discovery import diff_units
from aosp_agent.validation_plan import make_plan, normalize_checks
from test_diff_workflow import diff


class Blobs:
    def __init__(self, files):
        self.files = files
        self.head = 'fixed-target-commit'

    def read(self, path):
        return self.files[path]


class ValidationPlanTest(unittest.TestCase):
    def test_literal_modules_filegroups_globs_and_exclusions(self):
        repo = Blobs({
            'src/Android.bp': 'filegroup { name: "sources", srcs: ["**/*.java"], exclude_srcs: ["Skip.java"] }',
            'app/Android.bp': 'java_library { name: "client", srcs: [":sources"], min_sdk_version: 29 }',
        })
        result = discover_build(repo, ['src/Good.java', 'src/nested/Other.java'])
        self.assertEqual(result['status'], 'RESOLVED')
        self.assertEqual([m['name'] for m in result['modules']], ['client'])
        self.assertEqual(result['issues'], [])
        self.assertEqual(discover_build(repo, ['src/Skip.java'])['status'], 'UNRESOLVED')
        self.assertFalse(glob_matches('*.java', 'nested/Good.java'))
        self.assertFalse(glob_matches('../*.java', '../Good.java'))

    def test_dynamic_conditional_defaults_and_ambiguous_modules_stay_unresolved(self):
        inputs = [
            'java_library {name: "client", srcs: shared_sources + ["A.java"]}',
            'java_library {name: "client", srcs: ["A.java"], arch: {arm64: {srcs: ["B.java"]}}}',
            'java_defaults {name: "base", srcs: ["A.java"]}\njava_library {name: "client", defaults: ["base"]}',
            'java_library {name: "client", srcs: ["A.java"]}\njava_library {name: "client", srcs: ["A.java"]}',
            'filegroup {name: "a", srcs: [":b"]}\nfilegroup {name: "b", srcs: [":a"]}\njava_library {name: "client", srcs: [":a"]}',
            'java_library {name: "client", srcs: ["A.java"], exclude_srcs: [":excluded"]}',
        ]
        for content in inputs:
            with self.subTest(content=content):
                result = discover_build(Blobs({'Android.bp': content}), ['A.java'])
                self.assertEqual(result['status'], 'UNRESOLVED')
                self.assertTrue(result['issues'])

    def test_partial_ownership_and_scan_limit_do_not_generate_build(self):
        repo = Blobs({'Android.bp': 'java_library {name: "client", srcs: ["A.java"]}'})
        result = discover_build(repo, ['A.java', 'B.java'])
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['uncovered'], ['B.java'])
        self.assertEqual(discover_build(repo, ['A.java'], limit=0)['status'], 'UNRESOLVED')
        plan = make_plan(repo, [], {}, ['A.java', 'B.java'], '', build_runner='/trusted/build')
        self.assertEqual(plan['checks'], [])

    def test_source_contract_uses_only_novel_donor_additions_with_coordinates(self):
        before = 'void accept() {\n  contextToken();\n  oldToken();\n}\n'
        after = before.replace('oldToken();', 'newGuard();')
        patch = diff('donor/New.java', before, after)
        units = diff_units(patch)
        repo = Blobs({'Old.java': before, 'Android.bp': 'java_library {name: "client", srcs: ["Old.java"]}'})
        plan = make_plan(repo, units, {units[0]['id']: ['Old.java']}, ['Old.java'], patch,
                         build_runner='/trusted/build')
        self.assertEqual(plan['checks'][0]['argv'], ['grep', '-Ewq', '--', 'newGuard', 'Old.java'])
        self.assertEqual(plan['checks'][1]['argv'], ['/trusted/build', 'client'])
        self.assertEqual(plan['provenance'][0]['added_lines'], [{'line': 3, 'text': '  newGuard();'}])
        self.assertEqual(plan['target_commit'], repo.head)
        self.assertFalse(plan['runtime_security_proven'])

    def test_baseline_markers_and_missing_runner_cannot_manufacture_checks(self):
        before = 'void accept() { oldToken(); }\n'
        after = 'void accept() { newGuard(); }\n'
        patch = diff('New.java', before, after)
        units = diff_units(patch)
        repo = Blobs({'Old.java': after, 'Android.bp': 'java_library {name: "client", srcs: ["Old.java"]}'})
        plan = make_plan(repo, units, {units[0]['id']: ['Old.java']}, ['Old.java'], patch)
        self.assertEqual(plan['checks'], [])
        self.assertEqual(plan['provenance'][0]['status'], 'NO_NOVEL_MARKER')
        self.assertFalse(plan['build']['runner_configured'])

    def test_explicit_stage_override_empty_disable_and_disabled_auto(self):
        before, after = 'oldToken();\n', 'newGuard();\n'
        patch = diff('Old.java', before, after)
        units = diff_units(patch)
        repo = Blobs({'Old.java': before, 'Android.bp': 'java_library {name: "client", srcs: ["Old.java"]}'})
        args = (repo, units, {units[0]['id']: ['Old.java']}, ['Old.java'], patch)
        manual = {'source_contract': [['trusted-check', 'Old.java']]}
        plan = make_plan(*args, explicit=manual, build_runner='/trusted/build')
        self.assertEqual([c['argv'][0] for c in plan['checks']], ['/trusted/build', 'trusted-check'])
        self.assertEqual(make_plan(*args, explicit=[], build_runner='/trusted/build')['checks'], [])
        self.assertEqual(make_plan(*args, auto=False)['checks'], [])
        self.assertEqual(make_plan(*args, auto=False, explicit=manual)['checks'][0]['argv'][0], 'trusted-check')
        for invalid in ({'checks': 'wrong'}, {'checks': [], 'ignored': []}, {'stage': 'wrong'}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                normalize_checks(invalid)

    def test_malformed_and_commented_build_blocks_do_not_become_modules(self):
        modules, issues = parse_modules('// java_library { name: "fake" }\njava_library { name: "broken", srcs: [', 'Android.bp')
        self.assertEqual(modules, [])
        self.assertTrue(issues)
