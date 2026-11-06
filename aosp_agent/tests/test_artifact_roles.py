"""Names alone cannot exempt new dead code; real supplementary tests survive."""
from dataclasses import replace
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from aosp_agent.artifact_roles import artifact_kind, classify, donor_test_definition
from aosp_agent.engine import AospBackportAgent, CandidateRejected
from aosp_agent.patches import split_hunks
from engine_fixtures import BASELINE, FIXED, GitFixture, git
from test_diff_workflow import diff


def role(path, text, builds=None, changed=None, **kwargs):
    return classify(path, text, baseline_read=(builds or {}).get, changed_sources=changed or {}, **kwargs)


class ArtifactRolesTest(unittest.TestCase):
    def agent(self, fx, *paths):
        agent = AospBackportAgent(fx.source_root, fx.run_root,
            replace(fx.case(), files=tuple(dict.fromkeys(['counter.py', *paths]))))
        agent.prepare()
        return agent

    def build_baseline(self, fx, text):
        (fx.repo / 'Android.bp').write_text(text)
        git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'pinned test build metadata')
        fx.target = git(fx.repo, 'rev-parse', 'HEAD')
        (fx.repo / 'counter.py').write_text(FIXED)
        git(fx.repo, 'add', '.'); git(fx.repo, 'commit', '-qm', 'ordinary source fix')
        fx.donor = git(fx.repo, 'rev-parse', 'HEAD')
        git(fx.repo, 'checkout', '--detach', '-q', fx.target)

    def test_names_and_directories_do_not_classify_java_as_tests(self):
        for name in ('src/PermissionGateTest.java', 'tests/PermissionGate.java', 'fuzz/PermissionGate.java'):
            with self.subTest(name=name):
                self.assertEqual(role(name, 'class PermissionGate {}')['role'], 'source')

    def test_assembly_headers_scripts_and_unknown_types_have_no_non_source_fallback(self):
        for name in ('gate.S', 'gate.asm', 'gate.inc', 'gate.hxx', 'gate.sh', 'gate.ts'):
            self.assertEqual(artifact_kind(name), 'source')
        self.assertEqual(artifact_kind('gate.strange'), 'unknown')
        self.assertEqual(artifact_kind('notes.txt', '#!/usr/bin/python\npass'), 'source')
        self.assertEqual(artifact_kind('notes.txt', 'text', executable=True), 'source')

    def test_assertion_test_must_bind_to_an_existing_changed_implementation(self):
        good = 'from counter import normalize_count\nassert normalize_count(-1) == 0\n'
        proof = role('ordinary_checks.py', good, changed={'counter.py': FIXED})
        self.assertEqual(proof['role'], 'supplementary_test')
        self.assertFalse(proof['production_repair_credit'])
        self.assertFalse(proof['evidence']['test_executed'])
        for bad in ('assert normalize_count(-1) == 0\n', 'assert True\n',
                    good.replace('from counter', 'from unrelated'),
                    good + '\ndef normalize_count(value):\n    return value\n',
                    good + '\nnormalize_count = lambda value: value\n'):
            self.assertEqual(role('test_counter.py', bad, changed={'counter.py': FIXED})['role'], 'source')
        self.assertEqual(role('test_counter.py', good)['role'], 'source')

    def test_pytest_function_form_preserves_assertion_binding_and_rejects_shadow(self):
        good = 'from counter import normalize_count\ndef test_bounds():\n    assert normalize_count(-1) == 0\n'
        self.assertEqual(role('bounds.py', good, changed={'counter.py': FIXED})['role'], 'supplementary_test')
        bad = good.replace('def test_bounds():', 'def test_bounds(normalize_count):')
        self.assertEqual(role('bounds.py', bad, changed={'counter.py': FIXED})['role'], 'source')

    def test_pinned_test_consumer_supports_normal_java_test_without_name_heuristics(self):
        builds = {'Android.bp': 'java_test { name: "checks", srcs: ["checks/*.java"], }'}
        proof = role('checks/Bounds.java', 'class Bounds {}', builds)
        self.assertEqual(proof['role'], 'supplementary_test')
        self.assertEqual(proof['evidence']['modules'][0]['name'], 'checks')
        self.assertFalse(proof['evidence']['exclusive_product_ownership_proven'])
        mixed = {'Android.bp': builds['Android.bp'] + '\njava_library { name: "prod", srcs: ["checks/*.java"], }'}
        self.assertEqual(role('checks/Bounds.java', 'class Bounds {}', mixed)['role'], 'source')
        conditional = {'Android.bp': 'java_test { name: "checks", target: { android: { srcs: ["checks/*.java"], }, }, }'}
        self.assertEqual(role('checks/Bounds.java', 'class Bounds {}', conditional)['role'], 'source')

    def test_build_role_reads_only_ancestor_metadata_and_failure_gives_no_exemption(self):
        reads = []
        def reader(path):
            reads.append(path)
            if path == 'Android.bp':
                raise RuntimeError('object read failed')
            return 'java_test { name: "checks", srcs: ["*.java"], }'
        result = classify('checks/Bounds.java', 'class Bounds {}', baseline_read=reader, changed_sources={})
        self.assertEqual(reads, ['checks/Android.bp', 'Android.bp'])
        self.assertEqual(result['role'], 'source')

    def test_actual_export_rejects_test_named_dead_source_assembly_and_unknown(self):
        for name, text in (('PermissionGateTest.java', 'class PermissionGateTest {}\n'),
                           ('permission_gate.S', 'nop\n'), ('permission_gate.strange', 'new logic\n')):
            with self.subTest(name=name), GitFixture() as fx:
                agent = self.agent(fx, name)
                (agent.worktree / name).write_text(text)
                with self.assertRaises(CandidateRejected):
                    agent.export_patch(1)
                item = agent.record['new_file_audits']['1']['new_files'][0]
                self.assertEqual(item['status'], 'FAIL')
                self.assertNotEqual(item['basis'], 'non_source_artifact')
                self.assertFalse((agent.run_dir / 'backport.patch').exists())

    def test_model_cannot_invent_build_metadata_to_gain_test_exemption(self):
        with GitFixture() as fx:
            agent = self.agent(fx, 'PermissionGateTest.java', 'Android.bp')
            (agent.worktree / 'PermissionGateTest.java').write_text('class PermissionGateTest {}\n')
            (agent.worktree / 'Android.bp').write_text('java_test { name: "invented", srcs: ["*.java"], }\n')
            with self.assertRaises(CandidateRejected):
                agent.export_patch(1)
            roles = {e['path']: e['classification']['role'] for e in agent.record['new_file_audits']['1']['new_files']}
            self.assertEqual(roles['PermissionGateTest.java'], 'source')

    def test_actual_pinned_test_module_allows_supplementary_addition_and_replay(self):
        with GitFixture() as fx:
            self.build_baseline(fx, 'java_test { name: "checks", srcs: ["checks/*.java"], }\n')
            agent = self.agent(fx, 'checks/Bounds.java')
            (agent.worktree / 'checks').mkdir()
            (agent.worktree / 'checks/Bounds.java').write_text('class Bounds {}\n')
            (agent.worktree / 'counter.py').write_text(FIXED)
            agent.export_patch(1)
            proof = agent.record['new_file_audits']['1']['new_files'][0]
            self.assertEqual(proof['basis'], 'supplementary_test')
            self.assertFalse(proof['classification']['production_repair_credit'])
            self.assertEqual(agent.record['patch_replay'], 'pass')
            self.assertEqual((fx.repo / 'counter.py').read_text(), BASELINE)

    def test_auxiliary_test_and_document_cannot_discharge_production_obligation(self):
        for name, text in (('test_counter.py', 'from counter import normalize_count\nassert normalize_count(-1) == 0\n'),
                           ('repair.md', FIXED), ('repair.json', '{"bounds": [0, 10]}\n')):
            with self.subTest(name=name), GitFixture() as fx:
                agent = self.agent(fx, name)
                (agent.worktree / 'counter.py').write_text(FIXED)
                (agent.worktree / name).write_text(text)
                agent._current_hunks = split_hunks(diff('counter.py', BASELINE, FIXED))
                with patch.object(agent, '_donor_targets', return_value={name}), self.assertRaises(CandidateRejected):
                    agent.export_patch(1)
                self.assertEqual(agent.record['new_file_audits']['1']['rejected'][0]['basis'],
                                 'auxiliary_artifact_cannot_implement_source')

    def test_test_named_real_helper_still_qualifies_via_bound_source_call(self):
        with GitFixture() as fx:
            agent = self.agent(fx, 'HelperTest.py')
            (agent.worktree / 'HelperTest.py').write_text('def clamp(value):\n    return max(0, min(value, 10))\n')
            (agent.worktree / 'counter.py').write_text('from HelperTest import clamp\ndef normalize_count(value):\n    return clamp(value)\n')
            agent.export_patch(1)
            proof = agent.record['new_file_audits']['1']['new_files'][0]
            self.assertEqual(proof['classification']['role'], 'source')
            self.assertEqual(proof['basis'], 'existing_target_integration')

    def test_test_build_consumer_does_not_reclassify_production_donor_addition(self):
        with GitFixture() as fx:
            self.build_baseline(fx, 'java_test { name: "checks", srcs: ["*.java"], }\n')
            agent = self.agent(fx, 'PermissionGate.java')
            code = 'class PermissionGate { public static boolean allow() { return false; } }\n'
            (agent.worktree / 'PermissionGate.java').write_text(code)
            agent._current_hunks = split_hunks('diff --git a/PermissionGate.java b/PermissionGate.java\n'
                'new file mode 100644\n--- /dev/null\n+++ b/PermissionGate.java\n@@ -0,0 +1 @@\n+' + code)
            with self.assertRaises(CandidateRejected):
                agent.export_patch(1)
            self.assertEqual(agent.record['new_file_audits']['1']['rejected'][0]['basis'],
                             'auxiliary_artifact_cannot_implement_source')

    def test_actual_upstream_junit_test_addition_preserves_test_obligation(self):
        with GitFixture() as fx:
            self.build_baseline(fx, 'java_test { name: "checks", srcs: ["*.java"], }\n')
            agent = self.agent(fx, 'Bounds.java')
            code = 'import org.junit.Test; class Bounds { @Test public void bounds() {} }\n'
            (agent.worktree / 'Bounds.java').write_text(code)
            agent._current_hunks = split_hunks('diff --git a/Bounds.java b/Bounds.java\nnew file mode 100644\n'
                '--- /dev/null\n+++ b/Bounds.java\n@@ -0,0 +1 @@\n+' + code)
            agent.export_patch(1)
            self.assertEqual(agent.record['new_file_audits']['1']['status'], 'PASS')
            self.assertFalse(agent.record['new_file_audits']['1']['new_files'][0]['classification']['production_repair_credit'])

    def test_upstream_test_definition_requires_bound_annotations_and_no_mixed_production_method(self):
        good = 'import org.junit.Test; class Bounds { @Test public void bounds() {} }'
        self.assertTrue(donor_test_definition('Bounds.java', good))
        for bad in (good.replace('org.junit.Test', 'other.Test'), good.replace('import org.junit.Test;', ''),
                    good.replace('@Test', ''), good.replace('class Bounds {', 'class Bounds { void repair() {}')):
            self.assertFalse(donor_test_definition('Bounds.java', bad))
        kotlin = 'import kotlin.test.Test\nclass Bounds {\n@Test fun bounds() {}\n}\n'
        self.assertTrue(donor_test_definition('Bounds.kt', kotlin))

    def test_no_new_files_performs_no_role_metadata_reads(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            (agent.worktree / 'counter.py').write_text(FIXED)
            with patch.object(agent, '_artifact_baseline_text', side_effect=AssertionError('unnecessary role read')):
                agent.export_patch(1)

    def test_baseline_test_caller_without_test_name_cannot_activate_production_helper(self):
        for annotation in (False, True):
            with self.subTest(annotation=annotation), GitFixture() as fx:
                (fx.repo / 'checks').mkdir()
                before = 'class Runner { ' + ('@org.junit.Test ' if annotation else '') + 'public void check() {} }\n'
                (fx.repo / 'checks/Runner.java').write_text(before)
                self.build_baseline(fx, ('java_test { name: "checks", srcs: ["checks/*.java"], }\n'
                                        if not annotation else '// No module ownership supplied.\n'))
                agent = self.agent(fx, 'checks/Runner.java', 'Helper.java')
                (agent.worktree / 'Helper.java').write_text('class Helper { static void fix() {} }\n')
                (agent.worktree / 'checks/Runner.java').write_text(before.replace('check() {}', 'check() { Helper.fix(); }'))
                with self.assertRaises(CandidateRejected):
                    agent.export_patch(1)
                audit = agent.record['new_file_audits']['1']
                self.assertEqual(audit['excluded_test_callers']['checks/Runner.java']['role'], 'supplementary_test')
                self.assertEqual(audit['rejected'][0]['basis'], 'unintegrated_new_source')

    def test_failed_baseline_read_is_not_cached_as_absence(self):
        with GitFixture() as fx:
            agent = self.agent(fx)
            with patch.object(agent, '_git', side_effect=subprocess.TimeoutExpired(['git'], 1)):
                with self.assertRaisesRegex(RuntimeError, 'read failed'):
                    agent._artifact_baseline_text('Android.bp')
            self.assertNotIn('Android.bp', agent._artifact_baseline_cache)
            self.assertIsNone(agent._artifact_baseline_text('Android.bp'))
