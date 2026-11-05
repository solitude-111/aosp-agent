from dataclasses import replace
import unittest

from aosp_agent.engine import AospBackportAgent, _rewrap_only
from engine_fixtures import GitFixture, git


class LedgerBoundaryTest(unittest.TestCase):
    def prepared(self, fx, content):
        (fx.repo / 'guard.h').write_text(content)
        git(fx.repo, 'add', 'guard.h')
        git(fx.repo, 'commit', '-qm', 'target guard')
        case = replace(fx.case(), files=('guard.h',), target_commit=git(fx.repo, 'rev-parse', 'HEAD'))
        agent = AospBackportAgent(fx.source_root, fx.run_root, case)
        agent.prepare()
        return agent

    def test_build_configuration_and_metadata_names_are_not_blanket_exemptions(self):
        with GitFixture() as fx:
            agent = AospBackportAgent(fx.source_root, fx.run_root, fx.case())
            for path in ('Android.bp', 'Android.mk', 'METADATA', 'OWNERS'):
                hunk = {'path': path, 'patch': '@@ -1 +1 @@\n-enabled: true,\n+enabled: false,\n'}
                self.assertFalse(agent._is_metadata_hunk(hunk), path)
            for old, new in [('if (ratio < 1.2) reject();', 'if (ratio < 1.3) reject();'),
                             ('if (version < 1.2) reject();', 'if (version < 1.3) reject();')]:
                self.assertFalse(agent._is_metadata_hunk({'path': 'guard.c',
                    'patch': '@@ -1 +1 @@\n-' + old + '\n+' + new + '\n'}))
            self.assertTrue(agent._is_metadata_hunk({'path': 'METADATA',
                'patch': '@@ -1 +1 @@\n-version: "1.2"\n+version: "1.3"\n'}))
            for old, new in [('*allowed = false;', '*allowed = true;'),
                             ('/* note */ oldGuard();', '/* note */ missingGuard();'),
                             ('VERSION = 1;', 'VERSION = 2; execute();')]:
                self.assertFalse(agent._is_metadata_hunk({'path': 'Android.bp',
                    'patch': '@@ -1 +1 @@\n-' + old + '\n+' + new + '\n'}))

    def test_top_level_old_macro_cannot_claim_already_present(self):
        for old, new in [('#define LIMIT 10', '#define LIMIT 20'),
                         ('#define ACCEPT(x) ((x) < 10)', '#define ACCEPT(x) ((x) <= 10)')]:
            with self.subTest(old=old), GitFixture() as fx:
                agent = self.prepared(fx, old + '\n')
                hunk = {'path': 'guard.h', 'patch': '@@ -1 +1 @@\n-' + old + '\n+' + new + '\n'}
                reason = agent._falsify_exclusion_against_target(hunk, {}, 'already_present')
                self.assertIn('pre-change macro remains', reason)

    def test_unanchored_additions_require_actual_target_evidence(self):
        with GitFixture() as fx:
            agent = self.prepared(fx, '#define OLD_LIMIT 10\n')
            hunk = {'path': 'guard.h', 'patch': '@@ -0,0 +1 @@\n+#define NEW_LIMIT 20\n'}
            self.assertIn('unanchored additions are absent',
                          agent._falsify_exclusion_against_target(hunk, {}, 'already_present'))
            self.assertIn('no grounded target anchor',
                          agent._falsify_exclusion_against_target(hunk, {}, 'semantic_equivalence'))
        with GitFixture() as fx:
            agent = self.prepared(fx, '#define NEW_LIMIT 20\n')
            self.assertIsNone(agent._falsify_exclusion_against_target(hunk, {}, 'already_present'))

    def test_rewrap_detection_preserves_operators_and_quoted_spaces(self):
        self.assertTrue(_rewrap_only('@@ -1 +1,2 @@\n-call(a, b);\n+call(a,\n+ b);\n'))
        self.assertFalse(_rewrap_only('@@ -1 +1 @@\n-if (a < b) stop();\n+if (a <= b) stop();\n'))
        self.assertFalse(_rewrap_only('@@ -1 +1 @@\n-log("a b");\n+log("ab");\n'))
