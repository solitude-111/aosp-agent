import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from aosp_agent.case import Case
from aosp_agent.continuation_proof import coverage_gate, introduced_effects, verify_no_fallthrough
from aosp_agent.engine import AospBackportAgent
from aosp_agent.patches import split_hunks
from engine_fixtures import git
from engine_fixtures import GitFixture, BASELINE
from test_diff_workflow import diff


FIXTURES = Path(__file__).parent / 'fixtures/conditional-continuation'
BASE = '''class Handler {
    void handle(boolean rejected) {
        proceed();
    }
}
'''


def guarded(body, continuation='        proceed();'):
    return BASE.replace('        proceed();', '        if (rejected) {\n' + body + '\n        }\n' + continuation)


class ContinuationProofTest(unittest.TestCase):
    def test_identical_comment_and_empty_braces_are_not_executable_coverage(self):
        with GitFixture() as fixture:
            agent = AospBackportAgent(fixture.source_root, fixture.run_root, fixture.case())
            agent.prepare()
            donor = BASELINE.replace('    return value', '    // same security comment\n    authorize();\n    return value')
            candidate = BASELINE.replace('    return value', '    // same security comment\n    unrelated();\n    return value')
            agent._current_hunks = split_hunks(diff('counter.py', BASELINE, donor))
            result = agent._check_hunk_results('HUNK-RESULT f001-h001 implemented same comment',
                ['counter.py'], diff('counter.py', BASELINE, candidate))
            self.assertFalse(result['ok'])
            from aosp_agent.engine import _coverage_code_line
            for text in ('// same security comment', '/* comment */', '* block comment', '{', '}', ';'):
                self.assertFalse(_coverage_code_line(text))

    def test_calls_and_comments_do_not_satisfy_an_exclusion_postcondition(self):
        candidate = guarded('            requestStop();\n            // The operation is now terminated.')
        result = verify_no_fallthrough(BASE, candidate, 'rejected')
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['reachable_continuation'][0]['excerpt'], 'proceed();')

    def test_changed_continuation_and_empty_baseline_cannot_pass_by_text_mismatch(self):
        changed = guarded('            requestStop();', '        proceedWithDifferentArgument(2);')
        result = verify_no_fallthrough(BASE, changed, 'rejected')
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['reachable_continuation'][0]['excerpt'], 'proceedWithDifferentArgument(2);')
        empty = BASE.replace('        proceed();\n', '')
        no_tail = guarded('            requestStop();', '')
        self.assertEqual(verify_no_fallthrough(empty, no_tail, 'rejected')['status'], 'UNRESOLVED')
        direct = guarded('            requestStop();\n            return;', '')
        self.assertEqual(verify_no_fallthrough(empty, direct, 'rejected')['status'], 'EXCLUDED')

    def test_direct_transfer_and_equivalent_guard_both_exclude_continuation(self):
        for body, tail in (
                ('            requestStop();\n            return;', '        proceed();'),
                ('            requestStop();\n            throw new RuntimeException();', '        proceed();'),
                ('            requestStop();', '        if (!rejected) {\n            proceed();\n        }')):
            with self.subTest(body=body, tail=tail):
                self.assertEqual(verify_no_fallthrough(BASE, guarded(body, tail), 'rejected')['status'], 'EXCLUDED')

    def test_legal_state_update_does_not_invent_a_denial_obligation(self):
        baseline = 'class Handler { void handle(int count) { consume(count); } }\n'
        fixed = baseline.replace('consume(count);', 'if (count < 0) { count = 0; } consume(count);')
        patch = diff('Handler.java', baseline, fixed)
        self.assertEqual(introduced_effects(patch), [])
        self.assertEqual(coverage_gate(patch, baseline, fixed)['status'], 'NOT_REQUIRED')

    def test_repeated_mutable_predicate_is_not_a_stable_exclusion_guard(self):
        for condition in ('isRejected()', 'state.rejected', 'rejectedField'):
            with self.subTest(condition=condition):
                candidate = guarded('            updateState();',
                    '        if (!rejected) {\n            proceed();\n        }').replace('if (rejected)',
                        'if (' + condition + ')').replace('if (!rejected)', 'if (!(' + condition + '))')
                result = verify_no_fallthrough(BASE, candidate, condition)
                self.assertEqual(result['status'], 'UNRESOLVED')
                self.assertTrue(result['reachable_continuation'])
                direct = guarded('            updateState();\n            return;').replace('if (rejected)',
                                                                                              'if (' + condition + ')')
                self.assertEqual(verify_no_fallthrough(BASE, direct, condition)['status'], 'EXCLUDED')

    def test_call_only_source_does_not_invent_return_requirement_or_accept_text_overlap(self):
        candidate = guarded('            updateState();')
        result = coverage_gate(diff('Handler.java', BASE, candidate), BASE, candidate)
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertEqual(result['obligations'][0]['obligation'], 'semantic_postcondition_unresolved')
        self.assertFalse(result['obligations'][0]['source_excludes_continuation'])
        # A correct call-based state update may continue; the narrow structural
        # check demands semantic evidence rather than declaring it incorrect.

    def test_source_transfer_obligation_accepts_equivalent_target_guard(self):
        source = guarded('            requestStop();\n            return;')
        candidate = guarded('            requestStop();', '        if (!rejected) {\n            proceed();\n        }')
        result = coverage_gate(diff('Handler.java', BASE, source), BASE, candidate)
        self.assertEqual(result['status'], 'COVERED')

    def test_historical_candidate_is_not_covered_by_comment_or_finish_call(self):
        provenance = json.loads((FIXTURES / 'provenance.json').read_text())
        texts = {name: (FIXTURES / name).read_text() for name in provenance['sha256']}
        for name, expected in provenance['sha256'].items():
            self.assertEqual(hashlib.sha256(texts[name].encode()).hexdigest(), expected)
        path = provenance['path']
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / 'source/repo'
            repo.mkdir(parents=True)
            git(repo, 'init', '-q')
            target_file = repo / path
            target_file.parent.mkdir(parents=True)
            commits = []
            for name in ('target.java', 'donor-parent.java', 'donor-fix.java'):
                target_file.write_text(texts[name])
                git(repo, 'add', '.')
                git(repo, 'commit', '-q', '-m', name)
                commits.append(git(repo, 'rev-parse', 'HEAD'))
            target, parent, fix = commits
            git(repo, 'checkout', '--detach', '-q', target)
            case = Case.from_dict({'cve': 'CVE-2099-2001', 'project': 'conditional continuation fixture',
                'repository': 'repo', 'source_commit': fix, 'source_parent': parent,
                'target_commit': target, 'files': [path]})
            agent = AospBackportAgent(root / 'source', root / 'runs', case)
            agent.prepare()
            inspection = agent.inspect()
            agent._current_hunks = inspection['hunks']
            candidate = ''.join(hunk['patch'] for hunk in split_hunks(texts['candidate.patch']) if hunk['path'] == path)
            agent._git('apply', '--binary', '-', cwd=agent.worktree, input=candidate)
            rendered = agent.export_patch(1)
            claims = agent._check_hunk_results('\n'.join('HUNK-RESULT ' + hunk['id'] +
                ' implemented the matching guard and call are present.' for hunk in inspection['hunks']),
                [path], rendered, review_mapped=True)
            self.assertFalse(claims['ok'])
            self.assertTrue(any('continuation postcondition' in error for error in claims['contradictions']))
            gate = next(iter(agent.record['continuation_obligations'].values()))
            self.assertEqual(gate['status'], 'UNRESOLVED')
            self.assertFalse(gate['obligations'][0]['source_excludes_continuation'])
            self.assertTrue(gate['obligations'][0]['local_proof']['reachable_continuation'])
            # This is a test-only variant of the historical candidate. Closing
            # the local continuation gap is not an overall validation result.
            modified = agent.worktree / path
            modified.write_text(modified.read_text().replace('            finish();',
                                '            finish();\n            return;', 1))
            repaired = coverage_gate(diff(path, texts['donor-parent.java'], texts['donor-fix.java']),
                                     texts['target.java'], modified.read_text())
            self.assertEqual(repaired['status'], 'COVERED')
            self.assertFalse(repaired['runtime_security_proven'])
            self.assertNotEqual(agent.record.get('status'), 'VALIDATED')
            self.assertEqual(git(repo, 'status', '--porcelain'), '')


if __name__ == '__main__':
    unittest.main()
