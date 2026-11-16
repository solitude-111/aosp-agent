"""C++ flag support is grounded on fixed donor and target objects."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from aosp_agent.discovery import Repository, diff_units
from aosp_agent.donor import verify_donor
from aosp_agent.flag_cleanup import check_flag_cleanup
from aosp_agent.impact_proof import AssessmentError
from aosp_agent.retrieval import LazyTree
from engine_fixtures import git


PACKAGE = 'package: "com.example.flags"\n'
DECLARATION = 'flag {\n  name: "cap_count"\n  namespace: "counter"\n}\n'
RETAINED = 'flag {\n  name: "other_flag"\n  namespace: "counter"\n}\n'
INCLUDE = '#include <com_example_flags.h>\n'
CALL = 'com::example::flags::cap_count()'
CHECK = f'  if ({CALL} && count > 10) {{\n'
FIXED_CHECK = '  if (count > 10) {\n'


def cpp(check):
    return INCLUDE + 'int cap(int count) {\n' + check + '    return 10;\n  }\n  return count;\n}\n'


class FlagCleanupTest(unittest.TestCase):
    def setup_cpp(self, folder, *, before=CHECK, after=FIXED_CHECK, live=False):
        root = Path(folder)
        git(root, 'init', '-q')
        (root / 'counter.cc').write_text(cpp(FIXED_CHECK) + (f'bool cap_on() {{ return {CALL}; }}\n' if live else ''))
        git(root, 'add', '.')
        git(root, 'commit', '-qm', 'fixed target view')
        target = git(root, 'rev-parse', 'HEAD')
        flag_file = root / 'counter.aconfig'
        flag_file.write_text(PACKAGE + DECLARATION + RETAINED)
        (root / 'counter.cc').write_text(cpp(before))
        git(root, 'add', '.')
        git(root, 'commit', '-qm', 'donor parent')
        parent = git(root, 'rev-parse', 'HEAD')
        flag_file.write_text(PACKAGE + RETAINED)
        (root / 'counter.cc').write_text(cpp(after))
        git(root, 'add', '.')
        git(root, 'commit', '-qm', 'donor fix')
        fix = git(root, 'rev-parse', 'HEAD')
        patch = git(root, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames', parent, fix) + '\n'
        source, linked = diff_units(patch)
        controller = SimpleNamespace(donor=verify_donor(root, fix, parent, patch),
            inventory_issues=[], repos=[Repository('target', root, target, LazyTree(root, target))])
        entries = [{'unit_id': unit['id'], 'revision': 'source_parent',
                    'line_start': min(unit['before']), 'line_end': max(unit['before'])}
                   for unit in (source, linked)]
        return controller, source, linked, entries

    def test_cpp_qualified_guard_removed_and_target_pin_has_no_reference(self):
        with TemporaryDirectory() as folder:
            controller, source, linked, evidence = self.setup_cpp(folder)
            self.assertEqual(check_flag_cleanup(controller, source, [linked], evidence),
                             {'unit_id': source['id'], 'flag': 'cap_count', 'repositories_checked': ['target']})
            linked['source_id'] = 's002'
            with self.assertRaisesRegex(AssessmentError, 'cite the linked removal'):
                check_flag_cleanup(controller, source, [linked], evidence)
            linked.pop('source_id')
            # Exit status 1 accompanied by a read warning cannot establish absence.
            controller.repos = [SimpleNamespace(key='target', head=controller.repos[0].head,
                object_query=lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stderr='read warning'))]
            with self.assertRaisesRegex(AssessmentError, 'could not check target'):
                check_flag_cleanup(controller, source, [linked], evidence)

    def test_wrong_package_or_comment_cannot_prove_cpp_guard_removal(self):
        invalid = [CHECK.replace('example', 'other'), '  /*\n' + CHECK + '  */\n  if (count > 10) {\n']
        for condition in invalid:
            with self.subTest(condition=condition), TemporaryDirectory() as folder:
                controller, source, linked, evidence = self.setup_cpp(folder, before=condition)
                with self.assertRaisesRegex(AssessmentError, 'cite the linked removal'):
                    check_flag_cleanup(controller, source, [linked], evidence)

    def test_cpp_flag_still_live_in_donor_fix_or_target_is_rejected(self):
        for options, failure in (
            ({'after': FIXED_CHECK + f'    bool enabled = {CALL};\n'}, 'still present in the linked donor consumer'),
            ({'live': True}, 'target project target still references'),
        ):
            with self.subTest(options=options), TemporaryDirectory() as folder:
                controller, source, linked, evidence = self.setup_cpp(folder, **options)
                with self.assertRaisesRegex(AssessmentError, failure):
                    check_flag_cleanup(controller, source, [linked], evidence)


if __name__ == '__main__':
    unittest.main()
