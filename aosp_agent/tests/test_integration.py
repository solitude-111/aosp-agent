import difflib
import unittest
from aosp_agent.integration import activation
from aosp_agent.patches import split_hunks


class IntegrationTest(unittest.TestCase):
    def check(self, before, after, path='Main.java'):
        patch = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                           fromfile='a/' + path, tofile='b/' + path))
        return activation(path, before, after, split_hunks(patch), {'NewHelper'})

    def test_comments_strings_and_new_dead_function_are_not_calls(self):
        before = 'class Main {\n void entry() {\n  original();\n }\n}\n'
        for line in ('  // NewHelper.run();', '  log("NewHelper.run()");',
                     '  /*\nNewHelper.run();\n  */', '  Class<?> c = NewHelper.class;'):
            with self.subTest(line=line):
                self.assertIsNone(self.check(before, before.replace('  original();', line)))
        after = before.replace('  original();', '  original();')[:-2] + ' void dead() {\n  NewHelper.run();\n }\n}\n'
        self.assertIsNone(self.check(before, after))
        self.assertIsNotNone(self.check(before, before.replace('  original();', '  NewHelper.run();')))

    def test_python_strings_are_not_calls(self):
        before = 'def entry(value):\n    return value\n'
        self.assertIsNone(self.check(before, before.replace('return value', 'return "NewHelper(value)"'), 'main.py'))
        self.assertIsNotNone(self.check(before, before.replace('return value', 'return NewHelper(value)'), 'main.py'))

    def test_manifest_component_registration(self):
        before = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>\n'
        after = before.replace('<application/>', '<application><service android:name="pkg.NewHelper"/></application>')
        self.assertEqual(self.check(before, after, 'AndroidManifest.xml')['kind'], 'manifest_component')
