import difflib
import unittest
from aosp_agent.integration import local_flow_probe as activation
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

    def test_python_dead_branches_transfers_short_circuit_and_deferred_calls(self):
        before = 'def entry(value):\n    return value\n'
        bodies = [
            '    if False:\n        NewHelper(value)\n    return value\n',
            '    while False:\n        NewHelper(value)\n    return value\n',
            '    return value\n    NewHelper(value)\n',
            '    if value:\n        return 1\n    else:\n        return 2\n    NewHelper(value)\n',
            '    result = False and NewHelper(value)\n    return value\n',
            '    result = True or NewHelper(value)\n    return value\n',
            '    result = NewHelper(value) if False else value\n    return value\n',
            '    callback = lambda: NewHelper(value)\n    return value\n',
            '    factory(NewHelper).run()\n    return value\n',
            '    def never_called():\n        return NewHelper(value)\n    return value\n',
            '    for unused in []:\n        NewHelper(value)\n    return value\n',
            '    result = [NewHelper(value) for unused in []]\n    return value\n',
            '    result = [NewHelper(value) for unused in [1] if False]\n    return value\n',
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.assertIsNone(self.check(before, 'def entry(value):\n' + body, 'main.py'))

    def test_possible_python_calls_retain_unresolved_conditions(self):
        before = 'def entry(value):\n    return value\n'
        for body in ('    if True:\n        return NewHelper(value)\n',
                     '    if False:\n        return value\n    return NewHelper(value)\n',
                     '    if value:\n        return NewHelper(value)\n    return value\n'):
            with self.subTest(body=body):
                result = self.check(before, 'def entry(value):\n' + body, 'main.py')
                self.assertIsNotNone(result)
                self.assertFalse(result['production_reachability_proven'])
        self.assertEqual(result['unresolved_conditions'], ['value'])

    def test_java_dead_calls_and_live_branches(self):
        before = 'class Main {\n void entry(boolean flag) {\n  original();\n }\n}\n'
        for code in ('if (false) { NewHelper.run(); }', 'if (1 == 2) NewHelper.run();',
                     'return; NewHelper.run();', 'while (false) { NewHelper.run(); }',
                     'if (flag) return; else return; NewHelper.run();',
                     'boolean x = false && NewHelper.run();', 'boolean x = true || NewHelper.run();',
                     'Runnable r = () -> NewHelper.run();',
                     'factory(NewHelper.class).run();',
                     'try { original(); } finally { return; } NewHelper.run();'):
            with self.subTest(code=code):
                self.assertIsNone(self.check(before, before.replace('original();', code)))
        for code in ('if (true) NewHelper.run();', 'if (false) original(); else NewHelper.run();',
                     'if (flag) NewHelper.run();', 'if (flag) return; NewHelper.run();'):
            with self.subTest(code=code):
                self.assertIsNotNone(self.check(before, before.replace('original();', code)))

    def test_c_and_cpp_preprocessor_and_control_flow(self):
        for path in ('main.c', 'main.cpp'):
            before = 'void entry(int flag) {\n original();\n}\n'
            for code in ('if (0) NewHelper();', 'return; NewHelper();',
                         'for (; 0; ) { NewHelper(); }', '0 && NewHelper();',
                         '#if 0\n NewHelper();\n#endif', 'while (1) {} NewHelper();'):
                with self.subTest(path=path, code=code):
                    self.assertIsNone(self.check(before, before.replace('original();', code), path))
            for code in ('if (1) NewHelper();', '#if 0\n original();\n#else\n NewHelper();\n#endif',
                         'for (NewHelper(); 0; ) {}'):
                with self.subTest(path=path, code=code):
                    self.assertIsNotNone(self.check(before, before.replace('original();', code), path))

    def test_kotlin_dead_and_live_calls(self):
        before = 'class Main {\n fun entry(flag: Boolean) {\n  original()\n }\n}\n'
        for code in ('if (false) { NewHelper.run() }', 'return\n  NewHelper.run()',
                     'val callback = { NewHelper.run() }', 'while (false) { NewHelper.run() }'):
            with self.subTest(code=code):
                self.assertIsNone(self.check(before, before.replace('original()', code), 'Main.kt'))
        for code in ('NewHelper.run()', 'if (flag) { NewHelper.run() }'):
            with self.subTest(code=code):
                self.assertIsNotNone(self.check(before, before.replace('original()', code), 'Main.kt'))

    def test_switch_selection_fallthrough_and_transfer(self):
        for path, before, call in (
            ('Main.java', 'class Main {\n void entry(int flag) {\n  original();\n }\n}\n', 'NewHelper.run()'),
            ('main.c', 'void entry(int flag) {\n original();\n}\n', 'NewHelper()'),
            ('main.cpp', 'void entry(int flag) {\n original();\n}\n', 'NewHelper()'),
        ):
            for code, live in (
                (f'switch(0) {{ case 1: {call}; break; default: break; }}', False),
                (f'switch(0) {{ case 0: {call}; break; default: break; }}', True),
                (f'switch(0) {{ case 0: original(); case 1: {call}; break; }}', True),
                (f'switch(0) {{ case 0: break; case 1: {call}; break; }}', False),
                (f'switch(0) {{ case 0: return; case 1: {call}; break; }}', False),
                (f'switch(1) {{ default: {call}; break; case 1: break; }}', False),
                (f'switch(flag) {{ case 1: {call}; break; }}', True),
            ):
                with self.subTest(path=path, code=code):
                    result = self.check(before, before.replace('original();', code), path)
                    self.assertEqual(result is not None, live)
                    if 'flag' in code:
                        self.assertTrue(result['unresolved_conditions'])

    def test_java_arrow_switch_has_no_fallthrough(self):
        before = 'class Main {\n void entry() {\n original();\n }\n}\n'
        for value, live in ((0, False), (1, True)):
            code = f'switch({value}) {{ case 0 -> original(); case 1 -> NewHelper.run(); default -> original(); }}'
            self.assertEqual(self.check(before, before.replace('original();', code)) is not None, live)

    def test_kotlin_when_selection(self):
        before = 'fun entry() {\n original()\n}\n'
        for value, live in ((0, False), (1, True)):
            code = f'when({value}) {{\n 1 -> NewHelper.run()\n else -> original()\n }}'
            self.assertEqual(self.check(before, before.replace('original()', code), 'Main.kt') is not None, live)

    def test_new_class_cannot_borrow_existing_method_name(self):
        before = 'class Main {\n void entry() {\n  original();\n }\n}\n'
        after = before + 'class NeverUsed {\n void entry() {\n  NewHelper.run();\n }\n}\n'
        self.assertIsNone(self.check(before, after))
        before = 'class Main:\n    def entry(self):\n        return 1\n'
        after = before + '\nclass NeverUsed:\n    def entry(self):\n        return NewHelper()\n'
        self.assertIsNone(self.check(before, after, 'main.py'))
        before = 'fun Main.entry() {\n original()\n}\n'
        after = before + 'fun Other.entry() {\n NewHelper.run()\n}\n'
        self.assertIsNone(self.check(before, after, 'main.kt'))

    def test_disabled_manifest_components_are_not_activation(self):
        before = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>\n'
        for app, component in (('', ' android:enabled="false"'), (' android:enabled="false"', '')):
            after = before.replace('<application/>', '<application' + app + '><service android:name="pkg.NewHelper"' + component + '/></application>')
            self.assertIsNone(self.check(before, after, 'AndroidManifest.xml'))

    def test_parser_errors_do_not_fall_back_to_text_matching(self):
        before = 'class Main {\n void entry() {\n  original();\n }\n}\n'
        self.assertIsNone(self.check(before, before.replace('original();', 'if ( NewHelper.run();')))
