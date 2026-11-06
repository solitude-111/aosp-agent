"""New-file credit needs an actual declaration and an unshadowed caller edge."""
import difflib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from aosp_agent.integration import activation
from aosp_agent.patches import split_hunks


def check(path, before, after, new_path, source):
    patch = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                       fromfile='a/' + path, tofile='b/' + path))
    return activation(path, before, after, split_hunks(patch), {'NewHelper'},
                      new_source={'path': new_path, 'text': source})


class ActivationBindingTest(unittest.TestCase):
    def test_production_gate_cannot_use_a_names_only_flow_probe(self):
        with self.assertRaises(TypeError):
            activation('main.py', '', '', [], {'NewHelper'})
        with self.assertRaises(ValueError):
            activation('main.py', '', '', [], {'NewHelper'}, new_source=None)

    def test_python_explicit_imports_aliases_and_package_relative_imports(self):
        before = 'def entry(value):\n    return value\n'
        source = 'def clamp(value):\n    return max(0, min(value, 10))\n'
        for path, new, header, call in (
            ('main.py', 'helper.py', 'import helper', 'helper.clamp'),
            ('main.py', 'helper.py', 'import helper as h', 'h.clamp'),
            ('main.py', 'pkg/helper.py', 'import pkg.helper', 'pkg.helper.clamp'),
            ('main.py', 'pkg/helper.py', 'from pkg import helper as h', 'h.clamp'),
            ('pkg/main.py', 'pkg/helper.py', 'from .helper import clamp as bound', 'bound'),
        ):
            with self.subTest(header=header):
                after = header + '\n\ndef entry(value):\n    return ' + call + '(value)\n'
                result = check(path, before, after, new, source)
                self.assertIsNotNone(result)
                self.assertEqual(result['binding']['target_source'], new)
                self.assertEqual(result['binding']['status'], 'RESOLVED_LEXICALLY')

    def test_python_same_name_without_binding_and_shadowed_imports_are_rejected(self):
        before = 'def entry(value):\n    return value\n'
        source = 'def clamp(value):\n    return max(0, min(value, 10))\n'
        cases = [
            'def entry(value):\n    return helper.clamp(value)\n',
            'import other.helper as helper\ndef entry(value):\n    return helper.clamp(value)\n',
            'import helper\ndef entry(value):\n    helper = lambda x: x\n    return helper(value)\n',
            'import helper\ndef entry(value):\n    helper.clamp = lambda x: x\n    return helper.clamp(value)\n',
            'import helper\ndef entry(value):\n    return helper.missing(value)\n',
            'import helper\ndef entry(value):\n    return helper.clamp(value)\n    helper = value\n',
            'import helper\ndef entry(value):\n    return [helper.clamp(value) for helper in value]\n',
        ]
        for after in cases:
            with self.subTest(after=after):
                self.assertIsNone(check('main.py', before, after, 'helper.py', source))

    def test_python_class_static_calls_and_source_rebinding(self):
        before = 'def entry(value):\n    return value\n'
        after = 'from helper import NewHelper as H\ndef entry(value):\n    return H.clamp(value)\n'
        source = 'class NewHelper:\n    @staticmethod\n    def clamp(value):\n        return max(0, value)\n'
        self.assertIsNotNone(check('main.py', before, after, 'helper.py', source))
        self.assertIsNone(check('main.py', before, after, 'helper.py', source + '\nNewHelper = object\n'))
        self.assertIsNone(check('main.py', before, after, 'helper.py', source.replace('@staticmethod', '@unknown_decorator')))

    def test_changed_import_can_connect_existing_call_but_unrelated_import_cannot(self):
        before = 'from old_helper import clamp\ndef entry(value):\n    return clamp(value)\n'
        source = 'def clamp(value):\n    return max(0, value)\n'
        after = before.replace('old_helper', 'helper')
        self.assertIsNotNone(check('main.py', before, after, 'helper.py', source))
        self.assertIsNone(check('main.py', after, 'import unrelated\n' + after, 'helper.py', source))
        before = 'package p;\nimport old.NewHelper;\nclass Main {\n int entry() { return NewHelper.run(); }\n}\n'
        after = before.replace('old.NewHelper', 'newpkg.NewHelper')
        source = 'package newpkg; class NewHelper { static int run() { return 1; } }\n'
        self.assertIsNotNone(check('Main.java', before, after, 'NewHelper.java', source))
        self.assertIsNone(check('Main.java', after, after.replace('package p;', 'package p;\nimport unrelated.Type;'), 'NewHelper.java', source))

    def test_java_package_import_and_actual_static_declaration(self):
        source = 'package p; public class NewHelper { public static int run() { return 1; } }\n'
        before = 'package p;\nclass Main {\n int entry() { return 0; }\n}\n'
        after = before.replace('return 0;', 'return NewHelper.run();')
        self.assertIsNotNone(check('Main.java', before, after, 'NewHelper.java', source))
        self.assertIsNone(check('Main.java', before, after, 'NewHelper.java', source.replace('package p;', 'package other;')))
        self.assertIsNotNone(check('Main.java', before, after.replace('package p;', 'package p;\nimport other.NewHelper;'),
                                   'NewHelper.java', source.replace('package p;', 'package other;')))
        self.assertIsNone(check('Main.java', before, after.replace('package p;', 'package p;\nimport other.NewHelper;'), 'NewHelper.java', source))
        self.assertIsNone(check('Main.java', before, after.replace('.run()', '.missing()'), 'NewHelper.java', source))

    def test_java_variable_shadow_and_nested_class_method_cannot_activate_outer(self):
        source = 'class NewHelper { static int run() { return 1; } }\n'
        before = 'class Main {\n int entry() { return 0; }\n}\n'
        after = before.replace('return 0;', 'Other NewHelper = existing(); return NewHelper.run();')
        self.assertIsNone(check('Main.java', before, after, 'NewHelper.java', source))
        after = before.replace('return 0;', 'return NewHelper.run();')
        nested = 'class NewHelper { static class Nested { static int run() { return 1; } } }\n'
        self.assertIsNone(check('Main.java', before, after, 'NewHelper.java', nested))

    def test_kotlin_object_import_alias_and_local_shadow(self):
        source = 'package p\nobject NewHelper {\n fun run(): Int {\n  return 1\n }\n}\n'
        before = 'package q\nfun entry(): Int {\n return 0\n}\n'
        after = before.replace('package q', 'package q\nimport p.NewHelper as H').replace('return 0', 'return H.run()')
        self.assertIsNotNone(check('Main.kt', before, after, 'NewHelper.kt', source))
        self.assertIsNone(check('Main.kt', before, after.replace('return H.run()', 'val H = existing()\n return H.run()'), 'NewHelper.kt', source))

    def test_kotlin_top_level_constructor_and_companion_calls(self):
        before = 'package q\nfun entry() {\n original()\n}\n'
        examples = [
            ('package p\nfun clamp() {\n original()\n}\n', 'p.clamp as repair', 'repair()'),
            ('package p\nclass NewHelper {}\n', 'p.NewHelper', 'NewHelper()'),
            ('package p\nclass NewHelper {\n companion object {\n  fun run() {\n   original()\n  }\n }\n}\n', 'p.NewHelper', 'NewHelper.run()'),
        ]
        for source, imported, call in examples:
            with self.subTest(call=call):
                after = before.replace('package q', 'package q\nimport ' + imported).replace('original()', call)
                self.assertIsNotNone(check('Main.kt', before, after, 'Helper.kt', source))

    def test_java_explicit_static_import_and_conflicting_existing_method(self):
        source = 'package p; class NewHelper { static int run() { return 1; } }\n'
        before = 'class Main {\n int entry() { return 0; }\n}\n'
        after = 'import static p.NewHelper.run;\n' + before.replace('return 0;', 'return run();')
        self.assertIsNotNone(check('Main.java', before, after, 'NewHelper.java', source))
        self.assertIsNone(check('Main.java', before, after.replace('class Main {', 'class Main {\n int run() { return 0; }'), 'NewHelper.java', source))

    def test_java_helper_constructor_and_static_import_from_kotlin(self):
        source = 'package p; public class NewHelper { public static void run() {} }\n'
        before = 'package q\nfun entry() {\n original()\n}\n'
        for imported, call in (('p.NewHelper', 'NewHelper()'), ('p.NewHelper.run as repair', 'repair()')):
            after = before.replace('package q', 'package q\nimport ' + imported).replace('original()', call)
            self.assertIsNotNone(check('Main.kt', before, after, 'NewHelper.java', source))

    def test_kotlin_jvm_static_is_required_for_java_static_receiver(self):
        before = 'package p;\nclass Main {\n void entry() { original(); }\n}\n'
        after = before.replace('original();', 'NewHelper.run();')
        source = 'package p\nobject NewHelper {\n @JvmStatic\n fun run() {\n  original()\n }\n}\n'
        self.assertIsNotNone(check('Main.java', before, after, 'NewHelper.kt', source))
        self.assertIsNone(check('Main.java', before, after, 'NewHelper.kt', source.replace(' @JvmStatic\n', '')))

    def test_native_function_body_not_filename_is_the_binding(self):
        source = 'int enforce_count(int value) { return value < 0 ? 0 : value; }\n'
        before = 'int entry(int value) {\n return value;\n}\n'
        after = 'int enforce_count(int);\n' + before.replace('return value;', 'return enforce_count(value);')
        result = check('main.c', before, after, 'different_filename.c', source)
        self.assertIsNotNone(result)
        self.assertEqual(result['binding']['symbol'], 'enforce_count')
        self.assertIsNone(check('main.c', before, after, 'different_filename.c', 'static ' + source))
        self.assertIsNone(check('main.c', before, after, 'different_filename.c', 'int enforce_count(int);\n'))

    def test_native_pointer_or_old_definition_does_not_bind_new_function(self):
        source = 'int enforce_count(int value) { return value < 0 ? 0 : value; }\n'
        before = 'int entry(int value) {\n return value;\n}\n'
        shadow = before.replace('return value;', 'int (*enforce_count)(int) = other; return enforce_count(value);')
        self.assertIsNone(check('main.c', before, shadow, 'helper.c', source))
        existing = source.replace('value < 0 ? 0 : value', 'value')
        after = existing + before.replace('return value;', 'return enforce_count(value);')
        self.assertIsNone(check('main.c', existing + before, after, 'helper.c', source))

    def test_manifest_requires_exact_declared_component_class(self):
        before = '<manifest package="p" xmlns:android="http://schemas.android.com/apk/res/android"><application/></manifest>\n'
        after = before.replace('<application/>', '<application><service android:name=".NewHelper"/></application>')
        self.assertIsNotNone(check('AndroidManifest.xml', before, after, 'NewHelper.java', 'package p; class NewHelper {}'))
        self.assertIsNone(check('AndroidManifest.xml', before, after, 'NewHelper.java', 'package other; class NewHelper {}'))

    @unittest.skipUnless(shutil.which('cc'), 'local C compiler is unavailable')
    def test_bound_native_helper_compiles_and_executes_normal_function(self):
        before = 'int entry(int value) {\n return value;\n}\n'
        after = 'int enforce_count(int);\n' + before.replace('return value;', 'return enforce_count(value);')
        source = 'int enforce_count(int value) { return value < 0 ? 0 : value; }\n'
        self.assertIsNotNone(check('main.c', before, after, 'helper.c', source))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'main.c').write_text(after + '\nint main(void) { return entry(-2) != 0 || entry(3) != 3; }\n')
            (root / 'helper.c').write_text(source)
            compiled = subprocess.run([shutil.which('cc'), '-Wall', '-Werror', str(root / 'main.c'), str(root / 'helper.c'), '-o', str(root / 'check')], capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            self.assertEqual(subprocess.run([str(root / 'check')], timeout=5).returncode, 0)
