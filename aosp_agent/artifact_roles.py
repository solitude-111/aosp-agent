"""Bounded artifact roles; names never establish a test or a production fix.

Test recognition grants supplementary-artifact credit only. The caller must
separately reject attempts to discharge a production donor obligation with it.
Build evidence is a positive test consumer in pinned nearby metadata, not a
claim that no consumer anywhere else in the product exists.
"""
import ast
from pathlib import PurePosixPath
from types import SimpleNamespace

from .activation_binding import python_binder, parse_source
from .activation_flow import txt, walk
from .build_discovery import discover_build


SOURCE_SUFFIXES = frozenset(('.aidl .c .cc .cpp .cxx .go .h .hh .hpp .hxx .ipp .tpp .inc '
    '.java .kt .kts .m .mm .proto .py .rs .s .asm .sh .bash .zsh .js .jsx .ts .tsx '
    '.rb .pl .lua .swift .scala .cs .ll .f .f90 .v .sv').split())
CONFIG_SUFFIXES = frozenset(('.xml .json .yaml .yml .toml .ini .cfg .conf .bp .mk .bzl '
    '.rc .te .fc .cil .map .properties').split())
DATA_SUFFIXES = frozenset(('.txt .md .rst .html .css .csv .tsv .png .jpg .jpeg .gif .webp .svg').split())
CONFIG_NAMES = {'Android.bp', 'Android.mk', 'BUILD', 'BUILD.bazel', 'CMakeLists.txt',
                'Makefile', 'file_contexts', 'service_contexts', 'property_contexts',
                'seapp_contexts', '.gitignore'}
DATA_NAMES = {'LICENSE', 'NOTICE', 'OWNERS', 'METADATA', 'README'}


def artifact_kind(path, text='', *, executable=False):
    name = PurePosixPath(path)
    if text.startswith('#!') or executable or name.suffix.lower() in SOURCE_SUFFIXES:
        return 'source'
    if name.name in CONFIG_NAMES or name.suffix.lower() in CONFIG_SUFFIXES:
        return 'configuration'
    if name.name in DATA_NAMES or name.suffix.lower() in DATA_SUFFIXES:
        return 'data'
    return 'unknown'


def python_test_shape(text):
    """Recognize assertion scripts and simple pytest-style test functions.

    No arbitrary exported classes/functions, decorators, top-level assignments
    or setup expressions. This is deliberately a supported syntax profile,
    not a generic Python test-framework or execution proof.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    assertions = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.Assert):
            assertions.append((node, tree))
            continue
        if isinstance(node, ast.FunctionDef) and node.name.startswith('test_') and not node.decorator_list:
            if not any(isinstance(n, ast.Assert) for n in node.body):
                return None
            if any(not isinstance(n, (ast.Assert, ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign)) for n in node.body):
                return None
            assertions.extend((n, node) for n in node.body if isinstance(n, ast.Assert))
            continue
        return None
    return (tree, assertions) if assertions else None


def assertion_test(path, text, changed_sources):
    if PurePosixPath(path).suffix != '.py':
        return None
    shape = python_test_shape(text)
    if not shape:
        return None
    tree, assertions = shape
    for target, content in changed_sources.items():
        if PurePosixPath(target).suffix != '.py':
            continue
        bind = python_binder(target, content, path)
        if bind is None:
            continue
        for assertion, owner in assertions:
            for call in ast.walk(assertion.test):
                binding = bind(call, tree, owner) if isinstance(call, ast.Call) else None
                if binding:
                    return {'basis': 'assertion_calls_changed_existing_source', 'binding': binding,
                            'line': assertion.lineno, 'test_executed': False}
    return None


def donor_test_definition(path, text):
    """Identify a complete upstream test addition, never a filename hint.

    Besides the assertion-script profile, support Java/Kotlin classes whose
    functions are bound JUnit/kotlin.test test or fixture methods. Mixed helper
    and production classes remain unsupported by this narrow source-role proof.
    """
    if PurePosixPath(path).suffix == '.py':
        return bool(python_test_shape(text))
    if PurePosixPath(path).suffix not in ('.java', '.kt'):
        return False
    lang, tree = parse_source(path, text)
    if tree is None or tree.root_node.has_error:
        return False
    known = {'org.junit.Test': 'test', 'org.junit.jupiter.api.Test': 'test', 'kotlin.test.Test': 'test'}
    for name in ('Before', 'After', 'BeforeClass', 'AfterClass'):
        known['org.junit.' + name] = 'fixture'
    for name in ('BeforeEach', 'AfterEach', 'BeforeAll', 'AfterAll'):
        known['org.junit.jupiter.api.' + name] = 'fixture'
    imports = {}
    for node in tree.root_node.named_children:
        if node.type in ('import_declaration', 'import_header', 'import'):
            value = txt(node).removeprefix('import').strip().rstrip(';')
            if value in known:
                imports[value.rsplit('.', 1)[-1]] = known[value]
    test_count = 0
    for node in walk(tree.root_node):
        if node.type in ('class_declaration', 'interface_declaration', 'annotation_type_declaration', 'object_declaration'):
            if txt(node.child_by_field_name('name')) in imports:
                return False  # A local type can shadow an imported annotation.
        if node.type not in ('method_declaration', 'function_declaration'):
            continue
        modifiers = next((n for n in node.named_children if n.type == 'modifiers'), None)
        annotations = [n for n in walk(modifiers) if n.type in ('annotation', 'marker_annotation')] if modifiers else []
        kinds = set()
        for annotation in annotations:
            name = txt(annotation.child_by_field_name('name'))
            if not name:
                name = txt(annotation).lstrip('@').split('(', 1)[0].strip()
            kind = known.get(name) or imports.get(name)
            if kind:
                kinds.add(kind)
        if not kinds:
            return False
        test_count += 'test' in kinds
    return bool(test_count)


def nearby_test_consumer(path, baseline_read):
    """Query only ancestor Android.bp files at the pinned target revision."""
    files, issues = {}, []
    directory = PurePosixPath(path).parent
    for parent in (directory, *directory.parents):
        bp = (parent / 'Android.bp').as_posix()
        try:
            text = baseline_read(bp)
            if text is not None:
                files[bp] = text
        except (OSError, ValueError, RuntimeError) as exc:
            issues.append({'path': bp, 'reason': str(exc)[:300]})
    if issues:
        return None
    report = discover_build(SimpleNamespace(files=files, read=files.__getitem__), [path])
    tests = [m for m in report['modules'] if m['role'] == 'test']
    production = [m for m in report['modules'] if m['role'] == 'production']
    if not tests or production or report.get('issues'):
        return None
    return {'basis': 'pinned_test_build_consumer', 'modules': tests, 'build_files': sorted(files),
            'scope': 'nearby_literal_build_metadata', 'exclusive_product_ownership_proven': False,
            'test_executed': False}


def classify(path, text, *, baseline_read, changed_sources, executable=False):
    kind = artifact_kind(path, text, executable=executable)
    if kind == 'source':
        test = assertion_test(path, text, changed_sources) or nearby_test_consumer(path, baseline_read)
        if test:
            return {'role': 'supplementary_test', 'evidence': test, 'production_repair_credit': False}
    return {'role': kind, 'production_repair_credit': kind == 'source'}
