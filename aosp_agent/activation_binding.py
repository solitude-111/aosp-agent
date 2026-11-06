"""Restricted lexical bindings from a caller to an actual new source file.

This is not compiler/type/linker resolution. Python requires explicit imports;
Java/Kotlin require a matching package/import and a declared callable; native
free functions require matching external linkage without a local replacement.
Dynamic rebinding, reflection, overload dispatch and product linkage are not
proven. Unsupported forms cannot obtain credit by spelling a file's basename.
"""
import ast
from collections import Counter
import importlib
from pathlib import PurePosixPath
import re

from .activation_flow import TS_FUNCTIONS, TS_TYPES, compact, function_parts, literal_truth, txt, walk


def receipt(path, symbol, basis, assumptions=()):
    return {'status': 'RESOLVED_LEXICALLY', 'target_source': path, 'symbol': symbol,
            'basis': basis, 'assumptions': list(assumptions), 'runtime_dispatch_proven': False}


def py_selector(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr); node = node.value
    return [node.id, *reversed(parts)] if isinstance(node, ast.Name) else []


def py_scope_nodes(node):
    """Bindings of this scope, excluding nested bodies with their own locals."""
    pending = list(ast.iter_child_nodes(node))
    while pending:
        child = pending.pop()
        yield child
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
                              ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        pending.extend(ast.iter_child_nodes(child))


def py_module(path):
    parts = list(PurePosixPath(path).with_suffix('').parts)
    return '.'.join(parts[:-1] if parts[-1] == '__init__' else parts)


def python_binder(new_path, new_text, caller_path):
    try:
        source = ast.parse(new_text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    definitions = {n.name: n for n in source.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and not n.decorator_list}
    counts = Counter(n.name for n in source.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    module = py_module(new_path)
    if not module or not definitions: return None
    for n in py_scope_nodes(source):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            definitions.pop(n.id, None)

    def import_target(node, alias):
        if isinstance(node, ast.Import):
            local = alias.asname or alias.name.split('.')[0]
            if alias.name == module:
                return local, ([] if alias.asname else module.split('.')[1:])
            return None
        package = list(PurePosixPath(caller_path).parent.parts)
        if package == ['.']: package = []
        if node.level:
            if node.level > len(package): return None
            prefix = package[:len(package) - node.level + 1]
            imported = '.'.join(prefix + ([node.module] if node.module else []))
        else:
            imported = node.module or ''
        local = alias.asname or alias.name
        if imported == module and alias.name in definitions:
            return local, ['@' + alias.name]
        if '.'.join(filter(None, (imported, alias.name))) == module:
            return local, []
        return None

    def bind(call, tree, owner):
        parts = py_selector(call.func)
        if not parts: return None
        root = parts[0]
        parents = {id(c): p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        scopes, cursor = [tree], owner
        while cursor is not None and cursor is not tree:
            if isinstance(cursor, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(cursor)
            cursor = parents.get(id(cursor))
        imports, import_lines = [], set()
        for scope in scopes:
            for n in py_scope_nodes(scope):
                if isinstance(n, ast.arg) and n.arg == root: return None
                if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id == root: return None
                if isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)):
                    if (py_selector(n) or [None])[0] == root: return None
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == root:
                    return None
                if isinstance(n, (ast.Global, ast.Nonlocal)) and root in n.names: return None
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    for alias in n.names:
                        local = alias.asname or (alias.name.split('.')[0] if isinstance(n, ast.Import) else alias.name)
                        if alias.name == '*': return None
                        if local != root: continue
                        target = import_target(n, alias)
                        # Only unconditional imports in this scope establish
                        # this restricted binding. Repeated identical imports
                        # are fine; a different source with the same name is not.
                        if target is None or n not in getattr(scope, 'body', []): return None
                        if scope is not tree and n.lineno > call.lineno: return None
                        imports.append(target[1])
                        import_lines.update(range(n.lineno, n.end_lineno + 1))
        # Comprehension targets live in their own scope and may shadow an
        # otherwise unambiguous module import at this particular call.
        cursor = call
        while cursor is not owner and cursor is not None:
            if isinstance(cursor, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                if any(isinstance(n, ast.Name) and n.id == root for g in cursor.generators for n in ast.walk(g.target)):
                    return None
            cursor = parents.get(id(cursor))
        if not imports or any(v != imports[0] for v in imports): return None
        prefix = imports[0]
        if prefix and prefix[0].startswith('@'):
            selected = [prefix[0][1:], *parts[1:]]
        else:
            if parts[1:1 + len(prefix)] != prefix: return None
            selected = parts[1 + len(prefix):]
        if not selected or counts[selected[0]] != 1: return None
        definition = definitions.get(selected[0])
        if definition is None: return None
        if len(selected) > 1:
            if len(selected) != 2 or not isinstance(definition, ast.ClassDef): return None
            methods = [n for n in definition.body if
                       (isinstance(n, ast.FunctionDef) and n.name == selected[1]) or
                       (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == selected[1] for t in n.targets))]
            if len(methods) != 1: return None
            # Class-qualified instance methods are not assumed to have a bound
            # receiver. Explicit static/class methods have a known declaration.
            method = methods[0]
            if isinstance(method, ast.FunctionDef):
                if (len(method.decorator_list) != 1 or not isinstance(method.decorator_list[0], ast.Name)
                        or method.decorator_list[0].id not in ('staticmethod', 'classmethod')): return None
            elif not (isinstance(method.value, ast.Call) and isinstance(method.value.func, ast.Name)
                      and method.value.func.id == 'staticmethod' and len(method.value.args) == 1
                      and isinstance(method.value.args[0], ast.Lambda)):
                return None
        return {**receipt(new_path, '.'.join(selected), 'explicit_python_import_and_declaration',
                          ['repository-relative import root', 'no dynamic module or attribute rebinding']),
                'caller_binding_lines': sorted(import_lines)}
    return bind


def parse_source(path, text):
    suffix = PurePosixPath(path).suffix
    lang = {'.java': 'java', '.kt': 'kotlin', '.kts': 'kotlin', '.c': 'c', '.h': 'cpp',
            '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp'}.get(suffix)
    if lang is None: return None, None
    from tree_sitter import Language, Parser
    return lang, Parser(Language(importlib.import_module('tree_sitter_' + lang).language())).parse(text.encode())


def package_name(tree):
    node = next((n for n in tree.root_node.named_children if n.type in ('package_declaration', 'package_header')), None)
    return re.sub(r'^package\s+|;\s*$', '', txt(node)).strip()


def declarator_name(node):
    while node is not None:
        if node.type in ('identifier', 'field_identifier'): return txt(node)
        child = node.child_by_field_name('declarator')
        if child is None and node.type == 'parenthesized_declarator':
            child = next(iter(node.named_children), None)
        node = child
    return ''


def tree_shadows(tree, owner, root, *, native=False, functions_shadow=False):
    scopes, cursor = [owner], owner.parent
    while cursor:
        if cursor.type in TS_TYPES or cursor.parent is None: scopes.append(cursor)
        cursor = cursor.parent
    for scope in scopes:
        pending = list(scope.named_children)
        while pending:
            n = pending.pop()
            if n.type in TS_FUNCTIONS:
                # A second local definition beats a presumed external symbol.
                if (native or functions_shadow) and function_parts(n)[0] == root: return True
                continue
            if n.type in TS_TYPES:
                if compact(n.child_by_field_name('name')) == root and not (native and n.type == 'namespace_definition'): return True
                continue
            if n.type in ('variable_declarator', 'formal_parameter', 'spread_parameter', 'catch_formal_parameter'):
                if compact(n.child_by_field_name('name')) == root: return True
            if n.type in ('parameter', 'variable_declaration'):
                ident = next((c for c in n.named_children if c.type == 'identifier'), None)
                if txt(ident) == root: return True
            if native and n.type in ('declaration', 'parameter_declaration', 'init_declarator'):
                for d in n.children_by_field_name('declarator'):
                    # An ordinary function prototype is compatible with external
                    # linkage. A pointer/object with that name shadows the call.
                    prototype = d.type == 'function_declarator' and d.child_by_field_name('declarator') is not None and d.child_by_field_name('declarator').type == 'identifier'
                    if not prototype and declarator_name(d) == root: return True
            pending.extend(n.named_children)
    return False


def tree_binder(new_path, new_text, caller_path):
    lang, source = parse_source(new_path, new_text)
    caller_lang, _ = parse_source(caller_path, '')
    if source is None or source.root_node.has_error or caller_lang is None: return None
    if (lang in ('c', 'cpp')) != (caller_lang in ('c', 'cpp')): return None
    if lang in ('java', 'kotlin'):
        package = package_name(source)
        types = [n for n in source.root_node.named_children if n.type in TS_TYPES]
        names = Counter(compact(n.child_by_field_name('name')) for n in types)
        top_functions = [n for n in source.root_node.named_children if n.type == 'function_declaration'
                         and not function_parts(n)[2]] if lang == 'kotlin' else []
        def bind(call, tree, owner):
            creation = call.type in ('object_creation_expression', 'new_expression')
            if creation:
                selector = compact(call.child_by_field_name('type'))
                method = None
                raw_selector = selector
            elif call.type == 'method_invocation':
                selector = compact(call.child_by_field_name('object'))
                method = compact(call.child_by_field_name('name'))
                raw_selector = '.'.join(filter(None, (selector, method)))
            else:
                raw_selector = compact(next(iter(call.named_children), None))
                parts = raw_selector.split('.')
                selector, method = '.'.join(parts[:-1]), parts[-1]
            imports, import_lines = [], {}
            for n in tree.root_node.named_children:
                if n.type in ('import_declaration', 'import'):
                    value = re.sub(r'^import\s+|;\s*$', '', txt(n)).strip()
                    imports.append(value)
                    import_lines[value] = list(range(n.start_point.row + 1, n.end_point.row + 2))
            def bound_receipt(symbol, basis):
                # Only imports of this exact class/function establish this edge;
                # an unrelated added import cannot activate an unchanged call.
                relevant = []
                for value, lines in import_lines.items():
                    imported = value.removeprefix('static ').split(' as ')[0]
                    if imported == symbol or imported == symbol.rpartition('.')[0]: relevant.extend(lines)
                return {**receipt(new_path, symbol, basis, ['compiler resolves overloads and product classpath']),
                        'caller_binding_lines': sorted(set(relevant))}
            def resolves(value, qualified, *, static=False):
                if not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*', value): return False
                relevant = [v.removeprefix('static ') for v in imports if v.startswith('static ') == static]
                explicit = [v for v in relevant if v.rsplit('.', 1)[-1] == value or v.endswith(' as ' + value)]
                if explicit:
                    return all(v in (qualified, qualified + ' as ' + value) for v in explicit)
                return not static and (value == qualified or (value == qualified.rsplit('.', 1)[-1]
                            and package_name(tree) == qualified.rpartition('.')[0]))
            if lang == 'kotlin' and caller_lang == 'kotlin':
                for declaration in top_functions:
                    qualified = '.'.join(filter(None, (package, function_parts(declaration)[0])))
                    if resolves(raw_selector, qualified) and not tree_shadows(tree, owner, raw_selector.split('.')[0], functions_shadow=True):
                        return bound_receipt(qualified, 'declared_kotlin_function_and_import')
            for declaration in types:
                name = compact(declaration.child_by_field_name('name'))
                if not name or names[name] != 1: continue
                qualified = '.'.join(filter(None, (package, name)))
                constructor = creation or (caller_lang == 'kotlin' and declaration.type == 'class_declaration' and resolves(raw_selector, qualified))
                selected = raw_selector if constructor and caller_lang == 'kotlin' else selector
                direct_member = not constructor and not selector
                selected = method if direct_member else selected
                member = method
                if direct_member:
                    originals = []
                    for imported in imports:
                        value, *alias = imported.removeprefix('static ').split(' as ')
                        local = alias[0] if alias else value.rsplit('.', 1)[-1]
                        if local == selected and value.rpartition('.')[0] == qualified:
                            originals.append(value.rsplit('.', 1)[-1])
                    if len(set(originals)) != 1: continue
                    member = originals[0]
                matches = resolves(selected, qualified + '.' + member, static=caller_lang == 'java') if direct_member else resolves(selected, qualified)
                if not matches: continue
                if tree_shadows(tree, owner, selected.split('.')[0], functions_shadow=direct_member): continue
                if not constructor:
                    def belongs(n):
                        parent = n.parent
                        while parent is not None and parent.type not in TS_TYPES:
                            parent = parent.parent
                        return parent == declaration
                    methods = [n for n in walk(declaration) if n.type in TS_FUNCTIONS and function_parts(n)[0] == member and belongs(n)]
                    if not methods: continue
                    if lang == 'java' and not any(re.search(r'\bstatic\b', txt(n.child_by_field_name('modifiers')) or txt(next((c for c in n.named_children if c.type == 'modifiers'), None))) for n in methods):
                        continue
                    if lang == 'kotlin' and declaration.type != 'object_declaration':
                        def companion(n):
                            parent = n.parent
                            while parent is not None and parent != declaration:
                                if parent.type == 'companion_object': return True
                                parent = parent.parent
                            return False
                        if not any(companion(n) for n in methods): continue
                    if lang == 'kotlin' and caller_lang == 'java':
                        if not any(re.search(r'@(?:kotlin\.jvm\.)?JvmStatic\b', txt(next((c for c in n.named_children if c.type == 'modifiers'), None))) for n in methods):
                            continue
                return bound_receipt(qualified + ('.' + member if member and not constructor else ''),
                                     'package_or_explicit_import_and_declared_callable')
            return None
        return bind

    # Free native functions: no basename guessing and no credit for prototypes
    # without a body. Static definitions in a new translation unit are private.
    exports = {}
    for n in walk(source.root_node):
        if n.type != 'function_definition': continue
        name = function_parts(n)[0]
        if not re.fullmatch(r'[A-Za-z_]\w*', name): continue
        cursor, disabled, namespace = n.parent, False, []
        while cursor:
            if cursor.type in TS_TYPES:
                if cursor.type == 'namespace_definition': namespace.append(compact(cursor.child_by_field_name('name')))
                else: disabled = True
            if cursor.type in ('preproc_if', 'preproc_elif', 'preproc_ifdef'):
                # Conditional definitions require build-configuration evidence.
                disabled = True
            cursor = cursor.parent
        if any(c.type == 'storage_class_specifier' and txt(c) == 'static' for c in n.named_children):
            disabled = True
        if not disabled:
            qualified = '::'.join([*reversed(namespace), name])
            exports[qualified] = exports.get(qualified, 0) + 1
    def bind(call, tree, owner):
        selector = compact(call.child_by_field_name('function'))
        if exports.get(selector) != 1 or tree_shadows(tree, owner, selector.split('::')[0], native=True): return None
        return receipt(new_path, selector, 'declared_native_external_function',
                       ['build links this new translation unit into the caller; no alternate external definition'])
    return bind


def binding_for(new_path, new_text, caller_path):
    if PurePosixPath(new_path).suffix == '.py' and PurePosixPath(caller_path).suffix == '.py':
        return python_binder(new_path, new_text, caller_path)
    return tree_binder(new_path, new_text, caller_path)


def manifest_binding(new_path, new_text, name, manifest_package):
    lang, tree = parse_source(new_path, new_text)
    if lang not in ('java', 'kotlin') or tree.root_node.has_error: return None
    if name.startswith('.'):
        qualified = manifest_package + name
    elif '.' not in name:
        qualified = '.'.join(filter(None, (manifest_package, name)))
    else:
        qualified = name
    package = package_name(tree)
    matches = [n for n in tree.root_node.named_children if n.type in TS_TYPES
               and '.'.join(filter(None, (package, compact(n.child_by_field_name('name'))))) == qualified]
    if len(matches) != 1: return None
    return receipt(new_path, qualified, 'manifest_component_exact_class', ['Android component instantiation and product configuration'])
