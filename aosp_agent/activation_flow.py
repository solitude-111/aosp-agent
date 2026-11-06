"""Local reachability filters for new-source integration, never a call graph.

We assume entry into an existing function. Constant branches, short-circuiting,
deferred bodies and guaranteed prior transfers can disprove a call's local
reachability. Unknown predicates remain explicit conditions, not product facts.
"""
import ast
from collections import Counter
import importlib
import re

UNKNOWN = object()


def literal_value(text):
    """Only literal case labels/subjects, not language-independent evaluation."""
    text = text.strip()
    while text.startswith('(') and text.endswith(')'):
        text = text[1:-1].strip()
    if text in ('true', 'false'):
        return text == 'true'
    try:
        value = ast.literal_eval(text)
    except (ValueError, SyntaxError, RecursionError):
        return UNKNOWN
    if isinstance(value, (int, str, bool)):
        return ord(value) if text.startswith("'") and isinstance(value, str) and len(value) == 1 else value
    return UNKNOWN


def literal_truth(text):
    """Evaluate a small side-effect-free literal expression, never source eval."""
    text = re.sub(r'\btrue\b', 'True', text.strip())
    text = re.sub(r'\bfalse\b', 'False', text)
    text = text.replace('&&', ' and ').replace('||', ' or ')
    text = re.sub(r'!(?!=)', ' not ', text).strip()
    try:
        node = ast.parse(text, mode='eval').body
    except (SyntaxError, ValueError, RecursionError):
        return None
    return py_truth(node)


def py_truth(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (bool, int, float, str, type(None))):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        value = py_truth(node.operand)
        return None if value is None else not value
    if isinstance(node, ast.BoolOp):
        values = [py_truth(v) for v in node.values]
        if isinstance(node.op, ast.And):
            return False if False in values else True if all(v is True for v in values) else None
        return True if True in values else False if all(v is False for v in values) else None
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = node.left, node.comparators[0]
        if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
            a, b = left.value, right.value
            try:
                if isinstance(node.ops[0], ast.Eq): return a == b
                if isinstance(node.ops[0], ast.NotEq): return a != b
                if isinstance(node.ops[0], ast.Lt): return a < b
                if isinstance(node.ops[0], ast.LtE): return a <= b
                if isinstance(node.ops[0], ast.Gt): return a > b
                if isinstance(node.ops[0], ast.GtE): return a >= b
            except TypeError:
                return None
    return None


PY_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


def py_parents(tree):
    return {id(c): (p, name, value if isinstance(value, list) else None)
            for p in ast.walk(tree) for name, value in ast.iter_fields(p)
            for c in (value if isinstance(value, list) else [value]) if isinstance(c, ast.AST)}


def py_key(node, parents):
    parts = [(type(node).__name__, node.name)]
    cursor = node
    while id(cursor) in parents:
        cursor = parents[id(cursor)][0]
        if isinstance(cursor, (*PY_FUNCTIONS, ast.ClassDef)):
            parts.append((type(cursor).__name__, cursor.name))
    return tuple(reversed(parts)) + ((ast.dump(node.args, include_attributes=False),),)


def py_sequence_exits(statements):
    return any(py_exits(s) for s in statements)


def py_exits(node):
    if isinstance(node, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    if isinstance(node, ast.Assert): return py_truth(node.test) is False
    if isinstance(node, ast.If):
        value = py_truth(node.test)
        return (py_sequence_exits(node.body) if value is True else py_sequence_exits(node.orelse)
                if value is False else py_sequence_exits(node.body) and py_sequence_exits(node.orelse))
    # TryStar exists only from Python 3.11; ordinary nodes must still be
    # analyzed on 3.10, whose parser rejects unsupported except* syntax.
    if isinstance(node, (ast.Try, getattr(ast, 'TryStar', ast.Try))):
        return py_sequence_exits(node.finalbody)
    if isinstance(node, ast.While) and py_truth(node.test) is True:
        return not any(isinstance(n, ast.Break) for statement in node.body for n in ast.walk(statement))
    return False


def python_activation(path, baseline, candidate, changed, names, bind=None):
    try:
        old, tree = ast.parse(baseline), ast.parse(candidate)
    except (SyntaxError, RecursionError):
        return None
    old_parents, parents = py_parents(old), py_parents(tree)
    old_keys = Counter(py_key(n, old_parents) for n in ast.walk(old) if isinstance(n, PY_FUNCTIONS))
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        call_changed = bool(set(range(call.lineno, call.end_lineno + 1)) & changed)
        if not call_changed and bind is None: continue
        identifiers, selector = set(), call.func
        while isinstance(selector, ast.Attribute):
            identifiers.add(selector.attr); selector = selector.value
        if isinstance(selector, ast.Name): identifiers.add(selector.id)
        else: continue  # Passing a class to factory(...) is not invoking it.
        if bind is None and not identifiers & names: continue
        cursor, owner, conditions, rejected = call, None, [], False
        while id(cursor) in parents:
            parent, field, siblings = parents[id(cursor)]
            if isinstance(parent, (ast.Lambda, ast.ClassDef, ast.GeneratorExp)):
                rejected = True; break  # A deferred body is not a call from this function.
            if isinstance(parent, ast.Match):
                # Pattern binding and guards need their own scope adapter.
                # Do not silently turn an unhandled match arm into a live call.
                if field == 'cases': rejected = True; break
            if isinstance(parent, (ast.For, ast.AsyncFor)) and field == 'body':
                iterator = parent.iter
                if isinstance(iterator, (ast.List, ast.Tuple, ast.Set)) and not iterator.elts:
                    rejected = True; break
                conditions.append('iteration is nonempty: ' + ast.unparse(iterator))
            if isinstance(parent, (ast.ListComp, ast.SetComp, ast.DictComp)):
                if any((isinstance(g.iter, (ast.List, ast.Tuple, ast.Set)) and not g.iter.elts)
                       or any(py_truth(p) is False for p in g.ifs) for g in parent.generators):
                    rejected = True; break
                conditions.append('comprehension iteration and filters')
            if siblings and field in ('body', 'orelse', 'finalbody'):
                if py_sequence_exits(siblings[:siblings.index(cursor)]):
                    rejected = True; break
            if isinstance(parent, (ast.If, ast.IfExp, ast.While)) and field in ('body', 'orelse'):
                value = py_truth(parent.test)
                desired = field == 'body'
                if isinstance(parent, ast.While) and field == 'orelse':
                    value = None  # Loop-else depends on break, not just the test.
                if value is not None and value != desired:
                    rejected = True; break
                if value is None: conditions.append(ast.unparse(parent.test))
            if isinstance(parent, ast.BoolOp):
                prior = parent.values[:parent.values.index(cursor)]
                blocked = False if isinstance(parent.op, ast.And) else True
                if any(py_truth(v) is blocked for v in prior):
                    rejected = True; break
                conditions.extend(ast.unparse(v) for v in prior if py_truth(v) is None)
            if isinstance(parent, PY_FUNCTIONS):
                if field != 'body': rejected = True  # Defaults/decorators are not function-body evidence.
                owner = parent; break
            cursor = parent
        if not rejected and owner is not None and old_keys[py_key(owner, parents)] == 1:
            binding = bind(call, tree, owner) if bind else None
            if bind and not binding: continue
            if not call_changed and not set(binding.get('caller_binding_lines', [])) & changed: continue
            return evidence(path, owner.name, call.lineno,
                            binding['symbol'] if binding else sorted(identifiers & names)[0],
                            conditions, 'python_ast', binding)
    return None


TS_FUNCTIONS = {'method_declaration', 'constructor_declaration', 'function_definition', 'function_declaration'}
TS_TYPES = {'class_declaration', 'interface_declaration', 'enum_declaration', 'struct_specifier',
            'class_specifier', 'namespace_definition', 'object_declaration'}
TS_BLOCKS = {'block', 'compound_statement', 'function_body', 'case_statement', 'switch_block_statement_group', 'switch_rule'}
TS_TRANSFERS = {'return_statement', 'throw_statement', 'break_statement', 'continue_statement',
                'return_expression', 'throw_expression', 'break_expression', 'continue_expression', 'goto_statement'}
TS_DEFERRED = {'lambda_expression', 'lambda_literal', 'anonymous_function', 'object_literal', 'class_body'}


def walk(node):
    stack = [node]
    while stack:
        current = stack.pop(); yield current
        stack.extend(reversed(current.named_children))


def txt(node):
    return node.text.decode('utf-8', errors='replace') if node is not None else ''


def compact(node):
    return re.sub(r'\s+', '', txt(node))


def selector_names(node):
    if node is None: return set()
    if node.type in ('argument_list', 'value_arguments', 'template_argument_list'): return set()
    if node.type in ('call_expression', 'method_invocation', 'object_creation_expression', 'new_expression'):
        return set()  # The inner call is examined separately; its arguments are not selectors.
    if not node.named_children:
        return {txt(node)} if re.fullmatch(r'[A-Za-z_$][\w$]*', txt(node)) else set()
    return set().union(*(selector_names(child) for child in node.named_children))


def function_parts(node):
    name, params = node.child_by_field_name('name'), node.child_by_field_name('parameters')
    receiver = ''
    if node.type == 'function_definition':
        declarator = node.child_by_field_name('declarator')
        declaration = next((n for n in walk(declarator) if n.type == 'function_declarator'), None) if declarator else None
        if declaration:
            name, params = declaration.child_by_field_name('declarator'), declaration.child_by_field_name('parameters')
    if node.type == 'function_declaration':
        params = next((n for n in node.named_children if n.type == 'function_value_parameters'), None)
        # Kotlin extension receiver belongs to the callable identity too:
        # adding Other.entry must not borrow the old Main.entry declaration.
        if name is not None:
            receiver = '|'.join(compact(n) for n in node.named_children
                                if n.end_byte <= name.start_byte and n.type in ('user_type', 'nullable_type'))
    return compact(name), compact(params), receiver


def ts_key(node):
    parts, cursor = [(node.type, *function_parts(node))], node.parent
    while cursor:
        if cursor.type in TS_TYPES:
            parts.append((cursor.type, compact(cursor.child_by_field_name('name'))))
        elif cursor.type in TS_FUNCTIONS:
            parts.append((cursor.type, *function_parts(cursor)))
        cursor = cursor.parent
    return tuple(reversed(parts))


def branches(node):
    condition = node.child_by_field_name('condition')
    yes, no = node.child_by_field_name('consequence'), node.child_by_field_name('alternative')
    if node.type == 'if_expression':
        rest = [c for c in node.named_children if c != condition]
        yes, no = (rest + [None, None])[:2]
    return condition, yes, no


def ts_exits(node):
    if node.type in TS_TRANSFERS: return True
    if node.type in TS_BLOCKS: return any(ts_exits(c) for c in node.named_children)
    if node.type in ('if_statement', 'if_expression'):
        condition, yes, no = branches(node)
        value = literal_truth(txt(condition))
        return (bool(yes and ts_exits(yes)) if value is True else bool(no and ts_exits(no))
                if value is False else bool(yes and no and ts_exits(yes) and ts_exits(no)))
    if node.type in ('while_statement', 'while_expression'):
        condition = node.child_by_field_name('condition')
        return literal_truth(txt(condition)) is True and not any(
            n.type in ('break_statement', 'break_expression') for n in walk(node))
    if node.type in ('try_statement', 'try_expression'):
        final = next((c for c in node.named_children if c.type in ('finally_clause', 'finally_block')), None)
        return bool(final and any(ts_exits(c) for c in final.named_children))
    return False


def switch_condition(call, control):
    """Filter simple literal switch/when arms; retain unknown conditions.

    C/Java colon arms can fall through; Java arrow and Kotlin when arms cannot.
    Unusual nested C labels are unsupported, rather than silently accepted.
    """
    kotlin = control.type == 'when_expression'
    body = control if kotlin else control.child_by_field_name('body')
    kinds = {'when_entry'} if kotlin else {'case_statement', 'switch_block_statement_group', 'switch_rule'}
    if body is None: return False, []
    arms = [c for c in body.named_children if c.type in kinds]
    selected_arm = next((i for i, arm in enumerate(arms)
                         if arm.start_byte <= call.start_byte < arm.end_byte), None)
    if selected_arm is None:
        # Calls in a subject execute before arm selection.
        condition = control.child_by_field_name('condition')
        condition = condition or next((c for c in control.named_children if c.type == 'when_subject'), None)
        return bool(condition and condition.start_byte <= call.start_byte < condition.end_byte), []
    def owning_switch(node):
        cursor = node.parent
        while cursor and cursor.type not in ('switch_statement', 'switch_expression', 'when_expression'):
            cursor = cursor.parent
        return cursor
    if any(n.type in kinds and owning_switch(n) == control for n in walk(arms[selected_arm]) if n != arms[selected_arm]):
        return False, []
    condition = control.child_by_field_name('condition')
    condition = condition or next((c for c in control.named_children if c.type == 'when_subject'), None)
    subject = literal_value(txt(condition))
    if subject is UNKNOWN:
        return True, ['switch/when selection: ' + (txt(condition) or 'subjectless conditions')]
    labels, default, uncertain = [], None, False
    for i, arm in enumerate(arms):
        if kotlin:
            values = arm.children_by_field_name('condition')
            is_default = txt(arm).lstrip().startswith('else')
        elif arm.type == 'case_statement':
            value = arm.child_by_field_name('value')
            values = [value] if value is not None else []
            is_default = txt(arm).lstrip().startswith('default')
        else:
            label = next((c for c in arm.named_children if c.type == 'switch_label'), None)
            if label is None: return False, []
            values = list(label.named_children)
            is_default = txt(label).strip() == 'default'
        if is_default: default = i
        parsed = [literal_value(txt(v)) for v in values]
        uncertain |= any(v is UNKNOWN for v in parsed) or not (parsed or is_default)
        labels.extend((v, i) for v in parsed if v is not UNKNOWN)
    if uncertain:
        return True, ['switch/when labels require constant or type resolution: ' + txt(condition)]
    start = next((i for v, i in labels if v == subject), default)
    if start is None or start > selected_arm: return False, []
    if kotlin or arms[selected_arm].type == 'switch_rule':
        return start == selected_arm, []
    return not any(ts_exits(arm) for arm in arms[start:selected_arm]), []


def tree_activation(path, baseline, candidate, changed, names, bind=None):
    suffix = path.rsplit('.', 1)[-1]
    grammar = {'java': 'java', 'c': 'c', 'h': 'cpp', 'cc': 'cpp', 'cpp': 'cpp',
               'cxx': 'cpp', 'hpp': 'cpp', 'kt': 'kotlin', 'kts': 'kotlin'}.get(suffix)
    if grammar is None: return None
    from tree_sitter import Language, Parser
    parser = Parser(Language(importlib.import_module('tree_sitter_' + grammar).language()))
    old, tree = parser.parse(baseline.encode()), parser.parse(candidate.encode())
    old_keys = Counter(ts_key(n) for n in walk(old.root_node) if n.type in TS_FUNCTIONS and not n.has_error)
    for call in walk(tree.root_node):
        if call.type not in ('call_expression', 'method_invocation', 'object_creation_expression', 'new_expression'): continue
        call_changed = bool(set(range(call.start_point.row + 1, call.end_point.row + 2)) & changed)
        if not call_changed and bind is None: continue
        if call.type == 'method_invocation':
            selectors = selector_names(call.child_by_field_name('object')) | selector_names(call.child_by_field_name('name'))
        elif call.type in ('object_creation_expression', 'new_expression'):
            selectors = selector_names(call.child_by_field_name('type'))
        else: selectors = selector_names(call.child_by_field_name('function') or next(iter(call.named_children), None))
        identifiers = selectors & names
        if bind is None and not identifiers: continue
        cursor, owner, rejected, conditions = call, None, False, []
        while cursor.parent:
            parent = cursor.parent
            if parent.type in TS_DEFERRED or parent.type in ('labeled_statement', 'ERROR'):
                rejected = True; break
            if parent.type in ('switch_statement', 'switch_expression', 'when_expression'):
                allowed, pending = switch_condition(call, parent)
                if not allowed: rejected = True; break
                conditions.extend(pending)
            if parent.type in TS_BLOCKS:
                prior = parent.named_children[:parent.named_children.index(cursor)]
                if any(ts_exits(c) for c in prior): rejected = True; break
            if parent.type in ('if_statement', 'if_expression', 'conditional_expression'):
                condition, yes, no = branches(parent)
                if cursor in (yes, no):
                    value = literal_truth(txt(condition))
                    if value is not None and value != (cursor == yes): rejected = True; break
                    if value is None: conditions.append(txt(condition))
            if parent.type in ('while_statement', 'for_statement', 'while_expression'):
                condition = parent.child_by_field_name('condition')
                body = parent.child_by_field_name('body') or next((c for c in reversed(parent.named_children) if c.type == 'block'), None)
                if cursor == body or cursor == parent.child_by_field_name('update'):
                    value = literal_truth(txt(condition))
                    if value is False: rejected = True; break
                    if value is None: conditions.append(txt(condition) or 'loop control')
            if parent.type in ('binary_expression', 'conjunction_expression', 'disjunction_expression'):
                left = parent.child_by_field_name('left') or next(iter(parent.named_children), None)
                if left is not None and cursor != left:
                    operator = txt(parent.child_by_field_name('operator'))
                    if not operator: operator = parent.text[left.end_byte-parent.start_byte:cursor.start_byte-parent.start_byte].decode().strip()
                    value = literal_truth(txt(left))
                    if (operator == '&&' and value is False) or (operator == '||' and value is True): rejected = True; break
                    if operator in ('&&', '||') and value is None: conditions.append(txt(left))
            if parent.type in ('preproc_if', 'preproc_elif', 'preproc_ifdef'):
                condition = parent.child_by_field_name('condition')
                value = literal_truth(txt(condition))
                if value is not None and value != (cursor != parent.child_by_field_name('alternative')):
                    rejected = True; break
                if value is None: conditions.append(txt(condition) or 'preprocessor configuration')
            if parent.type in TS_FUNCTIONS:
                owner = parent
                if owner.has_error or old_keys[ts_key(owner)] != 1: rejected = True
                break
            cursor = parent
        # A function may itself be compiled out. Examine enclosing preprocessor
        # branches too; unknown build conditions are not resolved here.
        cursor = owner
        while cursor is not None and cursor.parent and not rejected:
            parent = cursor.parent
            if parent.type in ('preproc_if', 'preproc_elif', 'preproc_ifdef'):
                condition = parent.child_by_field_name('condition')
                alternative = parent.child_by_field_name('alternative')
                value = literal_truth(txt(condition))
                if value is not None and value != (cursor != alternative): rejected = True
                if value is None: conditions.append(txt(condition) or 'preprocessor configuration')
            cursor = parent
        if owner is not None and not rejected:
            binding = bind(call, tree, owner) if bind else None
            if bind and not binding: continue
            if not call_changed and not set(binding.get('caller_binding_lines', [])) & changed: continue
            return evidence(path, function_parts(owner)[0], call.start_point.row + 1,
                            binding['symbol'] if binding else sorted(identifiers)[0], conditions, 'tree_sitter_' + grammar, binding)
    return None


def evidence(path, function, line, identifier, conditions, parser, binding=None):
    return {'path': path, 'kind': 'call_in_existing_function', 'function': function,
            'line': line, 'identifier': identifier, 'parser': parser,
            'scope': 'local_function_entry_assumed', 'unresolved_conditions': sorted(set(conditions)),
            'production_reachability_proven': False,
            'binding': binding or {'status': 'NOT_CHECKED'}}
