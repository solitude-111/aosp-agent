"""Bounded Java continuation checks, separate from textual hunk coverage.

A conditional call is not a return from its caller. A newly introduced call-only
guard needs a grounded semantic postcondition; its shape alone never declares a
denial obligation. Explicit donor control transfers can establish a local
no-fallthrough obligation. Neither result proves application-level security.
"""
import re

from .activation_flow import branches, literal_truth, ts_key, txt, walk
from .java_regions import JavaSource, owner
from .patches import text_hunks


def _children(node):
    return [n for n in node.named_children if not n.type.endswith('_comment')]


def _key(node):
    while node is not None and node.type == 'parenthesized_expression' and len(node.named_children) == 1:
        node = node.named_children[0]
    return re.sub(r'\s+', '', txt(node))


def _exits(node):
    if node is None:
        return False
    if node.type in ('return_statement', 'throw_statement'):
        return True
    if node.type == 'block':
        return any(_exits(child) for child in _children(node))
    if node.type == 'if_statement':
        condition, yes, no = branches(node)
        known = literal_truth(txt(condition))
        return _exits(yes) if known is True else _exits(no) if known is False else _exits(yes) and _exits(no)
    return False


def introduced_effects(patch):
    effects = []
    for hunk in text_hunks(patch):
        added = '\n'.join(row['text'] for row in hunk['lines'] if row['marker'] == '+')
        if not re.search(r'\bif\s*\(', added):
            continue
        source = JavaSource('ConditionalEffect.java', 'class ConditionalEffect { void check() {\n' + added + '\n} }')
        if source.tree.root_node.has_error:
            continue  # Partial conditions are outside this deliberately narrow detector.
        for node in walk(source.tree.root_node):
            if node.type != 'if_statement':
                continue
            condition, body, other = branches(node)
            if body is None or body.type != 'block' or other is not None:
                continue
            statements = _children(body)
            def effect(statement):
                if statement.type in ('return_statement', 'throw_statement'):
                    return True
                return (statement.type == 'expression_statement' and len(statement.named_children) == 1
                        and statement.named_children[0].type == 'method_invocation')
            if statements and all(effect(statement) for statement in statements):
                effects.append({'condition': _key(condition), 'branch': txt(body),
                                'source_excludes_continuation': _exits(body)})
    return effects


def verify_no_fallthrough(baseline, candidate, condition, *, start=1, end=None):
    """Check a caller-supplied predicate-true exclusion obligation locally.

    All unchanged baseline executable statements after the matched guard are
    treated conservatively as protected. This API does not decide which business
    condition must deny access, or whether a side-effect-only repair is valid.
    """
    old, new = JavaSource('Target.java', baseline), JavaSource('Target.java', candidate)
    if old.tree.root_node.has_error or new.tree.root_node.has_error:
        return {'status': 'UNRESOLVED', 'reason': 'source parsing is incomplete'}
    methods = old.overlapping_methods(start, end or len(baseline.splitlines()))
    candidates = []
    for method in methods:
        for current in new.methods:
            if ts_key(current) != ts_key(method):
                continue
            body = current.child_by_field_name('body')
            for guard in _children(body):
                if guard.type == 'if_statement' and _key(branches(guard)[0]) == condition:
                    candidates.append((method, current, guard))
    if len(candidates) != 1:
        return {'status': 'UNRESOLVED', 'reason': 'guard is missing, renamed, nested or ambiguous'}
    method, current, guard = candidates[0]
    protected = {_key(node) for node in walk(method.child_by_field_name('body'))
                 if node.type in ('expression_statement', 'local_variable_declaration')
                 and owner(node, {'method_declaration', 'constructor_declaration'}) == method}
    reachable, unsupported = [], []

    # Only primitive method parameters and literal expressions are stable under
    # calls. Repeating a field read or method invocation can observe a new value.
    primitive_parameters = set()
    parameters = current.child_by_field_name('parameters')
    for parameter in _children(parameters) if parameters is not None else []:
        kind = parameter.child_by_field_name('type')
        name = parameter.child_by_field_name('name')
        if kind is not None and kind.type in {'boolean_type', 'integral_type', 'floating_point_type'} and name is not None:
            primitive_parameters.add(txt(name))
    first_condition, first_body, _ = branches(guard)
    pure_nodes = {'parenthesized_expression', 'unary_expression', 'binary_expression',
        'identifier', 'true', 'false', 'decimal_integer_literal', 'hex_integer_literal',
        'octal_integer_literal', 'binary_integer_literal', 'decimal_floating_point_literal',
        'hex_floating_point_literal', 'character_literal'}
    stable_condition = all(node.type in pure_nodes and
        (node.type != 'identifier' or txt(node) in primitive_parameters) for node in walk(first_condition))

    def known(node):
        key = _key(node)
        if stable_condition:
            if key == condition: return True
            if key in ('!' + condition, '!(' + condition + ')'): return False
        return literal_truth(txt(node))

    def sequence(statements, *, continuation=False):
        for statement in statements:
            if statement.type in ('return_statement', 'throw_statement'):
                return False
            if statement.type == 'block':
                if not sequence(_children(statement), continuation=continuation): return False
            elif statement.type == 'if_statement':
                test, yes, no = branches(statement)
                truth = known(test)
                if truth is True:
                    if not sequence([yes], continuation=continuation): return False
                elif truth is False:
                    if no is not None and not sequence([no], continuation=continuation): return False
                else:
                    yes_continues = sequence([yes], continuation=continuation)
                    no_continues = sequence([no], continuation=continuation) if no is not None else True
                    if not yes_continues and not no_continues: return False
            elif statement.type in ('expression_statement', 'local_variable_declaration'):
                if continuation or _key(statement) in protected:
                    reachable.append(new.snippet(statement))
                # A predicate changed after the guard invalidates the simple
                # same-predicate reasoning. No dataflow guess grants approval.
                if any(n.type in ('assignment_expression', 'update_expression') for n in walk(statement)):
                    unsupported.append('predicate state may change along the continuation')
            else:
                unsupported.append('unsupported continuation statement: ' + statement.type)
        return True

    siblings = _children(current.child_by_field_name('body'))
    # The contract assumes the original guard evaluated true once. It makes no
    # claim about subsequent evaluations of a potentially mutable predicate.
    if sequence([first_body]):
        tail = siblings[siblings.index(guard) + 1:]
        if sequence(tail, continuation=True) and (not protected or not tail):
            unsupported.append('no grounded continuation or explicit control transfer')
    return {'status': 'UNRESOLVED' if reachable or unsupported else 'EXCLUDED',
            'condition': condition, 'guard': new.snippet(guard), 'reachable_continuation': reachable,
            'limitations': sorted(set(unsupported)), 'scope': 'local_predicate_true_paths_only'}


def coverage_gate(donor_patch, baseline, candidate, *, start=1, end=None):
    obligations = []
    for effect in introduced_effects(donor_patch):
        proof = verify_no_fallthrough(baseline, candidate, effect['condition'], start=start, end=end)
        # A call-only donor branch does not establish a denial postcondition.
        # A locally proven exclusion closes this structural gap even when the
        # donor itself only calls a helper. It does not prove the business
        # postcondition; the original impact and obligation reviews still run.
        source_bound = effect['source_excludes_continuation']
        obligations.append({**effect, 'local_proof': proof,
            'obligation': 'source_control_transfer' if source_bound else 'semantic_postcondition_unresolved',
            'status': 'COVERED' if proof['status'] == 'EXCLUDED' else 'UNRESOLVED'})
    return {'status': 'UNRESOLVED' if any(row['status'] == 'UNRESOLVED' for row in obligations) else
                      'COVERED' if obligations else 'NOT_REQUIRED',
            'obligations': obligations, 'runtime_security_proven': False}
