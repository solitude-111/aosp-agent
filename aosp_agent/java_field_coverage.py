"""Collect explicit, type-bound changes to a Java boolean field's lifecycle."""
import re

from .activation_binding import package_name
from .activation_flow import branches, txt, walk
from .java_regions import TYPES, method_name, owner


ROLES = {'set', 'guard_read', 'clear'}
METHODS = {'method_declaration', 'constructor_declaration'}


def receiver_key(use):
    return use['path'], use['receiver_class_line'], use['receiver']



def _member_fields(body, name, field_type):
    return [decl for decl in body.named_children if decl.type == 'field_declaration'
            and txt(decl.child_by_field_name('type')) == field_type
            and any(txt(node.child_by_field_name('name')) == name
                    for node in decl.named_children if node.type == 'variable_declarator')]


def _bound(node, declared, field_type, receiver, same_file):
    body = owner(node, TYPES)
    if body is None:
        return False
    if receiver == 'this':
        return same_file and body == declared
    if not re.fullmatch(r'[A-Za-z_$][\w$]*', receiver) or len(_member_fields(body, receiver, field_type)) != 1:
        return False
    method = owner(node, METHODS)
    return method is not None and not any(
        n.type in ('formal_parameter', 'spread_parameter', 'variable_declarator', 'catch_formal_parameter',
                   'enhanced_for_statement', 'lambda_expression', 'inferred_parameters')
        and (txt(n.child_by_field_name('name')) == receiver
             or (n.type in ('lambda_expression', 'inferred_parameters')
                 and re.search(r'\b' + re.escape(receiver) + r'\b', txt(n.child_by_field_name('parameters') or n))))
        for n in walk(method))


def _state_use(node):
    parent = node.parent
    if parent.type == 'assignment_expression' and parent.child_by_field_name('left') == node:
        right = txt(parent.child_by_field_name('right'))
        if txt(parent.child_by_field_name('operator')) == '=' and right in ('true', 'false'):
            return ('set' if right == 'true' else 'clear'), parent
        return None, None
    guard = owner(node, {'if_statement'} | METHODS)
    if guard is not None and guard.type == 'if_statement':
        condition, _, _ = branches(guard)
        if condition is not None and condition.start_byte <= node.start_byte < condition.end_byte:
            return 'guard_read', condition
    return None, None


def field_evidence(region, parsed, related):
    match = re.fullmatch(r'(?:[\w$]+\.)*([\w$]+)\.([\w$]+)', region['symbol'])
    if not match:
        return None, 'field obligation requires a qualified Java field name'
    field_type, name = match.groups()
    _, declaration_source, blocks = parsed
    allowed = set().union(*(lines for first, last, lines in blocks
                           if region['line_start'] <= first <= last <= region['line_end']))
    declarations = [(body, decl) for body in walk(declaration_source.tree.root_node)
                    if body.type in TYPES and body.parent.parent == declaration_source.tree.root_node
                    and method_name(body.parent) == field_type
                    for decl in _member_fields(body, name, 'boolean')
                    if not any(child.type == 'static' for part in decl.named_children if part.type == 'modifiers'
                               for child in part.children)]
    if len(declarations) != 1 or declaration_source.first(declarations[0][1]) not in allowed:
        return None, 'mapped field requires one changed boolean declaration in its target region'
    body, decl = declarations[0]
    package = package_name(declaration_source.tree)
    uses = []
    for path, (_, candidate, changes) in related.items():
        if package_name(candidate.tree) != package:
            continue
        # A different explicitly imported or nested class with this name
        # makes a simple receiver type ambiguous.
        if path != region['path'] and any(
                (n.type == 'import_declaration' and re.search(r'\.' + re.escape(field_type) + r'\s*;', txt(n)))
                or (n.type in ('class_declaration', 'interface_declaration', 'record_declaration', 'enum_declaration')
                    and method_name(n) == field_type)
                for n in walk(candidate.tree.root_node)):
            continue
        changed = set().union(*(lines for _, _, lines in changes))
        for node in walk(candidate.tree.root_node):
            if (node.type != 'field_access' or candidate.first(node) not in changed
                    or txt(node.child_by_field_name('field')) != name):
                continue
            receiver = txt(node.child_by_field_name('object'))
            if not _bound(node, body, field_type, receiver, path == region['path']):
                continue
            role, anchor = _state_use(node)
            if role:
                uses.append({'role': role, 'path': path, 'receiver': receiver,
                             'receiver_class_line': candidate.first(owner(node, TYPES).parent),
                             'evidence': candidate.snippet(anchor),
                             'method': candidate.snippet(owner(node, METHODS))})
    bindings = {}
    for use in uses:
        bindings.setdefault(receiver_key(use), set()).add(use['role'])
    if ROLES not in bindings.values():
        missing = ROLES - {u['role'] for u in uses}
        if missing:
            return None, 'field lifecycle is missing changed, bound evidence: ' + ', '.join(sorted(missing))
        return None, 'field lifecycle roles must use the same bound receiver'
    if len(uses) > 12:
        return None, 'field lifecycle has too many changed references for the bounded review'
    return {'kind': 'field_lifecycle', 'candidate': declaration_source.snippet(decl), 'state_uses': uses}, None
