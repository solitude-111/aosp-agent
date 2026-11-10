"""Provenance of cited runtime implementation, never a semantic oracle.

The caller must first ground excerpts at the pinned target. This adapter only
recognizes an actual named definition with a body; it cannot verify a prose
behavior claim, overload resolution, dynamic dispatch or product linkage.
Unsupported source forms require more evidence, not a namespace exemption.
"""
from .activation_binding import parse_source, package_name
from .activation_flow import TS_FUNCTIONS, TS_TYPES, function_parts, txt, walk
import re


def api_identity(api):
    """Parse one callable identity without discarding a supplied overload."""
    match = re.fullmatch(r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)(?:\(([^()]*)\))?',
                         str(api).strip())
    if not match:
        return None
    parameters = None
    if match.group(2) is not None:
        parameters = [p.strip() for p in match.group(2).split(',')] if match.group(2).strip() else []
        if any(not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\[\])*', p)
               for p in parameters):
            return None
    return {'name': match.group(1), 'parameters': parameters}


def _type_identity(value):
    # Only these built-in aliases are unambiguous without import resolution.
    value = re.sub(r'\s+', '', value)
    return value.removeprefix('java.lang.') if value in (
        'java.lang.String', 'java.lang.Object', 'java.lang.Boolean', 'java.lang.Integer') else value


def _parameters_match(node, parameters, lang):
    if parameters is None:
        return True
    if lang != 'java':
        return False  # No C/Kotlin overload inference from a display signature.
    declared = node.child_by_field_name('parameters')
    if declared is None:
        return False
    types = []
    for parameter in declared.named_children:
        if parameter.type != 'formal_parameter':
            return False
        kind = parameter.child_by_field_name('type')
        if kind is None or parameter.child_by_field_name('dimensions') is not None:
            return False
        types.append(_type_identity(txt(kind)))
    return types == [_type_identity(p) for p in parameters]


def signature_call_present(api, entry):
    """Conservative Java call check for an explicitly supplied overload.

    Unknown expression types and implicit conversions remain unresolved; arity
    or the member's spelling alone must not validate an arbitrary overload.
    """
    identity = api_identity(api)
    if identity is None:
        return False
    if identity['parameters'] is None:
        return True  # Existing unsigned provenance contract, not overload proof.
    lang, tree = parse_source(entry['path'], entry['excerpt'])
    if lang != 'java' or tree is None:
        return False
    name = identity['name'].rsplit('.', 1)[-1]
    expected = [_type_identity(p) for p in identity['parameters']]
    literal_types = {'string_literal': 'String', 'decimal_integer_literal': 'int',
                     'true': 'boolean', 'false': 'boolean', 'character_literal': 'char'}
    imports = {re.sub(r'^import\s+|;\s*$', '', txt(n)).strip()
               for n in tree.root_node.named_children if n.type == 'import_declaration'}

    def names_type(spelling, qualified):
        return spelling == qualified or (spelling == qualified.rsplit('.', 1)[-1]
            and (qualified in imports or qualified.rsplit('.', 1)[0] == 'java.lang'
                 or package_name(tree) == qualified.rsplit('.', 1)[0]))

    for node in walk(tree.root_node):
        if node.type not in ('method_invocation', 'object_creation_expression'):
            continue
        field = 'type' if node.type == 'object_creation_expression' else 'name'
        if txt(node.child_by_field_name(field)).rsplit('.', 1)[-1] != name:
            continue
        if node.type == 'object_creation_expression':
            if not names_type(txt(node.child_by_field_name('type')), identity['name']):
                continue
        else:
            owner = identity['name'].rsplit('.', 1)[0]
            if not names_type(txt(node.child_by_field_name('object')), owner):
                continue
        arguments = node.child_by_field_name('arguments')
        if arguments is None:
            continue
        actual = []
        for argument in arguments.named_children:
            kind = literal_types.get(argument.type)
            if argument.type in ('cast_expression', 'object_creation_expression'):
                kind = txt(argument.child_by_field_name('type'))
            actual.append(_type_identity(kind) if kind else None)
        if actual == expected:
            return True
    return False


def definition_present(api, entry):
    identity = api_identity(api)
    if identity is None:
        return False
    name_identity = identity['name']
    lang, tree = parse_source(entry['path'], entry['excerpt'])
    if tree is None or tree.root_node.has_error:
        return False
    package = package_name(tree) if lang in ('java', 'kotlin') else ''
    for node in walk(tree.root_node):
        if node.type not in TS_FUNCTIONS:
            continue
        name = function_parts(node)[0]
        body = node.child_by_field_name('body')
        if body is None and lang == 'kotlin':
            body = next((n for n in node.named_children if n.type == 'function_body'), None)
        if not name or body is None or not any(
                c.type not in ('comment', 'line_comment', 'block_comment') for c in body.named_children):
            continue
        if not _parameters_match(node, identity['parameters'], lang):
            continue
        if lang in ('c', 'cpp'):
            # A member or nested function is not the public libc API.
            if any(n.type == 'storage_class_specifier' and txt(n) == 'static' for n in node.named_children):
                continue
            parent = node.parent
            nested = False
            while parent is not None:
                if parent.type in TS_FUNCTIONS | TS_TYPES | {'namespace_definition'}:
                    nested = True
                parent = parent.parent
            if not nested and name == name_identity:
                return True
        elif lang in ('java', 'kotlin'):
            owners = []
            parent = node.parent
            while parent is not None:
                if parent.type in TS_TYPES:
                    owners.append(txt(parent.child_by_field_name('name')))
                elif parent.type in TS_FUNCTIONS:
                    owners = []; break
                parent = parent.parent
            qualified = '.'.join(filter(None, (package, *reversed(owners))))
            if package and owners and ((name_identity == qualified and name == owners[0])
                                       or name_identity == qualified + '.' + name):
                return True
    return False


def receipt(assessment):
    """Expose exactly what is checked, separately from the model's claim."""
    return {'policy': 'target_implementation_provenance_v1',
            'status': 'SOURCE_GROUNDED' if (assessment.get('causal_chain') or {}).get('platform_semantics')
                      else 'NOT_USED',
            'semantic_correctness_proven': False, 'runtime_dispatch_proven': False,
            'claims': [{'api': item['api'], 'behavior': item['behavior'],
                        'call_sites': item['relied_at_evidence'],
                        'implementation': item['implementation_evidence']}
                       for item in (assessment.get('causal_chain') or {}).get('platform_semantics', [])]}
