"""Provenance of cited runtime implementation, never a semantic oracle.

The caller must first ground excerpts at the pinned target. This adapter only
recognizes an actual named definition with a body; it cannot verify a prose
behavior claim, overload resolution, dynamic dispatch or product linkage.
Unsupported source forms require more evidence, not a namespace exemption.
"""
from .activation_binding import parse_source, package_name
from .activation_flow import TS_FUNCTIONS, TS_TYPES, function_parts, txt, walk


def definition_present(api, entry):
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
            if not nested and name == api:
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
            if package and owners and ((api == qualified and name == owners[0])
                                       or api == qualified + '.' + name):
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
