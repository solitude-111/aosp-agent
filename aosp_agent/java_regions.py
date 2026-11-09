"""Java declarations and stable line ranges for pinned and candidate source."""
from bisect import bisect_right
import re

from .activation_binding import parse_source
from .activation_flow import txt, walk


TYPES = {'class_body', 'interface_body', 'enum_body'}
CALLABLES = {'method_declaration', 'constructor_declaration', 'compact_constructor_declaration'}
TYPE_DECLARATIONS = {'class_declaration', 'interface_declaration', 'enum_declaration',
                     'record_declaration', 'annotation_type_declaration'}
FIELDS = {'field_declaration', 'constant_declaration'}


class JavaSource:
    def __init__(self, path, text):
        self.text = text
        _, self.tree = parse_source(path, text)
        # Point objects in the pinned parser can crash on large Linux trees.
        self.line_starts = [0, *(match.end() for match in re.finditer(b'\n', text.encode()))]
        self.callables = [n for n in walk(self.tree.root_node) if n.type in CALLABLES]
        self.methods = [n for n in self.callables if n.type == 'method_declaration']

    @property
    def imports(self):
        return [n for n in self.tree.root_node.named_children if n.type == 'import_declaration']

    def import_bounds(self):
        imports = self.imports
        if imports:
            # A final insertion immediately after the last import belongs here.
            return self.first(imports[0]), self.last(imports[-1]) + 1
        children = self.tree.root_node.named_children
        package = next((n for n in children if n.type == 'package_declaration'), None)
        declaration = next((n for n in children if n.type in TYPE_DECLARATIONS), None)
        return (self.last(package) if package else 1, self.first(declaration)) if declaration else None

    def first(self, node):
        return bisect_right(self.line_starts, node.start_byte)

    def last(self, node):
        return bisect_right(self.line_starts, node.end_byte - 1)

    def snippet(self, node):
        return {'first_line': self.first(node), 'last_line': self.last(node), 'excerpt': txt(node)}

    def overlapping_methods(self, start, end):
        methods = [m for m in self.methods if self.first(m) <= end and start <= self.last(m)]
        # A local/anonymous class method does not split its enclosing method.
        return [m for m in methods if owner(m, {'method_declaration'}) not in methods]

    def overlapping_callables(self, start, end):
        matches = [n for n in self.callables if self.first(n) <= end and start <= self.last(n)]
        return [n for n in matches if owner(n, CALLABLES) not in matches]

    def header_bounds(self, declaration):
        body = declaration.child_by_field_name('body')
        return (self.first(declaration), self.first(body)) if body is not None else None


def owner(node, kinds):
    cursor = node.parent
    while cursor is not None and cursor.type not in kinds:
        cursor = cursor.parent
    return cursor


def method_name(node):
    return txt(node.child_by_field_name('name'))


def mapped_name(symbol):
    return re.split(r'[.#]|::', symbol.split('(', 1)[0])[-1].strip()
