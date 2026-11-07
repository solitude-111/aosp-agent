"""Java declarations and stable line ranges for pinned and candidate source."""
from bisect import bisect_right
import re

from .activation_binding import parse_source
from .activation_flow import txt, walk


TYPES = {'class_body', 'interface_body', 'enum_body'}


class JavaSource:
    def __init__(self, path, text):
        _, self.tree = parse_source(path, text)
        # Point objects in the pinned parser can crash on large Linux trees.
        self.line_starts = [0, *(match.end() for match in re.finditer(b'\n', text.encode()))]
        self.methods = [n for n in walk(self.tree.root_node) if n.type == 'method_declaration']

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


def owner(node, kinds):
    cursor = node.parent
    while cursor is not None and cursor.type not in kinds:
        cursor = cursor.parent
    return cursor


def method_name(node):
    return txt(node.child_by_field_name('name'))


def mapped_name(symbol):
    return re.split(r'[.#]|::', symbol.split('(', 1)[0])[-1].strip()
