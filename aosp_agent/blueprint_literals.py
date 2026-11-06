"""Bounded static Blueprint expressions, not Soong's product/module evaluator.

Rules follow Android 12 Blueprint parser/parser.go: variables are immutable,
only local unreferenced variables permit +=, and children inherit values.
Unknown expressions, include directives and resource limits remain errors.
"""
import json
import re


TOKEN = re.compile(r'\s+|//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z_]\w*|\d+|\S')
IDENTIFIER = re.compile(r'[A-Za-z_]\w*\Z')
MAX_BYTES = 4 * 1024 * 1024
MAX_ITEMS = 200_000
MAX_DEPTH = 64


class LiteralParser:
    def __init__(self, text, inherited=None):
        if len(text.encode()) > MAX_BYTES:
            raise ValueError('Blueprint metadata byte limit exceeded')
        self.tokens = []
        for match in TOKEN.finditer(text):
            token = match[0]
            if token.isspace() or token.startswith(('//', '/*')):
                continue
            self.tokens.append(token)
            if len(self.tokens) > MAX_ITEMS:
                raise ValueError('Blueprint metadata token limit exceeded')
        self.pos, self.remaining = 0, MAX_ITEMS
        self.inherited, self.local, self.referenced = dict(inherited or {}), {}, set()

    def charge(self, amount=1):
        self.remaining -= amount
        if self.remaining < 0:
            raise ValueError('Blueprint expression evaluation limit exceeded')

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, expected=None):
        token = self.peek()
        if token is None or expected is not None and token != expected:
            raise ValueError('expected ' + str(expected or 'value') + ', found ' + str(token))
        self.pos += 1
        return token

    def identifier(self):
        token = self.take()
        if not IDENTIFIER.fullmatch(token):
            raise ValueError('expected Blueprint identifier')
        return token

    def plus(self, left, right, depth=0):
        self.charge()
        if depth > MAX_DEPTH:
            raise ValueError('Blueprint expression depth limit exceeded')
        if type(left) is not type(right) or isinstance(left, bool):
            raise ValueError('incompatible types for Blueprint +')
        if isinstance(left, str):
            if len(left) + len(right) > MAX_BYTES:
                raise ValueError('Blueprint string expansion limit exceeded')
            result = left + right
            if len(result.encode()) > MAX_BYTES:
                raise ValueError('Blueprint string byte limit exceeded')
            self.charge(min(len(result), MAX_ITEMS + 1))
            return result
        if isinstance(left, list):
            self.charge(len(left) + len(right))
            return left + right
        if isinstance(left, dict):
            self.charge(len(left) + len(right))
            result = dict(left)
            for key, value in right.items():
                result[key] = self.plus(result[key], value, depth + 1) if key in result else value
            return result
        if isinstance(left, int):
            result = left + right
            if not -(2 ** 63) <= result < 2 ** 63:
                raise ValueError('Blueprint integer overflow requires external evaluation')
            return result
        raise ValueError('unsupported Blueprint + operand')

    def expression(self, depth=0, *, allow_plus=True):
        self.charge()
        if depth > MAX_DEPTH:
            raise ValueError('Blueprint expression depth limit exceeded')
        token = self.take()
        if token.startswith('"'):
            value = json.loads(token)
        elif token in ('true', 'false'):
            value = token == 'true'
        elif token.isdigit() or token == '-':
            number = self.take() if token == '-' else token
            if not number.isdigit():
                raise ValueError('expected decimal integer')
            value = int(number) * (-1 if token == '-' else 1)
            if not -(2 ** 63) <= value < 2 ** 63:
                raise ValueError('Blueprint integer out of range')
        elif token in ('[', '{'):
            value, end = ([], ']') if token == '[' else ({}, '}')
            while self.peek() != end:
                if isinstance(value, dict):
                    key = self.identifier()
                    self.take(':')
                    if key in value:
                        raise ValueError('duplicate Blueprint property: ' + key)
                    value[key] = self.expression(depth + 1)
                else:
                    value.append(self.expression(depth + 1))
                if self.peek() == ',':
                    self.take(',')
                elif self.peek() != end:
                    raise ValueError('expected comma or ' + end)
            self.take(end)
        elif IDENTIFIER.fullmatch(token):
            if token in self.local:
                self.referenced.add(token)
                value = self.local[token]
            elif token in self.inherited:
                value = self.inherited[token]
            else:
                raise ValueError('undefined Blueprint variable: ' + token)
        else:
            raise ValueError('unsupported Blueprint expression: ' + token)
        # Blueprint parses + right-associatively. Limit both nesting and work
        # before allocating concatenations; references do not mutate values.
        if allow_plus and self.peek() == '+':
            self.take('+')
            value = self.plus(value, self.expression(depth + 1), depth)
        return value

    def parse(self, path):
        modules, issues = [], []
        while self.peek() is not None:
            name = self.identifier()
            if self.peek() == '{':
                properties = self.expression(allow_plus=False)
                if not isinstance(properties, dict):
                    raise ValueError('module properties must be a map')
                if name == 'package':
                    continue  # Package visibility is not a source consumer.
                if name == 'soong_namespace':
                    issues.append({'path': path, 'kind': name, 'source_bearing': True,
                                   'reason': 'namespace resolution requires qualified build metadata'})
                    continue
                if not isinstance(properties.get('name'), str):
                    raise ValueError('missing module name: ' + name)
                modules.append({'kind': name, 'path': path, 'properties': properties,
                                'name': properties['name']})
            else:
                append = self.peek() == '+'
                if append:
                    self.take('+')
                self.take('=')
                value = self.expression()
                if name in ('subdirs', 'optional_subdirs', 'build'):
                    raise ValueError('Blueprint file include directive requires external evaluation: ' + name)
                if append:
                    if name not in self.local:
                        raise ValueError('cannot append undefined or inherited variable: ' + name)
                    if name in self.referenced:
                        raise ValueError('cannot append referenced variable: ' + name)
                    self.local[name] = self.plus(self.local[name], value)
                else:
                    if name in self.local or name in self.inherited:
                        raise ValueError('Blueprint variable already assigned: ' + name)
                    self.local[name] = value
        return modules, issues, {**self.inherited, **self.local}


def parse_metadata(text, path, inherited=None):
    """An invalid file never exports partial variable bindings or modules."""
    try:
        return LiteralParser(text, inherited).parse(path)
    except (ValueError, IndexError, RecursionError) as exc:
        return [], [{'path': path, 'reason': str(exc), 'source_bearing': True}], None
