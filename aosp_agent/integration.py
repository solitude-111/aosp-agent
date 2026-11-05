"""Conservative source-integration evidence; not a whole-program reachability proof."""
import ast
import re
import xml.etree.ElementTree as ET

from .discovery import functions


def added_numbers(hunks):
    numbers = set()
    for hunk in hunks:
        current = None
        for line in hunk['patch'].splitlines():
            header = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)', line)
            if header:
                current = int(header[1])
            elif current is not None:
                if line.startswith('+'):
                    numbers.add(current)
                    current += 1
                elif line.startswith(' '):
                    current += 1
    return numbers


def activation(path, baseline, candidate, hunks, identities):
    """Return an added call in an existing function or a new manifest component.

    No credit for comments, log strings, type declarations, imports, tests,
    build inclusion or newly invented caller functions. Unsupported dynamic
    registration requires a future typed evidence adapter and fails closed here.
    """
    changed = added_numbers(hunks)
    names = {s for s in identities if re.fullmatch(r'[A-Za-z_$][\w$]*', s)}
    suffix = path.rsplit('.', 1)[-1]
    if path.endswith('AndroidManifest.xml'):
        try:
            def components(text):
                return {(node.tag, node.get('{http://schemas.android.com/apk/res/android}name'))
                        for node in ET.fromstring(text).iter()
                        if node.tag in {'activity', 'service', 'receiver', 'provider', 'application'}}
            for tag, name in sorted(components(candidate) - components(baseline)):
                if name and name.rsplit('.', 1)[-1] in names:
                    return {'path': path, 'kind': 'manifest_component', 'identifier': name,
                            'component': tag}
        except ET.ParseError:
            return None
        return None
    old_functions = {f['symbol'] for f in functions(baseline, '.' + suffix)}
    scopes = [f for f in functions(candidate, '.' + suffix) if f['symbol'] in old_functions]
    if suffix == 'py':
        try:
            tree = ast.parse(candidate)
        except SyntaxError:
            return None
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or node.lineno not in changed:
                continue
            call = node.func
            tokens = {n.id for n in ast.walk(call) if isinstance(n, ast.Name)}
            tokens.update(n.attr for n in ast.walk(call) if isinstance(n, ast.Attribute))
            for scope in scopes:
                if scope['line_start'] < node.lineno <= scope['line_end'] and tokens & names:
                    return {'path': path, 'kind': 'call_in_existing_function',
                            'function': scope['symbol'], 'line': node.lineno,
                            'identifier': sorted(tokens & names)[0]}
        return None
    # Preserve line numbers while removing complete multiline comments/strings.
    masked = re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), candidate)
    for number, code in enumerate(masked.splitlines(), 1):
        if number not in changed or re.match(r'^\s*(?:import|package)\b', code):
            continue
        for scope in scopes:
            if not scope['line_start'] < number <= scope['line_end']:
                continue
            for name in sorted(names):
                # Constructor, direct call or Class.staticMethod(...).
                if re.search(r'\b' + re.escape(name) + r'\s*(?:\.\s*[\w$]+\s*)?\(', code):
                    return {'path': path, 'kind': 'call_in_existing_function',
                            'function': scope['symbol'], 'line': number, 'identifier': name}
    return None
