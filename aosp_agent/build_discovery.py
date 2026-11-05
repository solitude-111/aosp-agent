"""Conservative Android.bp source ownership from pinned target blobs.

Supports literal modules, globs and filegroup references. Dynamic expressions,
conditional source lists, ambiguous names and source-bearing defaults remain
explicitly unresolved; this is not a replacement for the Soong evaluator.
"""
import json
from pathlib import PurePosixPath
import re
import subprocess

TOKEN = re.compile(r'\s+|//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z_][\w.]*|\d+|[{}\[\]:,]|\S')
BUILDABLE = {'java_library', 'java_library_static', 'java_library_host', 'java_test', 'java_test_host',
             'android_library', 'android_app', 'android_test', 'cc_library', 'cc_library_static',
             'cc_library_shared', 'cc_binary', 'cc_test', 'rust_library', 'rust_binary'}
CONDITIONAL = {'arch', 'target', 'product_variables', 'soong_config_variables'}


def parse_modules(text, path):
    tokens = [m[0] for m in TOKEN.finditer(text)
              if not m[0].isspace() and not m[0].startswith(('//', '/*'))]
    modules, issues = [], []
    def value(i):
        token = tokens[i]
        if token.startswith('"'):
            return json.loads(token), i + 1
        if token in ('true', 'false'):
            return token == 'true', i + 1
        if token in ('[', '{'):
            obj, end = ([] if token == '[' else {}), (']' if token == '[' else '}')
            i += 1
            while tokens[i] != end:
                if isinstance(obj, dict):
                    key = tokens[i]
                    if tokens[i + 1] != ':' or key in obj:
                        raise ValueError('invalid or duplicate property')
                    item, i = value(i + 2)
                    obj[key] = item
                else:
                    item, i = value(i)
                    obj.append(item)
                if tokens[i] == ',':
                    i += 1
                elif tokens[i] != end:
                    raise ValueError('dynamic expression')
            return obj, i + 1
        # Literals such as numeric SDK levels are harmless properties.
        if token.isdigit():
            return int(token), i + 1
        raise ValueError('non-literal expression')
    i = 0
    while i + 1 < len(tokens):
        if not re.fullmatch(r'[A-Za-z_]\w*', tokens[i]) or tokens[i + 1] != '{':
            i += 1
            continue
        kind, start = tokens[i], i + 1
        depth, end = 0, start
        while end < len(tokens):
            depth += (tokens[end] == '{') - (tokens[end] == '}')
            end += 1
            if depth == 0:
                break
        try:
            properties, parsed_end = value(start)
            if parsed_end != end or not isinstance(properties.get('name'), str):
                raise ValueError('missing literal name')
            modules.append({'kind': kind, 'path': path, 'properties': properties,
                            'name': properties['name']})
        except (ValueError, IndexError) as exc:
            issues.append({'path': path, 'kind': kind, 'reason': str(exc)})
        i = end
    return modules, issues


def glob_matches(pattern, path):
    if pattern.startswith('/') or '..' in PurePosixPath(pattern).parts:
        return False
    parts, index = [], 0
    while index < len(pattern):
        if pattern[index:index + 3] == '**/':
            parts.append('(?:.*/)?'); index += 3
        elif pattern[index:index + 2] == '**':
            parts.append('.*'); index += 2
        elif pattern[index] == '*':
            parts.append('[^/]*'); index += 1
        elif pattern[index] == '?':
            parts.append('[^/]'); index += 1
        else:
            parts.append(re.escape(pattern[index])); index += 1
    return re.fullmatch(''.join(parts), path) is not None


def discover_build(repo, paths, limit=2000):
    modules, issues = [], []
    bp_files = sorted(p for p in repo.files if PurePosixPath(p).name == 'Android.bp')
    if len(bp_files) > limit:
        return {'status': 'UNRESOLVED', 'modules': [], 'uncovered': sorted(paths),
                'issues': [{'reason': 'build file scan limit exceeded'}]}
    for bp in bp_files:
        try:
            found, errors = parse_modules(repo.read(bp), bp)
            modules.extend(found); issues.extend(errors)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            issues.append({'path': bp, 'reason': str(exc)})
    by_name = {}
    for module in modules:
        by_name.setdefault(module['name'], []).append(module)
    def literals(properties, field):
        items = properties.get(field, [])
        if not isinstance(items, list) or not all(isinstance(s, str) for s in items):
            raise ValueError('non-literal ' + field)
        return items
    def owns(module, path, seen):
        name, p = module['name'], module['properties']
        if name in seen or len(by_name[name]) != 1:
            raise ValueError('cyclic or ambiguous module: ' + name)
        if CONDITIONAL.intersection(p):
            raise ValueError('conditional source configuration: ' + name)
        if p.get('enabled', True) is not True:
            return False
        for default in literals(p, 'defaults'):
            candidates = by_name.get(default, [])
            if len(candidates) != 1:
                raise ValueError('unresolved defaults: ' + default)
            props = candidates[0]['properties']
            if any(k in props for k in ('srcs', 'exclude_srcs', 'defaults', 'enabled', *CONDITIONAL)):
                raise ValueError('source-bearing or conditional defaults: ' + default)
        directory = str(PurePosixPath(module['path']).parent)
        relative = path if directory == '.' else path.removeprefix(directory + '/')
        inside = directory == '.' or relative != path
        if any(source.startswith(':') for source in literals(p, 'exclude_srcs')):
            raise ValueError('filegroup exclusion requires Soong evaluation: ' + name)
        if inside and any(glob_matches(pattern, relative) for pattern in literals(p, 'exclude_srcs')):
            return False
        found = False
        for source in literals(p, 'srcs'):
            if source.startswith(':'):
                groups = by_name.get(source[1:], [])
                if len(groups) != 1 or groups[0]['kind'] != 'filegroup':
                    raise ValueError('unresolved filegroup: ' + source)
                found |= owns(groups[0], path, seen | {name})
            else:
                found |= inside and glob_matches(source, relative)
        return found
    targets, covered = [], set()
    for module in modules:
        if module['kind'] not in BUILDABLE or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*', module['name']):
            continue
        try:
            matched = [path for path in paths if owns(module, path, set())]
            if matched:
                targets.append({'name': module['name'], 'build_file': module['path'],
                                'kind': module['kind'], 'sources': sorted(matched)})
                covered.update(matched)
        except ValueError as exc:
            issues.append({'path': module['path'], 'module': module['name'], 'reason': str(exc)})
    return {'status': 'RESOLVED' if paths and covered == set(paths) else 'UNRESOLVED',
            'modules': targets, 'uncovered': sorted(set(paths) - covered), 'issues': issues,
            'scope': 'literal_source_ownership_not_product_reachability'}
