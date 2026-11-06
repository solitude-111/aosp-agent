"""Conservative Android.bp source ownership from pinned target blobs.

Supports bounded static variables/expressions, modules, globs and filegroup references. Unknown expressions,
conditional source lists, ambiguous names and source-bearing defaults remain
explicitly unresolved; this is not a replacement for the Soong evaluator.
"""
from pathlib import PurePosixPath
import re

from .blueprint_literals import parse_metadata
from .blueprint_glob import glob_matches
from .build_metadata import load_metadata

BUILDABLE = {'java_library', 'java_library_static', 'java_library_host', 'java_test', 'java_test_host',
             'android_library', 'android_app', 'android_test', 'cc_library', 'cc_library_static',
             'cc_library_shared', 'cc_binary', 'cc_test', 'rust_library', 'rust_binary'}
TEST_MODULES = {'java_test', 'java_test_host', 'android_test', 'cc_test'}
CONDITIONAL = {'arch', 'target', 'product_variables', 'soong_config_variables'}


def parse_modules(text, path):
    modules, issues, _ = parse_metadata(text, path)
    return modules, issues


def discover_build(repo, paths, limit=2000):
    # The cold index includes sibling consumers. Subsequent calls at the same
    # pinned revision reuse parsed facts without traversing or reading the tree.
    metadata = load_metadata(repo, limit)
    if metadata['limit_exceeded']:
        return {'status': 'UNRESOLVED', 'modules': [], 'uncovered': sorted(paths),
                'issues': [{'reason': 'build file scan limit exceeded'}]}
    modules, issues = metadata['modules'], list(metadata['issues'])
    metadata_inputs = metadata['metadata_inputs']
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
    def could_consume(module, path, seen=frozenset()):
        """Only prune a consumer when literal metadata proves no source edge.

        Look through every conditional branch and defaults; this does not
        evaluate the product configuration. Unknown references remain possible.
        Exclusions are ignored here, making this an over-approximation.
        """
        identity = (module['path'], module['name'])
        if identity in seen:
            return True
        directory = str(PurePosixPath(module['path']).parent)
        relative = path if directory == '.' else path.removeprefix(directory + '/')
        inside = directory == '.' or relative != path
        pending = [module['properties']]
        while pending:
            props = pending.pop()
            if not isinstance(props, dict):
                continue
            pending.extend(v for v in props.values() if isinstance(v, dict))
            for field in ('srcs', 'defaults'):
                values = props.get(field, [])
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    return True
                for value in values:
                    if field == 'defaults' or value.startswith(':'):
                        reference = value if field == 'defaults' else value[1:]
                        candidates = by_name.get(reference, [])
                        if len(candidates) != 1 or could_consume(candidates[0], path, seen | {identity}):
                            return True
                    elif glob_matches(value, relative) and inside:
                        return True
        return False

    targets, covered, production_covered = [], set(), set()
    # Opaque source-bearing modules/read failures may hide a consumer. Do not
    # turn a successful test or a second simple consumer into complete coverage.
    unresolved = [dict(issue) for issue in issues if 'kind' not in issue
                  or issue['kind'] in BUILDABLE | {'filegroup'} or issue['kind'].endswith('_defaults')
                  or issue.get('source_bearing')]
    for module in modules:
        if module['kind'] == 'filegroup' or module['kind'].endswith('_defaults'):
            continue
        try:
            if not any(could_consume(module, path) for path in paths):
                continue
            if module['kind'] not in BUILDABLE or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.+-]*', module['name']):
                raise ValueError('unsupported consumer kind or module name: ' + module['kind'])
            matched = [path for path in paths if owns(module, path, set())]
            if matched:
                targets.append({'name': module['name'], 'build_file': module['path'],
                                'kind': module['kind'], 'sources': sorted(matched),
                                'role': 'test' if module['kind'] in TEST_MODULES else 'production'})
                covered.update(matched)
                if module['kind'] not in TEST_MODULES:
                    production_covered.update(matched)
        except ValueError as exc:
            issue = {'path': module['path'], 'module': module['name'], 'reason': str(exc)}
            issues.append(issue)
            if module['kind'] not in TEST_MODULES:
                unresolved.append(issue)
    return {'status': 'RESOLVED' if paths and production_covered == set(paths) and not unresolved else 'UNRESOLVED',
            'modules': targets, 'uncovered': sorted(set(paths) - covered), 'issues': issues,
            'production_uncovered': sorted(set(paths) - production_covered),
            'unresolved_consumers': unresolved,
            'retrieval_scope': 'project_build_files',
            'scope': 'static_source_ownership_not_product_reachability',
            'metadata_inputs': metadata_inputs,
            'metadata_index': metadata.get('index'),
            'expression_policy': 'bounded_blueprint_static_values_v1',
            'glob_policy': 'blueprint_posix_bounded_v1'}
