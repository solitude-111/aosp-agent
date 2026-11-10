"""Bounded evidence from a generated Ninja graph, never module-name inference.

Only an actual compiler command naming a source (directly or in an inspected
response file), its output and variant can provide compile-action credit.
Missing/unsupported graph edges remain explicit partial coverage.
"""
import hashlib
import os
from pathlib import Path
import re
import shlex

from .build_environment import canonical_hash, file_identity
from .case import validate_relative_path
from .validation_process import run_check


def ninja_log_checkpoint(path):
    path = Path(path)
    if not path.exists():
        return {'size': 0, 'prefix_sha256': hashlib.sha256(b'').hexdigest()}
    return {'size': path.stat().st_size, 'prefix_sha256': file_identity(path)['sha256']}


def _executed_outputs(path, checkpoint):
    if checkpoint is None:
        return None, 'No pre-build Ninja log checkpoint was supplied.'
    path = Path(path)
    if not path.is_file():
        return set(), 'Ninja execution log is missing.'
    size = checkpoint['size']; digest = hashlib.sha256(); remaining = size
    with path.open('rb') as stream:
        while remaining:
            data = stream.read(min(remaining, 1024 * 1024))
            if not data:
                break
            digest.update(data); remaining -= len(data)
        tail = stream.read(16 * 1024 * 1024 + 1)
    if remaining or digest.hexdigest() != checkpoint['prefix_sha256']:
        return set(), 'Ninja log was rotated or changed; this validation execution cannot be isolated.'
    if len(tail) > 16 * 1024 * 1024:
        return set(), 'Ninja execution receipt exceeds the bounded read scope.'
    outputs = set()
    for line in tail.decode(errors='replace').splitlines():
        if line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 5 and parts[0].isdigit() and parts[1].isdigit():
            outputs.add(parts[3])
    return outputs, None


def _query_outputs(text):
    outputs, selected = [], False
    for line in text.splitlines():
        if line.strip() == 'outputs:':
            selected = True
        elif selected and line.startswith('    '):
            outputs.append(line.strip())
        elif selected and line.strip():
            break
    return outputs


def _module(output):
    parts = Path(output).parts
    if '.intermediates' not in parts:
        return None
    start = parts.index('.intermediates') + 1
    for index in range(start + 1, len(parts)):
        variant = parts[index]
        if re.fullmatch(r'(?:android|linux|darwin|windows)_[A-Za-z0-9_.-]+', variant):
            return {'module': parts[index - 1], 'variant': variant,
                    'build_path': '/'.join(parts[start:index - 1]),
                    'basis': 'generated_soong_compile_output'}
    return None


def _action_input(command, source, root, output_root, programs):
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|()')
        lexer.whitespace_split = True
        segments, current = [], []
        for token in lexer:
            if token in ('&&', '||', ';', '|', '(', ')'):
                segments.append(current); current = []
            else:
                current.append(token)
        segments.append(current)
    except ValueError:
        return False, [], 'Unparseable compiler command.'
    selected = []
    for segment in segments:
        offset = 0
        while offset < len(segment) and re.match(r'[A-Za-z_][A-Za-z0-9_]*=', segment[offset]):
            offset += 1
        # Do not treat compiler names in echo arguments or a different shell
        # command as proof this source was supplied to the compiler.
        if offset < len(segment) and Path(segment[offset]).name in programs:
            selected.append(segment[offset:])
    if not selected:
        return False, [], 'No supported source compiler in the direct action.'
    for tokens in selected:
        matches, responses, reason = _input_tokens(tokens, source, root, output_root)
        if matches:
            return matches, responses, reason
    return False, [], 'No supported action names this input in its own arguments.'


def _input_tokens(tokens, source, root, output_root):
    expanded, response_files = list(tokens), []
    for token in tokens:
        if not token.startswith('@'):
            continue
        response = Path(token[1:])
        if not response.is_absolute():
            response = root / response
        response = response.resolve()
        if (not response.is_relative_to(output_root) or not response.is_file()
                or response.stat().st_size > 4 * 1024 * 1024):
            return False, response_files, 'Response file is unavailable or outside the bounded output view.'
        data = response.read_bytes()
        try:
            expanded.extend(shlex.split(data.decode()))
        except (ValueError, UnicodeError):
            return False, response_files, 'Response file cannot be parsed without guessing.'
        response_files.append({'path': str(response), 'sha256': hashlib.sha256(data).hexdigest()})
    wanted = (root / source).resolve()
    for token in expanded:
        if token.startswith('-') or token in ('&&', '||', ';'):
            continue
        path = Path(token)
        if (path if path.is_absolute() else root / path).resolve() == wanted:
            return True, response_files, None
    return False, response_files, 'The direct compiler action does not name this source.'


def _source_in_command(command, source, root, output_root):
    return _action_input(command, source, root, output_root,
        ('clang', 'clang++', 'gcc', 'g++', 'cc', 'c++', 'javac', 'kotlinc', 'rustc'))


def collect_ninja_coverage(identity, config, ninja_file, changed_paths, run_dir, *,
                           build_receipt, before_log=None, require_executed=True,
                           max_queries=128, max_depth=4, runner=None, for_discovery=False):
    """Trace unresolved paths through this product's real graph under a bound.

    ``build_receipt`` must bind a completed graph/build invocation to this same
    environment. Candidate callers provide the pre-build .ninja_log checkpoint;
    merely finding an old output cannot prove the candidate was compiled.
    """
    root, output_root = Path(identity['source_root']).resolve(), Path(config['output_root']).resolve()
    graph = Path(ninja_file).resolve()
    if (not config.get('ninja') or not graph.is_relative_to(output_root) or not graph.is_file()
            or build_receipt.get('environment_id') != identity['environment_id']
            or build_receipt.get('returncode') != 0 or not build_receipt.get('validation_id')):
        return {'status': 'GRAPH_UNAVAILABLE', 'coverage': 'partial', 'files': [],
                'uncovered': sorted(changed_paths), 'reason': 'No matching successful generated build graph receipt.'}
    paths = sorted(set(validate_relative_path(p) for p in changed_paths))
    executed, log_issue = _executed_outputs(output_root / '.ninja_log', before_log)
    calls, records, uncovered = 0, [], []
    command_cache, query_cache = {}, {}
    env = dict(config['environment'])
    run = runner or run_check

    def tool(operation, value):
        nonlocal calls
        cache = query_cache if operation == 'query' else command_cache
        if value in cache:
            return cache[value]
        if calls >= max_queries:
            return None, 'Graph query limit reached.'
        calls += 1
        args = [config['ninja'], '-f', str(graph), '-t', operation]
        if operation == 'commands':
            args.append('-s')  # One direct action, not the whole dependency closure.
        args.append(value)
        out, err, code = run(args, str(root), env, timeout=config['graph_timeout'],
                             output_limit=4 * 1024 * 1024)
        cache[value] = (out, None) if code == 0 else (None, 'Graph tool failed: ' + err[-2000:])
        return cache[value]

    for source in paths:
        entry = {'path': source, 'actions': [], 'unresolved': []}
        if Path(source).name in ('Android.bp', 'Android.mk') or source.endswith(('.bp', '.mk')):
            entry['unresolved'].append('Build-metadata changes require graph-regeneration evidence; not source compilation credit.')
        else:
            frontier, visited = [(source, source, 0, [])], set()
            while frontier:
                node, compiler_input, depth, generators = frontier.pop(0)
                if (node, compiler_input) in visited:
                    continue
                visited.add((node, compiler_input))
                text, error = tool('query', node)
                if error:
                    entry['unresolved'].append(error); continue
                for output in _query_outputs(text):
                    command, error = tool('commands', output)
                    if error:
                        entry['unresolved'].append(error); continue
                    matches, responses, explanation = _source_in_command(command, compiler_input, root, output_root)
                    module = _module(output)
                    artifact = Path(output)
                    if not artifact.is_absolute():
                        artifact = root / artifact
                    artifact = artifact.resolve()
                    did_execute = bool(executed is not None and (output in executed or str(artifact) in executed))
                    if (matches and module and artifact.is_relative_to(output_root)
                            and (for_discovery or artifact.is_file() and (did_execute or not require_executed))):
                        entry['actions'].append({**module,
                            'output': file_identity(artifact) if artifact.is_file() else {'path': str(artifact)},
                            'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
                            'response_files': responses, 'executed_in_this_validation': did_execute,
                            'generators': generators,
                            'compile_credit': bool(not for_discovery and did_execute)})
                    elif depth < max_depth:
                        generated, generator_rsp, _ = _action_input(command, compiler_input, root, output_root,
                            ('aidl', 'protoc', 'bison', 'flex'))
                        if (generated and artifact.suffix in ('.java', '.kt', '.cpp', '.cc', '.c', '.h', '.rs')
                                and artifact.is_relative_to(output_root)
                                and (for_discovery or artifact.is_file() and (did_execute or not require_executed))):
                            receipt = {'input': compiler_input, 'output': str(artifact),
                                'command_sha256': hashlib.sha256(command.encode()).hexdigest(),
                                'response_files': generator_rsp, 'executed_in_this_validation': did_execute}
                            frontier.append((output, output, depth + 1, [*generators, receipt]))
                        else:
                            frontier.append((output, compiler_input, depth + 1, generators))
                    else:
                        entry['unresolved'].append(explanation or 'Action/output/execution identity is not established.')
        if not entry['actions']:
            uncovered.append(source)
        records.append(entry)
    result = {'status': 'SOURCE_ACTIONS_GROUNDED' if not uncovered else 'PARTIAL',
              'coverage': 'partial', 'complete_for_requested_sources': not uncovered,
              'environment_id': identity['environment_id'], 'validation_id': build_receipt['validation_id'],
              'patch_sha256': build_receipt.get('patch_sha256'), 'graph': file_identity(graph),
              'files': records, 'uncovered': uncovered, 'queries': calls,
              'log_issue': log_issue, 'scope': 'observed_actions_for_one_product_and_variant',
              'purpose': 'scheduled_owner_discovery' if for_discovery else 'candidate_compile_evidence',
              'runtime_security_proven': False,
              'limitations': ['Does not establish all product variants, semantic correctness or overall complete validation.']}
    from .build_environment import _write
    destination = Path(run_dir) / ('build-graph-' + build_receipt['validation_id'] + '.json')
    _write(destination, result)
    result['record'] = str(destination)
    return result
