"""Read-only candidate retrieval from pinned Git trees; similarity is never impact.

No CVE, donor SHA or target filename is needed. All search limits and missing local
objects are reported. Function ranges for C-family languages are lexical hints,
not an AST/call-graph proof. Source evidence stays anchored to the original diff.
"""
from __future__ import annotations

import ast
import hashlib
import math
import os
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .case import validate_relative_path
from .git_policy import offline_git_env
from .patches import split_hunks
from .path_mapping import version_normalized_paths

STOP = set('if else return void int long bool boolean public private protected static final class new null true false const char unsigned signed struct sizeof for while switch case break try catch throw throws def self this import package include override String Object value get set'.split())
TOKEN = re.compile(r'[A-Za-z_$][\w$]*')
SOURCE_SUFFIXES = {'.java', '.kt', '.c', '.cc', '.cpp', '.h', '.hpp', '.rs', '.py', '.aidl', '.xml', '.bp', '.mk'}


def local_git(repo: Path, *args: str, check: bool = True, timeout: int = 45):
    env = offline_git_env(dict(os.environ, GIT_OPTIONAL_LOCKS='0'))
    return subprocess.run(['git', '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false',
                           '-c', 'core.hooksPath=/dev/null', '-c', 'core.quotePath=false', *args],
                          cwd=repo, env=env, capture_output=True, text=True, errors='replace',
                          check=check, timeout=timeout)


# First attempt / one timeout-only retry. These are operation budgets, not
# promises about repository health or a substitute for object-store maintenance.
READ_BUDGETS = {
    'resolve_commit': (15, 45),
    'read_tree': (45, 120),
    'guard_head': (10, 30),
    'guard_status': (45, 120),
    'guard_diff': (45, 120),
    'blob_size': (15, 45),
    'blob_read': (30, 90),
    'identifier_search': (30, 60),
}


def read_git(repo, *args, stage, check=True, timeout=None, progress=None):
    """Retry only a timed-out read, never parse partial output or alter Git state.

    An explicit timeout retains the caller's single-attempt contract. Later
    source integrity audits use this mode; inventory uses the staged policy.
    local_git reaps its process before returning/raising, so retries are serial.
    """
    budgets = READ_BUDGETS[stage] if timeout is None else (timeout,)
    if any(not isinstance(t, (int, float)) or isinstance(t, bool) or not math.isfinite(t) or t <= 0 for t in budgets):
        raise ValueError('Git read timeouts must be positive numbers')
    attempts = []
    operation = hashlib.sha256('\0'.join(args).encode()).hexdigest()[:16]
    for number, budget in enumerate(budgets, 1):
        event = {'stage': stage, 'operation': operation, 'command': args[0],
                 'attempt': number, 'max_attempts': len(budgets), 'timeout_seconds': budget}
        if progress:
            progress({**event, 'status': 'STARTED'})
        started = time.monotonic()
        try:
            result = local_git(repo, *args, check=check, timeout=budget)
        except (OSError, subprocess.SubprocessError) as exc:
            timed_out = isinstance(exc, subprocess.TimeoutExpired)
            event.update(status='TIMED_OUT' if timed_out else 'ERROR',
                         elapsed_seconds=round(time.monotonic() - started, 3), type=type(exc).__name__)
            attempts.append(event)
            if progress:
                progress(dict(event))
            exc.read_attempts = list(attempts)
            if not timed_out or number == len(budgets):
                raise
        else:
            event.update(status='SUCCEEDED' if result.returncode == 0 else 'RETURNED_NONZERO',
                         returncode=result.returncode, elapsed_seconds=round(time.monotonic() - started, 3))
            if progress:
                progress(event)
            return result


@dataclass
class Repository:
    key: str
    root: Path
    head: str
    files: dict[str, str]  # path -> mode; blobs read only on demand
    read_events: object = field(default=None, repr=False, compare=False)

    def read(self, path: str) -> str:
        validate_relative_path(path)
        if self.files.get(path) not in ('100644', '100755'):
            raise ValueError(f'not a regular tracked file: {self.key}/{path}')
        size = int(read_git(self.root, 'cat-file', '-s', f'{self.head}:{path}',
                            stage='blob_size', progress=self.read_events).stdout)
        if size > 32 * 1024 * 1024:
            raise ValueError(f'blob exceeds 32 MiB retrieval limit: {path}')
        return read_git(self.root, 'show', '--no-ext-diff', '--no-textconv', f'{self.head}:{path}',
                        stage='blob_read', progress=self.read_events).stdout

    def state(self, *, timeout=45) -> dict:
        def read(stage, *args):
            return read_git(self.root, *args, stage=stage, timeout=timeout, progress=self.read_events).stdout
        return {'head': read('guard_head', 'rev-parse', 'HEAD').strip(),
                'status': read('guard_status', 'status', '--porcelain=v1', '-z', '--untracked-files=all'),
                'diff': hashlib.sha256(read('guard_diff', 'diff', '--binary', '--no-ext-diff', 'HEAD').encode()).hexdigest()}


def repository_roots(root: Path, max_directories: int = 20000) -> list[Path]:
    """Enumerate checkouts without opening Git objects or following directory links."""
    root = root.resolve()
    roots = []
    visited = 0
    for folder, dirs, _ in os.walk(root, followlinks=False):
        visited += 1
        if visited > max_directories:
            raise ValueError('repository discovery directory limit reached; provide a narrower checkout root')
        path = Path(folder)
        if os.path.lexists(path / '.git'):
            roots.append(path)
            dirs[:] = []
        else:
            dirs[:] = sorted(d for d in dirs if not d.startswith('.') and not (path / d).is_symlink()
                             and d not in ('out', 'runs', 'node_modules'))
    if not roots:
        raise ValueError('target must be a Git worktree or a root containing Git worktrees')
    return sorted(roots)


def object_store_diagnostic(root: Path, limit=100000):
    """Cheap metadata only; a timeout is not proof of a missing object.

    Do not run fsck, fetch, gc, or repack as part of discovery. Pack fragmentation
    is an advisory maintenance clue, not a diagnosis of repository corruption.
    """
    try:
        gitdir = root / '.git'
        if gitdir.is_file():
            with gitdir.open() as stream:
                pointer = stream.read(4096).strip()
            if not pointer.startswith('gitdir: '):
                return {'status': 'UNKNOWN_GIT_DIRECTORY'}
            gitdir = (root / pointer[8:]).resolve()
        common = gitdir / 'commondir'
        if common.is_file():
            with common.open() as stream:
                gitdir = (gitdir / stream.read(4096).strip()).resolve()
        counts = {'.pack': 0, '.idx': 0, '.promisor': 0}
        truncated = False
        with os.scandir(gitdir / 'objects' / 'pack') as entries:
            for number, entry in enumerate(entries):
                if number >= limit:
                    truncated = True
                    break
                suffix = Path(entry.name).suffix
                if suffix in counts:
                    counts[suffix] += 1
        return {'status': 'METADATA_ONLY', 'pack_files': counts['.pack'], 'index_files': counts['.idx'],
                'promisor_files': counts['.promisor'], 'truncated': truncated,
                'object_completeness': 'NOT_CHECKED',
                'maintenance_hint': 'MANY_PACK_FILES' if counts['.pack'] > 1024 else 'NONE'}
    except OSError as exc:
        return {'status': 'UNAVAILABLE', 'type': type(exc).__name__, 'object_completeness': 'NOT_CHECKED'}


def repository_issue(key, stage, exc, root=None):
    issue = {'repository': key, 'stage': stage, 'status': 'UNAVAILABLE',
            'type': type(exc).__name__,
            'error': re.sub(r'sk-[A-Za-z0-9_-]{16,}', '[REDACTED]', str(exc))[-1200:]}
    if root is not None:
        issue['object_store'] = object_store_diagnostic(root)
    if getattr(exc, 'read_attempts', None):
        issue['attempts'] = exc.read_attempts
    return issue


def repositories(root: Path, max_directories: int = 20000, *, pinned_heads=None,
                 issues=None, progress=None, roots=None, timeout=None, read_events=None) -> list[Repository]:
    """Read bounded inventories. Opt-in tolerant callers must retain every issue.

    An explicit pinned repository remains mandatory, even in tolerant mode.
    This never fetches or repairs source repositories.
    """
    root = root.resolve()
    roots = repository_roots(root, max_directories) if roots is None else roots
    result = []
    for number, path in enumerate(sorted(roots), 1):
        key = path.relative_to(root).as_posix() if path != root else 'repo'
        validate_relative_path(key)
        ref = (pinned_heads or {}).get(key, 'HEAD')
        def emit(event, repository=key):
            if read_events:
                read_events({'repository': repository, **event})
        event_sink = emit if read_events else None
        stage = 'resolve_commit'
        if progress:
            progress({'repository': key, 'completed_repositories': number - 1,
                      'total_repositories': len(roots), 'stage': stage})
        try:
            head = read_git(path, 'rev-parse', '--verify', ref + '^{commit}', timeout=timeout,
                            stage=stage, progress=event_sink).stdout.strip()
            stage = 'read_tree'
            entries = read_git(path, 'ls-tree', '-r', '-z', head, timeout=timeout,
                               stage=stage, progress=event_sink).stdout.split('\0')
            files = {}
            for entry in filter(None, entries):
                meta, name = entry.split('\t', 1)
                try:
                    validate_relative_path(name)
                except ValueError:
                    continue
                files[name] = meta.split()[0]
            result.append(Repository(key, path, head, files, event_sink))
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            if issues is None:
                raise
            issues.append(repository_issue(key, stage, exc, path))
            if progress:
                progress({'repository': key, 'completed_repositories': number,
                          'total_repositories': len(roots), 'stage': stage, 'status': 'UNAVAILABLE'})
            if key in (pinned_heads or {}):
                raise ValueError(f'pinned target repository is unavailable: {key}') from exc
        if progress:
            progress({'repository': key, 'completed_repositories': number,
                      'total_repositories': len(roots), 'stage': 'inventory'})
    if set(pinned_heads or {}) - {r.key for r in result}:
        raise ValueError('pinned target repository was not discovered')
    return result


def diff_units(diff: str) -> list[dict]:
    if len(diff.encode()) > 4 * 1024 * 1024:
        raise ValueError('diff exceeds 4 MiB input limit')
    units = split_hunks(diff)
    if not units or len(units) > 256:
        raise ValueError('diff must contain 1 to 256 change units')
    for unit in units:
        for key in ('old_path', 'new_path'):
            if unit[key]:
                validate_relative_path(unit[key])
        before, after = {}, {}
        old = new = None
        for line in unit['patch'].splitlines():
            match = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
            if match:
                old, new = map(int, match.groups())
            elif old is not None and line.startswith((' ', '-', '+')):
                if line[0] in ' -':
                    before[old] = line[1:]
                    old += 1
                if line[0] in ' +':
                    after[new] = line[1:]
                    new += 1
        unit['before'], unit['after'] = before, after
    return units


def tokens(text: str) -> set[str]:
    return {x for x in TOKEN.findall(text) if x not in STOP and len(x) > 2}


def functions(content: str, suffix: str) -> list[dict]:
    if suffix == '.py':
        try:
            return [{'symbol': n.name, 'line_start': n.lineno, 'line_end': n.end_lineno,
                     'parser': 'python_ast'} for n in ast.walk(ast.parse(content))
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        except SyntaxError:
            return []
    if suffix not in {'.java', '.c', '.cc', '.cpp', '.h', '.hpp', '.kt'}:
        return []
    # Mask comments and strings without changing offsets or line numbers.
    masked = re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                    lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), content)
    brace_ends, stack = {}, []
    for pos, char in enumerate(masked):
        if char == '{':
            stack.append(pos)
        elif char == '}' and stack:
            brace_ends[stack.pop()] = pos
    found = []
    import bisect
    newlines = [i for i, ch in enumerate(content) if ch == '\n']
    for match in re.finditer(r'\b([\w$]+)\s*\([^;{}]*\)\s*(?:(?:throws|const|noexcept|override|final)\b[^;{}]*)?\{', masked):
        symbol = match.group(1)
        if symbol in STOP or symbol in {'synchronized', 'do'}:
            continue
        end = brace_ends.get(match.end() - 1)
        if end is not None:
            found.append({'symbol': symbol, 'line_start': bisect.bisect_left(newlines, match.start()) + 1,
                          'line_end': bisect.bisect_left(newlines, end) + 1, 'parser': 'lexical_hint'})
    return found


def _windows(content: str, unit: dict, defs: list[dict]) -> tuple[float, list[dict]]:
    lines = content.splitlines()
    before = list(unit['before'].values())
    after = list(unit['after'].values())
    terms = tokens('\n'.join(before + after) + unit['header'])
    anchors = {re.sub(r'\s+', '', s) for s in before + after if len(tokens(s)) >= 2}
    hits = []
    for i, line in enumerate(lines):
        shared = terms & tokens(line)
        score = len(shared) + (8 if re.sub(r'\s+', '', line) in anchors else 0)
        if score >= 2:
            hits.append((score, i))
    best = sorted(hits, reverse=True)[:30]
    ranges = []
    for score, i in best:
        if any(abs(i + 1 - r['anchor_line']) < 12 for r in ranges):
            continue
        enclosing = [d for d in defs if d['line_start'] <= i + 1 <= d['line_end']]
        definition = min(enclosing, key=lambda d: d['line_end'] - d['line_start']) if enclosing else None
        start, end = max(0, i - 10), min(len(lines), i + 15)
        ranges.append({'line_start': start + 1, 'line_end': end, 'anchor_line': i + 1,
                       'function': definition, 'excerpt': '\n'.join(lines[start:end]), 'anchor_score': score})
        if len(ranges) == 4:
            break
    unique_shared = set()
    for _, i in best:
        unique_shared.update(terms & tokens(lines[i]))
    coverage = len(unique_shared) / max(1, len(terms))
    return (max((h[0] for h in hits), default=0) + 10 * coverage), ranges


class Locator:
    def __init__(self, repos: list[Repository], units: list[dict], *, candidate_limit: int = 12,
                 scan_limit: int = 100):
        self.repos, self.units = repos, units
        self.candidate_limit, self.scan_limit = candidate_limit, scan_limit
        self.cache = {}
        self.definitions = {}
        self.search_cache = {}
        self.search_failures = {}
        self.read_failures = {}
        self.issues = []

    def read(self, repo: Repository, path: str) -> str:
        key = (repo.key, path)
        if key in self.read_failures:
            raise ValueError(self.read_failures[key])
        if key not in self.cache:
            try:
                self.cache[key] = repo.read(path)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                self.read_failures[key] = str(exc)[-1000:]
                raise
        return self.cache[key]

    def locate(self, progress=None) -> dict:
        output = []
        for unit in self.units:
            paths = {p for p in (unit['old_path'], unit['new_path']) if p}
            normalized_paths = {p for original in paths for p in version_normalized_paths(original)}
            names = {Path(p).name for p in paths}
            text = '\n'.join(unit['before'].values()) + '\n' + '\n'.join(unit['after'].values())
            terms = tokens(text + '\n' + unit['header'])
            title_terms = tokens(re.sub(r'^@@.*?@@', '', unit['header']))
            query = sorted(terms, key=lambda t: (t not in title_terms, -len(t), t))[:12]
            candidates = []
            search_log = []
            for repo in self.repos:
                scores: Counter = Counter()
                reasons = {}
                def add(path, score, reason):
                    if repo.files.get(path) in ('100644', '100755'):
                        scores[path] += score
                        reasons.setdefault(path, []).append(reason)
                for path in repo.files:
                    if path in paths or f'{repo.key}/{path}' in paths:
                        add(path, 8, 'exact_path')
                    elif path in normalized_paths or f'{repo.key}/{path}' in normalized_paths:
                        add(path, 7, 'version_normalized_path')
                    elif Path(path).name in names:
                        add(path, 5, 'basename')
                    elif any(p.endswith('/' + path) or path.endswith('/' + p) for p in paths):
                        add(path, 4, 'path_suffix')
                if query and unit['supported']:
                    try:
                        if repo.key in self.search_failures:
                            raise ValueError(self.search_failures[repo.key])
                        # Preserve evidence from rare stable APIs/fields even if the file and
                        # enclosing function both changed names. A single OR grep followed by
                        # alphabetical truncation loses those hits in large AOSP repositories.
                        for term in query:
                            search_key = (repo.key, term)
                            if search_key not in self.search_cache:
                                res = read_git(repo.root, 'grep', '--no-textconv', '-I', '-l', '-z', '-F', '-w',
                                               '-e', term, repo.head, '--', check=False,
                                               stage='identifier_search', progress=repo.read_events)
                                if res.returncode not in (0, 1):
                                    raise ValueError(res.stderr[-1000:])
                                self.search_cache[search_key] = [p.removeprefix(repo.head + ':') for p in res.stdout.split('\0') if p]
                            hits = self.search_cache[search_key]
                            search_log.append({'repository': repo.key, 'query': term, 'matching_files': len(hits),
                                               'status': 'MATCHES' if hits else 'NO_MATCH'})
                            weight = 6 / (1 + math.log1p(len(hits)))
                            for path in hits:
                                add(path, weight, 'identifier:' + term)
                    except (OSError, ValueError, subprocess.SubprocessError) as exc:
                        self.search_failures[repo.key] = str(exc)[-1200:]
                        self.issues.append({'unit': unit['id'], 'repository': repo.key, 'stage': 'identifier_search',
                                            'error': str(exc)[-1200:]})
                # Prefer path hints, then rare identifier-bearing filenames. Never call a truncated scan exhaustive.
                ranked = sorted(scores, key=lambda p: (-scores[p], -len(tokens(p) & terms), p))
                if len(ranked) > self.scan_limit:
                    self.issues.append({'unit': unit['id'], 'repository': repo.key, 'stage': 'candidate_scan',
                                        'status': 'TRUNCATED', 'total': len(ranked), 'scanned': self.scan_limit})
                for path in ranked[:self.scan_limit]:
                    try:
                        content = self.read(repo, path)
                        cache_key = (repo.key, path)
                        if cache_key not in self.definitions:
                            self.definitions[cache_key] = functions(content, Path(path).suffix)
                        defs = self.definitions[cache_key]
                        similarity, windows = _windows(content, unit, defs)
                        matching_defs = [d for d in defs if d['symbol'] in terms]
                        if not windows and not matching_defs and not any(r in ('exact_path', 'version_normalized_path', 'basename', 'path_suffix') for r in reasons[path]):
                            continue
                        candidates.append({'repository': repo.key, 'path': path, 'workspace_path': f'{repo.key}/{path}',
                                           'score': round(scores[path] + similarity + 4 * bool(matching_defs), 3),
                                           'signals': reasons[path], 'symbols': matching_defs[:12], 'windows': windows})
                    except (OSError, ValueError, subprocess.SubprocessError) as exc:
                        self.issues.append({'unit': unit['id'], 'path': f'{repo.key}/{path}', 'stage': 'read', 'error': str(exc)[-1000:]})
            candidates.sort(key=lambda c: (-c['score'], c['workspace_path']))
            kept = candidates[:self.candidate_limit]
            status = ('UNSUPPORTED' if not unit['supported'] else 'UNRESOLVED' if not kept else
                      'AMBIGUOUS_CANDIDATES' if len(kept) > 1 and kept[0]['score'] - kept[1]['score'] < 3
                      else 'CANDIDATES')
            output.append({'id': unit['id'], 'old_path': unit['old_path'], 'new_path': unit['new_path'],
                           'kind': unit['kind'], 'status': status, 'searches': search_log,
                           'candidate_count': len(candidates), 'candidates_truncated': len(candidates) > len(kept),
                           'candidates': kept, 'before': unit['before'], 'after': unit['after']})
            if progress:
                progress({'completed_units': len(output), 'total_units': len(self.units),
                          'last_unit': unit['id'], 'issues': len(self.issues)})
        return {'schema_version': 1, 'units': output, 'issues': self.issues,
                'impact': 'UNASSESSED', 'function_parser': 'python_ast_or_c_family_lexical_hints',
                'limits': {'files_per_repo_per_unit': self.scan_limit, 'candidates_per_unit': self.candidate_limit},
                'warning': 'Candidate ranking is retrieval only. Missing or truncated search is not evidence of absence.'}

    def history(self, report: dict) -> list[dict]:
        """Bounded local target history; unavailable history never becomes absence."""
        result, seen = [], set()
        by_key = {r.key: r for r in self.repos}
        for unit in report['units']:
            for c in unit['candidates'][:2]:
                key = (c['repository'], c['path'])
                if key in seen:
                    continue
                seen.add(key)
                repo = by_key[key[0]]
                try:
                    res = local_git(repo.root, 'log', '--no-ext-diff', '--no-textconv', '--follow', '-n', '12',
                                    '--format=%H %s', '--name-status', repo.head, '--', key[1], timeout=10)
                    shallow = local_git(repo.root, 'rev-parse', '--is-shallow-repository').stdout.strip()
                    result.append({'repository': key[0], 'path': key[1], 'status': 'LOCAL_TARGET_HISTORY',
                                   'shallow': shallow == 'true', 'output': res.stdout[:6000],
                                   'truncated': len(res.stdout) > 6000, 'limit': 12})
                except subprocess.SubprocessError as exc:
                    result.append({'repository': key[0], 'path': key[1], 'status': 'UNAVAILABLE', 'error': str(exc)[-800:]})
        return result
