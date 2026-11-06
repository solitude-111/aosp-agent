"""Typed model tools executed by the controller before-budget admission.

No arbitrary program, shell or Git argv is accepted. Repository identities come
from controller-owned run metadata; filesystem edits name exact candidate files.
The SDK reader invokes this synchronous handler, so budgets/cancellation are
explicit objects rather than relying on the reader thread's ContextVars.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

from jsonschema import validate, ValidationError
from . import agent_tools
from .retrieval import ReadBudget, BudgetExceeded
from .tool_io import ACTIVE_TOOL_IO, ToolIO


MAX_FILE = 32 * 1024 * 1024
MAX_REPLY = 64 * 1024


def spec(name, description, properties, required):
    return {'type': 'function', 'name': name, 'description': description,
            'inputSchema': {'type': 'object', 'properties': properties,
                            'required': required, 'additionalProperties': False}}


STRING = {'type': 'string', 'maxLength': MAX_FILE}
PATH = {'type': 'string', 'minLength': 1, 'maxLength': 4096}
INDEX = {'type': 'integer', 'minimum': 1, 'maximum': 10000000}
TOOLS = [
    spec('aosp_read_file', 'Read metadata or candidate text, with complete-file SHA256. '
         'Target/donor source evidence must use aosp_source at a pinned commit.',
         {'path': PATH, 'start': INDEX, 'end': INDEX}, ['path', 'start', 'end']),
    spec('aosp_list_files', 'List one metadata/candidate directory without recursion; symlinks are not followed.',
         {'path': PATH}, ['path']),
    spec('aosp_write_file', 'Create, replace or delete one authorized candidate file. '
         'expected_sha256 must match a prior read, or ABSENT for creation. Read-only turns cannot edit.',
         {'path': PATH, 'expected_sha256': PATH, 'content': STRING,
          'operation': {'enum': ['write', 'delete']}}, ['path', 'expected_sha256', 'content', 'operation']),
    spec('aosp_replace_text', 'Replace one exact, unique text block in an authorized candidate file. '
         'Supply the SHA256 from a prior read; repeated or missing matches are rejected.',
         {'path': PATH, 'expected_sha256': PATH, 'old': STRING, 'new': STRING},
         ['path', 'expected_sha256', 'old', 'new']),
    spec('aosp_source', 'Bounded pinned Git source operations. Select target:<project>, donor:<source-step>, '
         'target, donor or dependency:<key> from run metadata. view/locate/search/paths need repo and ref. '
         'history needs hunk_id (and target_repo in multi-project runs); show needs sha and optional '
         'source_step/hunk_id/target_repo. No network, arbitrary refs or Git argv.',
         {'operation': {'enum': ['view', 'locate', 'search', 'paths', 'history', 'show']},
          'repo': PATH, 'ref': PATH, 'path': {'type': 'string', 'maxLength': 4096},
          'start': INDEX, 'end': INDEX, 'symbol': PATH,
          'query': {'type': 'string', 'minLength': 1, 'maxLength': 256},
          'hunk_id': PATH, 'sha': PATH, 'target_repo': PATH, 'source_step': PATH}, ['operation']),
]


class ToolDenied(ValueError):
    pass


def _permitted(path, grants, denied):
    allowed = max((len(Path(p).parts) for p in grants if path.is_relative_to(p)), default=-1)
    blocked = max((len(Path(p).parts) for p in denied if path.is_relative_to(p)), default=-1)
    return allowed > blocked


class ToolBroker:
    def __init__(self, scope, events, *, seconds=900, budget=None):
        self.scope, self.log = scope, events
        self.fallback = budget or ReadBudget(seconds=seconds)
        self.schemas = {t['name']: t['inputSchema'] for t in TOOLS}
        self.lock = threading.RLock()
        self.idle = threading.Event(); self.idle.set()
        self.cancelled = threading.Event()
        self.active = False; self.failure = None
        self.seen = set(); self.retired_turns = set(); self.snapshot = None; self.history = {}

    @property
    def tools(self):
        return copy.deepcopy(TOOLS)

    def instructions(self):
        return ('\nController tool policy: native shell, arbitrary commands and apply_patch are unavailable. '
                'Use aosp_source for fixed-revision reads/search/history (wrapper names in older prompts '
                'map to its view/locate/history/show operations). Use aosp_read_file/aosp_list_files '
                'for metadata and candidate files, aosp_replace_text or aosp_write_file for authorized edits. '
                'Do not execute scripts or validation: the controller runs checks. Limits and read failures '
                'are not absence evidence. Never repair run metadata or bypass a tool denial.\n'
                + json.dumps({'file_read_roots': self.scope.tool_readable, 'candidate_edit_files': self.scope.writable,
                              'source_context': self.scope.tool_context,
                              'explicit_target_repositories': self.scope.tool_repositories}, ensure_ascii=False))

    def begin(self, thread_id, cwd, read_only, timeout, budget=None):
        with self.lock:
            if self.active or not self.idle.is_set():
                raise RuntimeError('previous model tool call has not drained')
            self.active = True; self.cancelled.clear(); self.failure = None
            self.thread_id, self.turn_id, self.cwd, self.read_only = thread_id, None, Path(cwd), read_only
            self.budget = budget or self.fallback
            self.io = ToolIO(self.budget, self.cancelled, time.monotonic() + min(timeout, self.budget.remaining()), MAX_FILE)

    def bind_turn(self, ident):
        with self.lock:
            if self.turn_id is not None and self.turn_id != ident:
                raise RuntimeError('model tool call belongs to a different turn')
            self.turn_id = ident

    def end(self):
        self.cancelled.set()
        with self.lock:
            if self.active and self.turn_id is not None:
                self.retired_turns.add(self.turn_id)
            self.active = False
        if not self.idle.wait(5):
            raise RuntimeError('controller tool callback did not drain')

    def handle(self, method, params):
        if method != 'item/tool/call':
            # Never inherit the SDK's default approval acceptance.
            return {'decision': 'decline'}
        params = params or {}; name = params.get('tool'); ident = params.get('callId')
        with self.lock:
            if (not self.active or params.get('threadId') != self.thread_id
                    or not isinstance(ident, str) or ident in self.seen or not self.idle.is_set()
                    or not isinstance(params.get('turnId'), str)
                    or params.get('turnId') in self.retired_turns
                    or (self.turn_id is not None and params['turnId'] != self.turn_id)):
                return self._reply(False, {'error': 'inactive, duplicate, concurrent or foreign tool request'})
            self.turn_id = params['turnId']; self.seen.add(ident); self.idle.clear()
        success = False
        try:
            self.io.check()
            self.budget.command_timeout(120)  # Before any tool-owned filesystem access.
            if name not in self.schemas or params.get('namespace') not in (None, ''):
                raise ToolDenied('unknown controller tool')
            args = params.get('arguments')
            validate(args, self.schemas[name])
            # Count input before a model-controlled large string is processed.
            self.budget.claim_bytes(len(json.dumps(args, ensure_ascii=False).encode()))
            # Reserve the entire possible result before reads or edits. Error
            # control messages remain small even after the data budget ends.
            self.budget.claim_bytes(MAX_REPLY)
            token = ACTIVE_TOOL_IO.set(self.io)
            try:
                with self.budget.active():
                    result = self._dispatch(name, args)
            finally:
                ACTIVE_TOOL_IO.reset(token)
            self.io.check()
            success = not result.get('returncode', 0)
            reply = self._reply(success, result)
            success = reply['success']
            return reply
        except BudgetExceeded as exc:
            self.failure = exc
            return self._reply(False, {'error': str(exc), 'status': 'BUDGET_EXHAUSTED'})
        except (ToolDenied, ValidationError, ValueError, OSError, agent_tools.ToolError) as exc:
            return self._reply(False, {'error': str(exc)[:2000], 'status': 'TOOL_DENIED_OR_READ_FAILED'})
        except Exception as exc:
            # Unexpected subprocess/parser failures do not provide partial source evidence.
            return self._reply(False, {'error': type(exc).__name__ + ': ' + str(exc)[:1000], 'status': 'READ_FAILED'})
        finally:
            try:
                self.log('broker_tool', tool=name, call_id=ident, success=success, budget=self.budget.data())
            finally:
                self.idle.set()

    @staticmethod
    def _reply(success, result):
        text = json.dumps(result, ensure_ascii=False)
        if len(text.encode()) > MAX_REPLY:
            # Never return a syntactically truncated success object.
            success = False
            text = json.dumps({'status': 'OUTPUT_LIMIT', 'error': 'Use a smaller range or narrower path.'})
        return {'success': success, 'contentItems': [{'type': 'inputText', 'text': text}]}

    def _path(self, raw, *, write=False):
        path = Path(raw)
        path = Path(os.path.abspath(path if path.is_absolute() else self.cwd / path))
        if any(p in ('.git', '.repo') for p in path.parts):
            raise ToolDenied('Git metadata is available only through pinned source tools')
        if not _permitted(path, self.scope.tool_readable, self.scope.denied):
            raise ToolDenied('file path is outside model metadata/candidate scope')
        if write and (self.read_only or str(path) not in self.scope.writable):
            raise ToolDenied('this phase cannot modify that exact candidate file')
        return path

    def _parent(self, path, *, create=False):
        """Traverse using directory FDs and O_NOFOLLOW, including ancestors."""
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                self.io.check()
                if create:
                    try: os.mkdir(part, dir_fd=fd)
                    except FileExistsError: pass
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nxt
            return fd
        except BaseException:
            os.close(fd); raise

    def _read(self, path, *, missing=False):
        self.io.check()
        try:
            parent = self._parent(path)
        except FileNotFoundError:
            if missing: return None
            raise
        try:
            try: fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                if missing: return None
                raise
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                    raise ToolDenied('file is not regular or exceeds the per-file read limit')
                self.budget.claim_bytes(info.st_size + 1)
                data = stream.read(info.st_size + 1)
                if len(data) != info.st_size:
                    raise ToolDenied('file size changed during read')
                self.io.check()
                return data
        finally:
            os.close(parent)

    def _edit(self, args, *, replace=False):
        path = self._path(args['path'], write=True)
        current = self._read(path, missing=True)
        digest = hashlib.sha256(current).hexdigest() if current is not None else 'ABSENT'
        if args['expected_sha256'] != digest:
            raise ToolDenied('candidate changed; read it again before editing')
        delete = not replace and args['operation'] == 'delete'
        if replace:
            if current is None or not args['old']:
                raise ToolDenied('replacement needs an existing file and nonempty old text')
            old = current.decode('utf-8')
            if old.count(args['old']) != 1:
                raise ToolDenied('old text must match exactly once')
            content = old.replace(args['old'], args['new'], 1).encode()
        else:
            content = args['content'].encode()
        if len(content) > MAX_FILE:
            raise ToolDenied('candidate exceeds the per-file write limit')
        self.budget.claim_bytes(len(content))
        self.io.check()
        parent = self._parent(path, create=not delete)
        temporary = '.aosp-broker-' + uuid.uuid4().hex
        try:
            # Recheck identity after obtaining the destination parent. Only
            # broker writes run in this phase; external changes are rejected.
            if self._read(path, missing=True) != current:
                raise ToolDenied('candidate changed during edit preparation')
            if delete:
                if current is None: raise ToolDenied('cannot delete an absent file')
                self.io.check(); os.unlink(path.name, dir_fd=parent)
            else:
                mode = (os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_mode & 0o777) if current is not None else 0o644
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
                with os.fdopen(fd, 'wb') as stream:
                    os.fchmod(stream.fileno(), mode)
                    stream.write(content); stream.flush()
                self.io.check()
                os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
            return {'path': str(path), 'sha256': 'ABSENT' if delete else hashlib.sha256(content).hexdigest()}
        finally:
            try: os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError: pass
            os.close(parent)

    def _context(self):
        if self.snapshot is None:
            if self.scope.tool_repositories is not None:
                record = {'tool_target_repositories': copy.deepcopy(self.scope.tool_repositories)}
                inspection = {'hunks': []}
            elif self.scope.tool_context:
                root = Path(self.scope.tool_context)
                record = json.loads(self._read(self._path(str(root / 'run.json'))))
                inspection = json.loads(self._read(self._path(str(root / 'inspection.json'))))
            else:
                raise ToolDenied('this phase has no admitted source repositories')
            self.snapshot = (record, inspection)
        record, inspection = copy.deepcopy(self.snapshot)
        output = []
        def sink(text, entry):
            output.append({'text': text, 'usage': entry})
            self.log('broker_source_usage', **entry)
        ctx = agent_tools.RunContext(Path(self.scope.tool_context or self.cwd), record=record, inspection=inspection,
                                     output_sink=sink)
        ctx.history_shas = lambda: self.history.get(ctx.donor_git, set())
        ctx.record_history_shas = lambda shas, hunk: self.history.setdefault(ctx.donor_git, set()).update(shas[:20])
        return ctx, output

    def _check_repo(self, root):
        path = Path(root).resolve()
        if not _permitted(path, self.scope.readable, self.scope.denied):
            raise ToolDenied('repository is outside admitted read scope')

    def _source(self, args):
        ctx, output = self._context()
        operation = args['operation']
        values = {k: args.get(k) for k in ('repo', 'ref', 'path', 'symbol', 'hunk_id', 'sha', 'target_repo', 'source_step')}
        values.update(start=args.get('start', 1), end=args.get('end', 200), language=None)
        options = argparse.Namespace(**values)
        if operation in ('history', 'show'):
            ctx.bind_history_target(args.get('target_repo'))
            ctx.bind_source(args.get('source_step'), args.get('hunk_id'))
            if not ctx.donor_git: raise ToolDenied('NOT_AVAILABLE: no donor Git history supplied')
            self._check_repo(ctx.donor_git)
            if ctx.worktree is not None: self._check_repo(ctx.worktree)
            if operation == 'history' and not args.get('hunk_id'): raise ToolDenied('history needs hunk_id')
            if operation == 'show' and not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', args.get('sha', '')):
                raise ToolDenied('show requires a complete source commit ID')
        else:
            repo, ref = args.get('repo', ''), args.get('ref', '')
            if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', ref):
                raise ToolDenied('source reads require a complete pinned commit ID')
            if repo == 'target' and not ctx.target_repositories and ref != ctx.record.get('target_commit'):
                raise ToolDenied('target reads must use the pinned target commit')
            if repo == 'donor' and ref not in {ctx.record.get('source_parent'), ctx.record.get('source_commit')} | ctx.history_shas():
                raise ToolDenied('donor read ref was not supplied or observed in bounded history')
            ctx.check_ref(ref, repo)
            repo_args, cwd = ctx.repo_selection(repo)
            self._check_repo(cwd if cwd is not None else repo_args[1])
            if operation in ('search', 'paths'):
                path = args.get('path') or ''
                if path: agent_tools.validate_relative_path(path)
                if operation == 'search':
                    if not args.get('query'): raise ToolDenied('search needs a nonempty literal query')
                    command = ['grep', '-n', '-I', '-F', '-e', args['query'], ref, '--']
                else:
                    command = ['ls-tree', '-r', '--name-only', ref, '--']
                if path: command.append(':(literal)' + path)
                result = agent_tools._git(repo_args, *command, cwd=cwd, check=False)
                if result.returncode not in ((0, 1) if operation == 'search' else (0,)):
                    raise ToolDenied('READ_FAILED: ' + result.stderr[-1000:])
                return {'status': 'NOT_FOUND_IN_SCOPE' if result.returncode == 1 else 'FOUND',
                        'repo': repo, 'ref': ref, 'path_scope': path or 'admitted project',
                        'text': result.stdout[:12000], 'truncated': len(result.stdout) > 12000,
                        'absence_proven': False}
        handler = {'view': agent_tools.cmd_view_code, 'locate': agent_tools.cmd_locate_symbol,
                   'history': agent_tools.cmd_hunk_history, 'show': agent_tools.cmd_show_commit}.get(operation)
        if handler is None: raise ToolDenied('unknown source operation')
        if operation == 'view' and not args.get('path'): raise ToolDenied('view needs path')
        if operation == 'locate' and not args.get('symbol'): raise ToolDenied('locate needs symbol')
        code = handler(ctx, options)
        return {'returncode': code, 'results': output}

    def _dispatch(self, name, args):
        if name == 'aosp_source': return self._source(args)
        if name == 'aosp_write_file': return self._edit(args)
        if name == 'aosp_replace_text': return self._edit(args, replace=True)
        path = self._path(args['path'])
        if name == 'aosp_read_file':
            data = self._read(path)
            lines = data.decode('utf-8').splitlines()
            start, end = args['start'], min(args['end'], args['start'] + 399)
            if end < start: raise ToolDenied('line range must be ascending')
            text = '\n'.join(lines[start - 1:end])
            return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'start': start,
                    'end': min(end, len(lines)), 'total_lines': len(lines), 'text': text[:12000],
                    'truncated': len(text) > 12000 or args['end'] > end}
        parent = self._parent(path / 'unused')
        try:
            items = []
            with os.scandir(parent) as entries:
                for item in entries:
                    self.io.check()
                    self.budget.claim_bytes(len(item.name.encode()) + 128)
                    items.append({'name': item.name, 'symlink': item.is_symlink(), 'directory': item.is_dir(follow_symlinks=False)})
                    if len(items) >= 200: break
            return {'path': str(path), 'entries': items, 'possibly_truncated': len(items) == 200}
        finally:
            os.close(parent)
