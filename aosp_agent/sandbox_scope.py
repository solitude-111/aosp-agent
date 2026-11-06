"""Explicit filesystem scopes for model tools, independent of prompt wording.

The controller still grounds evidence at pinned commits. Filesystem permission
profiles bound native reads; they are not Git revision authorization or a
pre-execution tool budget. External tool surfaces are disabled separately.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile


class ScopeUnavailable(RuntimeError):
    kind = 'MODEL_SCOPE_UNAVAILABLE'


SHELL_ENV = {'PATH': '/usr/bin:/bin', 'GIT_ALLOW_PROTOCOL': '', 'GIT_NO_LAZY_FETCH': '1',
             'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
             'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}


def _paths(values):
    result = tuple(sorted({str(candidate) for p in values
                           for candidate in (Path(os.path.abspath(p)), Path(p).resolve())}))
    if any(Path(p).parent == Path(p) for p in result):
        raise ScopeUnavailable('filesystem root cannot be granted to model tools')
    return result


@dataclass(frozen=True)
class ModelScope:
    readable: tuple[str, ...]
    writable: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    tool_readable: tuple[str, ...] | None = None
    tool_context: str | None = None
    tool_repositories: dict | None = None

    def __post_init__(self):
        for key in ('readable', 'writable', 'denied'):
            object.__setattr__(self, key, _paths(getattr(self, key)))
        if not self.readable:
            raise ScopeUnavailable('model scope needs an explicit readable surface')
        object.__setattr__(self, 'tool_readable', _paths(self.readable if self.tool_readable is None else self.tool_readable))
        if self.tool_context is not None:
            object.__setattr__(self, 'tool_context', str(Path(self.tool_context).resolve()))
        for path in self.writable:
            if not any(Path(path).is_relative_to(root) for root in self.readable):
                raise ScopeUnavailable('model write path must belong to its readable scope')
            if any(Path(path).is_relative_to(root) for root in self.denied):
                raise ScopeUnavailable('model write path overlaps a denied tree')

    def data(self):
        return {'readable': list(self.readable), 'writable': list(self.writable), 'denied': list(self.denied),
                'tool_readable': list(self.tool_readable), 'tool_context': self.tool_context,
                'tool_repositories': self.tool_repositories}

    def profile(self, read_only=True):
        digest = hashlib.sha256(json.dumps(self.data(), sort_keys=True).encode()).hexdigest()[:20]
        return 'aosp_' + digest + ('_read' if read_only else '_edit')

    def filesystem(self, read_only=True):
        result = {':root': 'deny', ':minimal': 'read'}
        result.update({p: 'read' for p in self.readable})
        if not read_only:
            result.update({p: 'write' for p in self.writable})
        result.update({p: 'deny' for p in self.denied})
        return result

    def config_overrides(self):
        # These overrides belong only to this SDK subprocess. Do not change
        # the operator's config/auth files or silently inherit connected tools.
        settings = {
            # A custom profile table requires an explicit default even before
            # thread/start selects its profile. Never inherit a broader default.
            'default_permissions': self.profile(True),
            'mcp_servers': {}, 'web_search': 'disabled', 'project_doc_max_bytes': 0,
            'shell_environment_policy.inherit': 'none',
            'shell_environment_policy.set': SHELL_ENV,
            'features.shell_tool': False,
        }
        for feature in ('apps', 'plugins', 'browser_use', 'browser_use_external',
                        'browser_use_full_cdp_access', 'computer_use', 'in_app_browser',
                        'image_generation', 'view_image', 'multi_agent', 'multi_agent_v2',
                        'skill_mcp_dependency_install', 'skill_search', 'shell_snapshot',
                        'shell_snapshot_v2', 'request_permissions_tool', 'hooks', 'memories',
                        'external_agent_memory_import', 'code_mode', 'code_mode_host',
                        'code_mode_only', 'code_mode_prewarm'):
            settings['features.' + feature] = False
        settings['features.skip_host_skill_discovery'] = True
        for read_only in (True, False):
            prefix = 'permissions.' + self.profile(read_only)
            settings[prefix + '.filesystem'] = self.filesystem(read_only)
            settings[prefix + '.network.enabled'] = False
        return tuple(k + '=' + _toml(v) for k, v in settings.items())


def _toml(value):
    if isinstance(value, dict):
        return '{' + ', '.join(json.dumps(str(k)) + '=' + _toml(v) for k, v in value.items()) + '}'
    return json.dumps(value, ensure_ascii=False)


def git_read_roots(repositories):
    """Include only admitted repos' Git metadata and local object alternates.

    AOSP's .git file commonly points outside its checkout. Granting the whole
    .repo directory would reopen every project, so resolve concrete stores.
    """
    from .discovery import local_git
    roots = set()
    pending = []
    for value in set(map(str, repositories)):
        root = Path(value).resolve()
        roots.add(root)
        git_dir = Path(local_git(root, 'rev-parse', '--absolute-git-dir').stdout.strip()).resolve()
        common = Path(local_git(root, 'rev-parse', '--git-common-dir').stdout.strip())
        common = (root / common).resolve() if not common.is_absolute() else common.resolve()
        roots.update((git_dir, common)); pending.append((common / 'objects', 0))
    seen = set()
    while pending:
        objects, depth = pending.pop()
        objects = objects.resolve()
        if objects in seen:
            continue
        if depth > 8 or len(seen) >= 64:
            raise ScopeUnavailable('Git object alternate scope exceeds its bound')
        seen.add(objects)
        alternate = objects / 'info/alternates'
        if alternate.exists():
            if alternate.stat().st_size > 65536:
                raise ScopeUnavailable('Git object alternate metadata is too large')
            for entry in alternate.read_text().splitlines():
                if not entry:
                    continue
                path = Path(entry)
                path = (objects / path).resolve() if not path.is_absolute() else path.resolve()
                if not path.is_dir():
                    raise ScopeUnavailable('Git object alternate is unavailable')
                roots.add(path); pending.append((path, depth + 1))
    return roots


def source_scope(run_dir, repositories=(), *, writable=(), extra_readable=(), denied=(), tool_repositories=None):
    # Controlled Python wrappers stage their stdlib-only code inside run_dir.
    # They use the real interpreter, so neither its virtualenv aliases nor the
    # project parent, installed third-party packages or tests need a read grant.
    reads = {Path(run_dir), Path(sys.base_prefix),
             Path(sys.executable).resolve(), *map(Path, extra_readable)}
    git_binary = shutil.which('git')
    if not git_binary:
        raise ScopeUnavailable('Git executable is unavailable')
    git_binary = Path(git_binary).resolve()
    reads.add(git_binary)
    if sys.platform == 'darwin':
        stat = git_binary.stat()
        reads.update(Path(p) for p in _macos_libraries(str(git_binary), stat.st_size, stat.st_mtime_ns))
    reads.update(git_read_roots(repositories))
    return ModelScope(tuple(map(str, reads)), tuple(map(str, writable)), tuple(map(str, denied)),
                      tool_readable=(str(run_dir),),
                      tool_context=str(run_dir) if Path(run_dir).is_dir() else None,
                      tool_repositories=tool_repositories)


@lru_cache(maxsize=4)
def _macos_libraries(binary, size, modified):
    # Homebrew Git may depend on libraries outside :minimal. Ask the loader
    # about this trusted executable's --version invocation; do not grant all of
    # Homebrew or require/install Xcode merely to read Git objects.
    result = subprocess.run([binary, '--version'], capture_output=True, text=True,
                            env={**os.environ, 'DYLD_PRINT_LIBRARIES': '1'}, timeout=10)
    if result.returncode:
        raise ScopeUnavailable('cannot identify Git runtime library scope')
    paths = set()
    for value in re.findall(r'^dyld\[\d+\]: .*? (/[^\n]+)$', result.stderr, re.MULTILINE):
        path = Path(value)
        if value.startswith(('/System/', '/usr/lib/')):
            continue  # Already covered by :minimal, including shared-cache paths.
        paths.add(value)
    return tuple(sorted(paths))


def git_library_path(binary):
    """Give controlled Git its verified canonical dylib search directories.

    Exact file grants do not authorize dyld's traversal of Homebrew opt aliases.
    Selecting canonical directories avoids that traversal without granting the
    aliases' package trees. Only the actual loaded files receive read grants.
    """
    if sys.platform != 'darwin':
        return ''
    binary = Path(binary).resolve()
    stat = binary.stat()
    return ':'.join(sorted({str(Path(p).parent) for p in
        _macos_libraries(str(binary), stat.st_size, stat.st_mtime_ns) if p.endswith('.dylib')}))


def require_profile_protocol(codex_path=None):
    if codex_path:
        binary = Path(codex_path).resolve(strict=True)
    else:
        from codex_cli_bin import bundled_codex_path
        binary = Path(bundled_codex_path()).resolve(strict=True)
    stat = binary.stat()
    _check_protocol(str(binary), stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=4)
def _check_protocol(binary, size, modified):
    # The SDK's typed schema omits the CLI's permissions selector. Verify the
    # actual executable before using the pinned protocol adapter. Fail closed.
    with tempfile.TemporaryDirectory(prefix='aosp-protocol-') as raw:
        result = subprocess.run([binary, 'app-server', 'generate-json-schema', '--experimental', '--out', raw],
                                capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise ScopeUnavailable('cannot verify runtime permission profile protocol')
        for name, field in (('ThreadStartParams', 'permissions'), ('TurnStartParams', 'permissions'),
                            ('ThreadStartParams', 'dynamicTools'), ('DynamicToolCallParams', 'callId'),
                            ('DynamicToolCallResponse', 'contentItems'),
                            ('ThreadStartResponse', 'activePermissionProfile'),
                            ('ThreadBackgroundTerminalsCleanParams', 'threadId')):
            try:
                path = Path(raw) / 'v2' / (name + '.json')
                if not path.exists(): path = Path(raw) / (name + '.json')
                props = json.loads(path.read_text())['properties']
                if field not in props:
                    raise KeyError(field)
            except (OSError, ValueError, KeyError) as exc:
                raise ScopeUnavailable('runtime lacks required permission profile contract: ' + name) from exc


async def start_scoped_thread(codex, scope, *, cwd, instructions, model=None, model_provider=None, dynamic_tools=None):
    from pydantic import RootModel
    from openai_codex.api import AsyncThread
    class Reply(RootModel[dict]):
        pass
    # Empty tables merge with user config; they do not remove existing MCP
    # servers. Resolve names only, then explicitly disable every configured
    # server before a thread can connect or expose an unsandboxed read tool.
    effective = (await codex._client.request('config/read', {'cwd': str(cwd), 'includeLayers': False},
                                             response_model=Reply)).root.get('config', {})
    servers = effective.get('mcp_servers', {})
    if not isinstance(servers, dict):
        raise ScopeUnavailable('cannot enumerate external tool servers for this scope')
    disabled_servers = {}
    for name, settings in servers.items():
        transport = {k: settings[k] for k in ('command', 'url') if isinstance(settings.get(k), str)}
        if not transport:
            raise ScopeUnavailable('cannot disable an unrecognized external tool transport')
        disabled_servers[name] = {**transport, 'enabled': False}
    configured_env = effective.get('shell_environment_policy', {}).get('set', {}) or {}
    if not isinstance(configured_env, dict):
        raise ScopeUnavailable('cannot isolate configured shell environment')
    params = {'cwd': str(cwd), 'baseInstructions': instructions, 'approvalPolicy': 'never',
              'ephemeral': True, 'permissions': scope.profile(True),
              'config': {'mcp_servers': disabled_servers,
                         'shell_environment_policy': {'inherit': 'none',
                             'set': {**{k: '' for k in configured_env}, **SHELL_ENV}}}}
    if model: params['model'] = model
    if dynamic_tools is not None: params['dynamicTools'] = dynamic_tools
    if model_provider: params['modelProvider'] = model_provider
    reply = (await codex._client.request('thread/start', params, response_model=Reply)).root
    if (reply.get('activePermissionProfile') or {}).get('id') != scope.profile(True):
        raise ScopeUnavailable('runtime did not activate the requested read scope')
    return AsyncThread(codex, reply['thread']['id'])


async def clean_background_terminals(codex, thread):
    from pydantic import RootModel
    class Reply(RootModel[dict]):
        pass
    await codex._client.request('thread/backgroundTerminals/clean',
                               {'threadId': thread.id}, response_model=Reply)


async def scoped_turn(codex, thread, scope, prompt, *, cwd, read_only, output_schema, model=None, effort=None):
    from openai_codex.api import AsyncTurnHandle
    if not read_only and not scope.writable:
        raise ScopeUnavailable('this model phase has no authorized write paths')
    params = {'threadId': thread.id, 'input': [{'type': 'text', 'text': prompt}],
              'cwd': str(cwd), 'approvalPolicy': 'never', 'permissions': scope.profile(read_only)}
    if output_schema is not None: params['outputSchema'] = output_schema
    if model: params['model'] = model
    if effort: params['effort'] = effort
    # Mirror the SDK handle's subscription-before-start semantics to avoid lost
    # early notifications. Preserve SDK cancellation cleanup and interruption.
    turn, subscription = await codex._client._start_turn(thread.id, params['input'], params, for_handle=True)
    return AsyncTurnHandle(codex, thread.id, turn.turn.id, _subscription=subscription)
