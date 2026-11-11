"""Offline catalogue and first-registration audit for externally sealed bases.

This module does not provision images, enable verity, mount filesystems, fetch
objects or change checkouts. The catalogue is written outside the checkout; an
operator must include those exact bytes in their separately prepared image.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

from .case import validate_relative_path
from .git_policy import offline_git_env
from .project_catalog import parse_manifest
from .runtime_input import revision_name
from .server_config import safe_origin
from .source_base import SourceBaseBlocked, register_source_base


MAX_JSON = 16 * 1024**2
OID = re.compile(r'[0-9a-f]{40}(?:[0-9a-f]{24})?\Z')


def require(condition, message):
    if not condition:
        raise SourceBaseBlocked(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def read_bytes(path, limit=MAX_JSON):
    path = Path(path)
    require(path.is_file() and path.stat().st_size <= limit, 'audit input missing or oversized: ' + str(path))
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, 'audit input grew past its limit')
    return data


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(read_bytes(path), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


class GitAudit:
    """Bound both pipes while running local read-only Git with no lazy fetch."""
    def __init__(self, *, command_timeout=60, timeout=7200, max_output_bytes=64 * 1024**2,
                 max_total_output_bytes=1024**3, max_operations=50000):
        for value in (command_timeout, timeout, max_output_bytes, max_total_output_bytes, max_operations):
            require(isinstance(value, (int, float)) and not isinstance(value, bool)
                    and math.isfinite(value) and value > 0, 'audit limits must be finite and positive')
        self.command_timeout, self.deadline = command_timeout, time.monotonic() + timeout
        self.max_output_bytes, self.max_total_output_bytes = max_output_bytes, max_total_output_bytes
        self.max_operations = max_operations
        self.operations, self.output_bytes = 0, 0
        self.started = time.monotonic()

    def run(self, repo, *args, check=True):
        require(self.operations < self.max_operations, 'audit Git operation limit exhausted')
        remaining = min(self.command_timeout, self.deadline - time.monotonic())
        require(remaining > 0, 'audit time limit exhausted')
        self.operations += 1
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env = offline_git_env(dict(env, GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1',
                                  GIT_CONFIG_GLOBAL='/dev/null', LC_ALL='C'))
        argv = ['git', '-c', 'protocol.allow=never', '-c', 'core.fsmonitor=false',
                '-c', 'core.hooksPath=/dev/null', '-c', 'gc.auto=0', '-C', str(repo), *args]
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        deadline = time.monotonic() + remaining
        output, errors, size = bytearray(), bytearray(), 0
        selector = selectors.DefaultSelector()
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'audit Git command timed out')
                for key, _ in selector.select(min(.1, remaining)):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj); continue
                    size += len(block); self.output_bytes += len(block)
                    require(size <= self.max_output_bytes and self.output_bytes <= self.max_total_output_bytes,
                            'audit Git output limit exhausted')
                    (output if key.fileobj is process.stdout else errors).extend(block)
            process.wait(timeout=max(.001, deadline - time.monotonic()))
            require(not check or process.returncode == 0,
                    'offline Git audit failed (' + args[0] + '): ' + errors.decode(errors='replace')[-1000:])
            return subprocess.CompletedProcess(argv, process.returncode,
                output.decode('utf-8', errors='strict'), errors.decode('utf-8', errors='replace'))
        except subprocess.TimeoutExpired as exc:
            raise SourceBaseBlocked('audit Git command timed out') from exc
        finally:
            try:
                if process.poll() is None:
                    # Let a command that already filled its pipe finish before
                    # signalling; the cleanup grace is fixed, never renewed.
                    try:
                        process.wait(timeout=.1)
                    except subprocess.TimeoutExpired:
                        pass
                if process.poll() is None or selector.get_map():
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError as exc:
                        # A very short Git can exit between poll and killpg on
                        # macOS. An actually live unkillable command blocks.
                        if process.poll() is None:
                            raise SourceBaseBlocked('audit Git cleanup could not be verified') from exc
                process.wait(timeout=5)
            finally:
                selector.close(); process.stdout.close(); process.stderr.close()

    def check_time(self):
        require(time.monotonic() < self.deadline, 'audit time limit exhausted')

    def usage(self):
        return {'git_operations': self.operations, 'git_output_bytes': self.output_bytes,
                'seconds': time.monotonic() - self.started}


def contained(root, path):
    resolved = Path(path).resolve(strict=True)
    require(resolved != root and resolved.is_relative_to(root), 'Git/source path escapes the declared root: ' + str(path))
    return resolved


def portable_link(root, path):
    """An absolute internal pointer would still point at the old mount later."""
    for component in (path, *path.parents):
        if component == root: break
        if component.is_symlink():
            require(not os.path.isabs(os.readlink(component)), 'absolute metadata symlink is not relocatable: ' + str(component))
    return contained(root, path)


def metadata(root, repo, git):
    marker = repo / '.git'
    if marker.is_file() and not marker.is_symlink():
        text = read_bytes(marker, 65536).decode().strip()
        require(text.startswith('gitdir: ') and not os.path.isabs(text[8:]), 'gitdir pointer must be relative inside the source root')
    portable_link(root, marker)
    # Do not follow includes even to inspect their contents. Reject this first
    # version's unsupported configuration dependency graph from actual origins.
    config = git.run(repo, 'config', '--no-includes', '--null', '--show-origin',
                     '--name-only', '--list').stdout.split('\0')
    require(config[-1] == '' and (len(config) - 1) % 2 == 0, 'Git config origin output is malformed')
    for origin, key in zip(config[:-1:2], config[1:-1:2]):
        lowered = key.lower()
        require(lowered != 'include.path' and not (lowered.startswith('includeif.') and lowered.endswith('.path')),
                'Git config include/includeIf is not supported by a closed source base')
        if origin == 'command line:':
            continue  # Only this runner's fixed -c options; inherited GIT_* is cleared.
        require(origin.startswith('file:'), 'unsupported Git configuration origin')
        name = origin[len('file:'):]
        config_path = Path(name) if os.path.isabs(name) else repo / name
        require(portable_link(root, config_path).is_file(), 'Git configuration is not an in-image regular file')
    values = {}
    for key, args in (('git_dir', ('rev-parse', '--absolute-git-dir')),
                      ('common_dir', ('rev-parse', '--git-common-dir')),
                      ('objects_dir', ('rev-parse', '--git-path', 'objects'))):
        value = git.run(repo, *args).stdout.strip()
        path = Path(value) if os.path.isabs(value) else repo / value
        values[key] = portable_link(root, path).relative_to(root).as_posix()
    common = root / values['git_dir'] / 'commondir'
    if common.exists():
        require(not os.path.isabs(read_bytes(common, 65536).decode().strip()), 'absolute commondir is not relocatable')
    worktree = git.run(repo, 'config', '--get', 'core.worktree', check=False)
    require(worktree.returncode in (0, 1), 'cannot inspect controlled Git worktree metadata')
    require(not worktree.stdout.strip() or not os.path.isabs(worktree.stdout.strip()),
            'absolute core.worktree is not relocatable')
    return values


def object_closure(root, objects, git, *, visited=None):
    """Verify alternate and object-file pointers stay inside the image closure."""
    visited = set() if visited is None else visited
    objects = portable_link(root, objects)
    if objects in visited: return
    require(len(visited) < 4096, 'alternate object closure is oversized')
    visited.add(objects)
    # Git object storage has a shallow known layout; do not walk source trees.
    count = 0
    for folder in objects.iterdir():
        git.check_time()
        count += 1
        target = portable_link(root, folder)
        if folder.name in ('pack', 'info') or re.fullmatch(r'[0-9a-f]{2}', folder.name):
            require(target.is_dir(), 'unexpected object storage entry')
            for entry in target.iterdir():
                count += 1
                if count % 256 == 0: git.check_time()
                require(count <= 2000000, 'object storage entry limit exceeded')
                portable_link(root, entry)
    alternates = objects / 'info/alternates'
    if alternates.exists():
        for line in read_bytes(alternates, 1024 * 1024).decode().splitlines():
            require(line and not os.path.isabs(line) and not line.startswith('"'),
                    'alternates must be unquoted relative paths relocatable inside the image')
            object_closure(root, objects / line, git, visited=visited)
    require(not (objects / 'info/http-alternates').exists(), 'HTTP alternates are forbidden in an offline source base')


def audit_repository(root, key, git, *, manifest_metadata=False):
    if manifest_metadata:
        require(key.startswith('.repo/'), 'manifest Git metadata must remain under .repo')
        validate_relative_path(key[len('.repo/'):])
    else:
        key = validate_relative_path(key)
    repo = root / key
    require(repo.resolve() == repo, 'project checkout must not be a symlink')
    require(contained(root, git.run(repo, 'rev-parse', '--show-toplevel').stdout.strip()) == repo,
            'project is not its own Git checkout')
    paths = metadata(root, repo, git)
    object_closure(root, root / paths['objects_dir'], git)
    refs = git.run(repo, 'rev-parse', 'HEAD', 'HEAD^{tree}').stdout.splitlines()
    require(len(refs) == 2 and all(OID.fullmatch(value) for value in refs), 'invalid current fixed Git objects')
    flags = git.run(repo, 'ls-files', '-v', '-z').stdout.split('\0')
    require(all(len(entry) >= 3 and entry[1] == ' ' and not entry[0].islower() and entry[0] != 'S'
                for entry in flags if entry), 'index assume-unchanged/skip-worktree flags cannot establish clean source')
    row = {'head': refs[0], 'tree': refs[1],
        'index_flags_verified': True,
        'status': git.run(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout,
        'index_check_returncode': git.run(repo, 'diff', '--cached', '--quiet', '--no-ext-diff', '--no-textconv', 'HEAD', check=False).returncode,
        'worktree_check_returncode': git.run(repo, 'diff', '--quiet', '--no-ext-diff', '--no-textconv', 'HEAD', check=False).returncode}
    ignored = sorted(filter(None, git.run(repo, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').stdout.split('\0')))
    row.update(ignored_files=ignored, undeclared_ignored_files=ignored, declared_ignored_inputs={})
    require(not row['status'] and not row['index_check_returncode'] and not row['worktree_check_returncode']
            and not ignored, 'source base must be clean with no undeclared ignored inputs: ' + key)
    objects = git.run(repo, 'rev-list', '--objects', '--no-object-names', '--missing=print', '--no-walk', refs[0]).stdout.splitlines()
    require(objects and len(objects) <= 500000 and all(OID.fullmatch(value) for value in objects),
            'current snapshot has missing objects or exceeds the object bound: ' + key)
    return {**paths, 'commit': refs[0], 'tree': refs[1], 'audit': row}


def checkout_manifest(root, manifest_origin, git):
    manifests = portable_link(root, root / '.repo/manifests')
    manifest_git = audit_repository(root, manifests.relative_to(root).as_posix(), git, manifest_metadata=True)
    selected = root / '.repo/manifest.xml'
    if selected.is_symlink(): portable_link(root, selected)
    name = selected.resolve().relative_to(manifests).as_posix() if selected.is_symlink() else 'selected-manifest.xml'
    snapshots, documents = {}, {}
    def read(name):
        path = selected if name == 'selected-manifest.xml' else manifests / validate_relative_path(name)
        path = contained(root, path)
        data = read_bytes(path, 8 * 1024**2)
        snapshots[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
        documents[name] = data
        return data
    extras = []
    local = root / '.repo/local_manifests'
    if local.exists():
        require(not local.is_symlink(), 'local manifest directory must not be a symlink')
        for path in sorted(local.glob('*.xml')):
            require(not path.is_symlink(), 'local manifests must not be symlinks')
            data = read_bytes(contained(root, path), 8 * 1024**2)
            label = path.relative_to(root).as_posix()
            snapshots[label] = hashlib.sha256(data).hexdigest(); documents[label] = data
            extras.append((label, data))
    projects = parse_manifest(read, name, extra_documents=extras)
    require(len(projects) <= 10000, 'manifest project count exceeds audit bound')
    inventory_sha = None
    inventory = root / '.repo/project.list'
    if os.path.lexists(inventory):
        inventory_data = read_bytes(portable_link(root, inventory), 4 * 1024**2)
        listed = [validate_relative_path(line) for line in inventory_data.decode().splitlines() if line.strip()]
        require(len(listed) == len(set(listed)) and set(listed) == {item.key for item in projects},
                'checkout project inventory differs from the complete effective manifest')
        inventory_sha = hashlib.sha256(inventory_data).hexdigest()
    operations = []
    def project(node, parent_name='', parent_path=''):
        owner_name = '/'.join(filter(None, (parent_name, node.attrib['name'])))
        path = '/'.join(filter(None, (parent_path, node.get('path', node.attrib['name']))))
        matches = [p for p in projects if p.name == owner_name]
        exact = [p for p in matches if p.key == path]; matches = exact or matches
        for child in node:
            if child.tag == 'project': project(child, owner_name, path)
            elif child.tag in ('copyfile', 'linkfile') and matches:
                require(len(matches) == 1, 'ambiguous manifest file owner')
                operations.append({'kind': child.tag, 'project': matches[0].key,
                                   'src': child.attrib['src'], 'dest': child.attrib['dest']})
    for data in documents.values():
        for node in ET.fromstring(data):
            if node.tag == 'project': project(node)
    declarations = []
    for item in projects:
        row = asdict(item)
        require(item.fetch, 'manifest project has no explicit remote fetch')
        row['origin'] = safe_origin(urljoin(urljoin(manifest_origin, item.fetch.rstrip('/') + '/'), item.name))
        declarations.append(row)
    provenance = {'scope': 'effective_checkout_manifest',
        'manifest_origin': manifest_origin, 'manifest_name': name, 'metadata_sha256': snapshots,
        'manifest_git': manifest_git}
    if inventory_sha is not None: provenance['project_list_sha256'] = inventory_sha
    return declarations, operations, provenance


def manifest_projection(root, operations, projects, git):
    require(isinstance(operations, list) and len(operations) <= 4096, 'invalid manifest file projection')
    result = {}
    for item in operations:
        require(isinstance(item, dict) and set(item) == {'kind', 'project', 'src', 'dest'}
                and item['kind'] in ('copyfile', 'linkfile') and item['project'] in projects,
                'invalid manifest file directive')
        key, src, dest = item['project'], item['src'], validate_relative_path(item['dest'])
        require(src == '.' or validate_relative_path(src), 'invalid manifest source')
        source, target = root / key / src, root / dest
        require(source.resolve().is_relative_to(root / key) and target.parent.resolve() == target.parent
                and dest not in result, 'manifest projection escapes or duplicates a path')
        if item['kind'] == 'copyfile':
            require(not target.is_symlink(), 'manifest copy must be a regular file')
            expected, actual = read_bytes(source, 32 * 1024**2), read_bytes(target, 32 * 1024**2)
            require(expected == actual, 'manifest copy differs from its source')
            result[dest] = {'kind': 'copyfile', 'sha256': hashlib.sha256(actual).hexdigest()}
        else:
            require(target.is_symlink() and os.readlink(target) == os.path.relpath(source, target.parent)
                    and target.resolve() == source.resolve(), 'manifest link differs from its source')
            result[dest] = {'kind': 'linkfile', 'link': os.readlink(target)}
            if source.is_file():
                result[dest]['sha256'] = hashlib.sha256(read_bytes(source, 32 * 1024**2)).hexdigest()
            else:
                require(source.is_dir(), 'unsupported manifest link target')
                ref = projects[key]['commit'] + ('^{tree}' if src == '.' else ':' + src)
                tree = git.run(root / key, 'rev-parse', '--verify', ref).stdout.strip()
                require(git.run(root / key, 'cat-file', '-t', tree).stdout.strip() == 'tree', 'manifest directory link is not a fixed tree')
                result[dest]['tree'] = tree
    return result


def audit_projects(root, declarations, operations, provenance, git):
    require(isinstance(declarations, list) and 0 < len(declarations) <= 10000, 'invalid project declarations')
    projects = {}
    for declared in declarations:
        key = validate_relative_path(declared['key'])
        require(key not in projects, 'duplicate project path')
        row = audit_repository(root, key, git)
        revision = revision_name(declared['revision'])
        resolved = git.run(root / key, 'rev-parse', '--verify', revision + '^{commit}').stdout.strip()
        require(OID.fullmatch(resolved), 'manifest reference does not resolve to a fixed commit')
        row['references'] = {revision: resolved}
        if declared.get('origin'): row['origin'] = safe_origin(declared['origin'])
        projects[key] = row
    projection = manifest_projection(root, operations, projects, git)
    return {'version': 1, 'projects': projects, 'manifest_files': operations,
            'manifest_provenance': provenance, 'manifest_projection': projection,
            'project_declarations': declarations}


def create_catalog(source_root, *, manifest_origin=None, project_catalog=None, git=None):
    root = Path(source_root).resolve(strict=True); git = git or GitAudit()
    if (root / '.repo').exists():
        require(project_catalog is None and manifest_origin, 'repo checkout requires --manifest-origin and its complete effective manifest')
        declarations, operations, provenance = checkout_manifest(root, safe_origin(manifest_origin), git)
    else:
        require(project_catalog is not None, 'without .repo, an explicit --project-catalog is required; directories are never guessed')
        declared = read_json(project_catalog)
        declarations, operations = declared['projects'], declared.get('manifest_files', [])
        provenance = {'scope': 'explicit_project_catalog', 'input_sha256': hashlib.sha256(read_bytes(project_catalog)).hexdigest()}
    return audit_projects(root, declarations, operations, provenance, git)


def audit_registered_base(handle, *, git=None):
    git = git or GitAudit(); catalog = handle.catalog; root = handle.mount_root
    provenance = catalog['manifest_provenance']
    if provenance['scope'] == 'effective_checkout_manifest':
        declarations, operations, observed = checkout_manifest(root, provenance['manifest_origin'], git)
        require(observed == provenance, 'sealed manifest provenance differs from the catalogue')
    else:
        require(provenance['scope'] == 'explicit_project_catalog' and not (root / '.repo').exists(), 'unsupported catalogue source scope')
        declarations, operations = catalog['project_declarations'], catalog['manifest_files']
    actual = audit_projects(root, declarations, operations, provenance, git)
    require(actual == catalog, 'sealed checkout or fixed references differ from the catalogue')
    return {'status': 'PASS', 'repositories': {key: row['audit'] for key, row in actual['projects'].items()},
            'project_references': {key: {field: row[field] for field in ('origin', 'references', 'source_revision') if field in row}
                for key, row in actual['projects'].items()},
            'manifest_provenance': provenance, 'usage': git.usage()}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest='command', required=True)
    create = sub.add_parser('create-catalog', help='read a complete checkout; write catalogue outside it')
    create.add_argument('--source-root', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True)
    create.add_argument('--manifest-origin')
    create.add_argument('--project-catalog', type=Path, help='no-.repo only: JSON projects [{key, revision, origin?}], manifest_files []')
    register = sub.add_parser('register', help='audit an already sealed/mounted spec and publish a new receipt')
    register.add_argument('--spec', type=Path, required=True)
    register.add_argument('--receipt', type=Path, required=True)
    for command in (create, register):
        command.add_argument('--git-timeout', type=float, default=60)
        command.add_argument('--timeout', type=float, default=7200)
        command.add_argument('--max-output-bytes', type=int, default=64 * 1024**2)
        command.add_argument('--max-total-output-bytes', type=int, default=1024**3)
        command.add_argument('--max-git-operations', type=int, default=50000)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    git = GitAudit(command_timeout=args.git_timeout, timeout=args.timeout,
        max_output_bytes=args.max_output_bytes, max_total_output_bytes=args.max_total_output_bytes,
        max_operations=args.max_git_operations)
    destination = args.output if args.command == 'create-catalog' else args.receipt
    require(not os.path.lexists(destination), 'refusing to overwrite an existing catalogue/receipt')
    if args.command == 'create-catalog':
        root = args.source_root.resolve(strict=True)
        require(not destination.resolve().is_relative_to(root), 'catalogue output must be outside the source root')
        catalog = create_catalog(root, manifest_origin=args.manifest_origin, project_catalog=args.project_catalog, git=git)
        data = (json.dumps(catalog, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()
        require(len(data) <= MAX_JSON, 'catalogue exceeds provider byte limit')
        with destination.open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps({'catalog': str(destination.resolve()), 'catalog_sha256': hashlib.sha256(data).hexdigest(),
            'projects': len(catalog['projects']), 'usage': git.usage(),
            'next_step': 'Include these exact catalogue bytes in an externally prepared sealed image; no image or mount was created.'}))
    else:
        spec = read_json(args.spec)
        require(not destination.resolve().is_relative_to(Path(spec['mount_root']).resolve()), 'registration receipt must be outside the sealed source root')
        binding = register_source_base(spec, destination.resolve(), audit=lambda handle: audit_registered_base(handle, git=git))
        print(json.dumps({**binding, 'usage': git.usage()}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
