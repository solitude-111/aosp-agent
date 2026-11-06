"""Read a versioned repo manifest without walking or reading project trees.

Project objects are resolved only when selected. A missing requested revision
is an error; the catalogue never substitutes the checkout's current HEAD.
Reference: git-repo docs/manifest-format.md (include, project, remote/default).
"""
from dataclasses import asdict, dataclass, replace
import hashlib
from pathlib import Path
import os
import xml.etree.ElementTree as ET

from .case import validate_relative_path
from .discovery import local_git
from .runtime_input import project_name, revision_name


@dataclass(frozen=True)
class Project:
    key: str
    name: str
    revision: str
    remote: str = ''
    fetch: str = ''


class ProjectCatalog:
    def __init__(self, root, projects, provenance):
        self.root = Path(root).resolve()
        self.projects = {p.key: p for p in projects}
        if len(self.projects) != len(projects) or not projects:
            raise ValueError('manifest has duplicate project paths or no projects')
        self.provenance, self.pins = provenance, {}
        self.standalone = os.path.lexists(self.root / '.git')

    def data(self):
        return {'provenance': self.provenance,
                'projects': [asdict(p) for p in self.projects.values()]}

    def candidates(self, origins):
        names = {project_name(origin) for origin in origins}
        normalized = {n.removeprefix('platform/') for n in names}
        return [p.key for p in self.projects.values()
                if p.name in names or p.name.removeprefix('platform/') in normalized]

    def pin(self, key):
        if key not in self.projects:
            raise ValueError('project is not in the pinned manifest: ' + key)
        if key in self.pins:
            return self.pins[key]
        project = self.projects[key]
        path = self.root if self.standalone and key == 'repo' else (self.root / key).resolve()
        if not path.is_relative_to(self.root) or not path.is_dir():
            raise ValueError('target project is unavailable or escapes source root: ' + key)
        owning = Path(local_git(path, 'rev-parse', '--show-toplevel').stdout.strip()).resolve()
        if owning != path:
            raise ValueError('project path is not a standalone Git checkout: ' + key)
        head = local_git(path, 'rev-parse', '--verify', project.revision + '^{commit}').stdout.strip()
        self.pins[key] = {'root': str(path), 'head': head, 'revision': project.revision, 'name': project.name}
        return self.pins[key]


def parse_manifest(read, manifest_name='default.xml', *, extra_documents=()):
    """Parse bounded manifest metadata; read(name) returns pinned XML bytes/text.

    Nested submanifests need another independently pinned manifest repository;
    reject them explicitly instead of silently dropping their project scope.
    """
    nodes, total = [], [0]
    def expand(name, stack=(), inherited_revision=None, supplied=None):
        name = validate_relative_path(name)
        if name in stack or len(stack) >= 32 or len(nodes) > 20000:
            raise ValueError('manifest include cycle or metadata limit exceeded')
        content = read(name) if supplied is None else supplied
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        total[0] += len(content.encode())
        if total[0] > 8 * 1024 * 1024 or '<!DOCTYPE' in content or '<!ENTITY' in content:
            raise ValueError('manifest is oversized or contains unsupported entity declarations')
        root = ET.fromstring(content)
        if root.tag != 'manifest':
            raise ValueError('expected manifest XML root')
        for element in root:
            if element.tag == 'include':
                expand(element.attrib['name'], (*stack, name), element.get('revision', inherited_revision))
            elif element.tag == 'submanifest':
                raise ValueError('submanifest requires a separately pinned catalogue; automatic omission is forbidden')
            else:
                nodes.append((element, inherited_revision))
    expand(manifest_name)
    # Local manifests are ordered after the selected main manifest. Includes
    # still resolve relative to the manifest repository root, per repo's spec.
    for name, content in extra_documents:
        expand(name, supplied=content)
    remotes, default = {}, {}
    for node, _ in nodes:
        if node.tag == 'remote':
            name = node.attrib['name']
            if name in remotes and remotes[name] != node.attrib:
                raise ValueError('conflicting manifest remote: ' + name)
            remotes[name] = dict(node.attrib)
        elif node.tag == 'default':
            if default and default != node.attrib:
                raise ValueError('conflicting manifest defaults')
            default = dict(node.attrib)
    projects = {}
    def add(node, inherited_revision=None, parent=None):
        name = validate_relative_path(node.attrib['name'])
        path = validate_relative_path(node.get('path', name))
        if parent:
            name, path = parent.name + '/' + name, parent.key + '/' + path
        remote = node.get('remote') or (parent.remote if parent else default.get('remote', ''))
        if remote and remote not in remotes:
            raise ValueError('undefined manifest remote: ' + remote)
        revision = (node.get('revision') or inherited_revision or
                    (parent.revision if parent else None) or remotes.get(remote, {}).get('revision') or default.get('revision'))
        revision_name(revision)
        if path in projects:
            raise ValueError('duplicate manifest project path: ' + path)
        project = Project(path, name, revision, remote, remotes.get(remote, {}).get('fetch', ''))
        projects[path] = project
        for child in node.findall('project'):
            add(child, inherited_revision, project)
    for node, inherited in nodes:
        if node.tag == 'project':
            add(node, inherited)
        elif node.tag in ('extend-project', 'remove-project'):
            if not node.get('name') and not node.get('path'):
                raise ValueError('manifest edit requires project name or path')
            matches = [p for p in projects.values()
                       if (not node.get('name') or p.name == node.get('name'))
                       and (not node.get('path') or p.key == node.get('path'))]
            if not matches and not (node.tag == 'remove-project' and node.get('optional') == 'true'):
                raise ValueError('manifest edit did not match any project')
            for p in matches:
                if node.get('base-rev') and node.get('base-rev') != p.revision:
                    raise ValueError('manifest base-rev mismatch: ' + p.key)
                del projects[p.key]
                if node.tag == 'remove-project':
                    continue
                key = validate_relative_path(node.get('dest-path', p.key))
                remote = node.get('remote', p.remote)
                if key in projects or (remote and remote not in remotes):
                    raise ValueError('invalid extended project destination or remote')
                revision = revision_name(node.get('revision', p.revision))
                projects[key] = replace(p, key=key, revision=revision, remote=remote,
                                        fetch=remotes.get(remote, {}).get('fetch', ''))
    return list(projects.values())


def catalog_from_checkout(root, pinned_heads=None):
    """Snapshot effective checkout metadata, including sorted local overlays.

    This deliberately differs from a named release: read current XML bytes,
    retain their digests and pin each selected project's actual HEAD later.
    Unsupported or unreadable metadata must not become a partial catalogue.
    """
    root = Path(root).resolve()
    metadata = root / '.repo'
    if not metadata.exists():
        return None
    manifests = (metadata / 'manifests').resolve()
    selected = metadata / 'manifest.xml'
    snapshots = {}
    def snapshot(path, label):
        with path.open('rb') as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise ValueError('manifest metadata file is oversized')
        snapshots[label] = hashlib.sha256(data).hexdigest()
        return data
    def read(name):
        path = (manifests / validate_relative_path(name)).resolve()
        if not path.is_relative_to(manifests):
            raise ValueError('manifest include escapes metadata root')
        return snapshot(path, 'manifests/' + name)
    if os.path.lexists(selected):
        resolved = selected.resolve()
        if resolved == selected:
            main_data = snapshot(selected, 'manifest.xml')
            name = 'selected-manifest.xml'
        elif resolved.is_relative_to(manifests):
            name = resolved.relative_to(manifests).as_posix()
            main_data = read(name)
        else:
            raise ValueError('selected manifest escapes metadata root')
    else:
        name, main_data = 'default.xml', read('default.xml')
    local = metadata / 'local_manifests'
    extra = []
    if os.path.lexists(local):
        if local.is_symlink() or not local.is_dir():
            raise ValueError('local manifest directory must be a real directory')
        for path in sorted(local.glob('*.xml')):
            if path.is_symlink() or not path.is_file():
                raise ValueError('local manifest must be a regular metadata file')
            extra.append(('local_manifests/' + path.name, snapshot(path, 'local_manifests/' + path.name)))
    projects = parse_manifest(lambda requested: main_data if requested == name else read(requested),
                              name, extra_documents=extra)
    pins = pinned_heads or {}
    projects = [replace(p, revision=pins.get(p.key, 'HEAD')) for p in projects]
    return ProjectCatalog(root, projects, {'scope': 'effective_checkout_manifest',
        'manifest_name': name, 'metadata_sha256': snapshots, 'local_overrides': 'APPLIED_IN_FILENAME_ORDER',
        'target_policy': 'current_heads_pinned_on_admission'})


def catalog_at_revision(root, target_revision, *, manifest_repo=None, manifest_name=None):
    root = Path(root).resolve()
    target_revision = revision_name(target_revision)
    manifest_repo = Path(manifest_repo).resolve() if manifest_repo else root / '.repo/manifests'
    if manifest_name is None:
        selected = root / '.repo/manifest.xml'
        if selected.exists() and selected.resolve().is_relative_to(manifest_repo.resolve()):
            manifest_name = selected.resolve().relative_to(manifest_repo.resolve()).as_posix()
        else:
            manifest_name = 'default.xml'
    manifest_name = validate_relative_path(manifest_name)
    sha = local_git(manifest_repo, 'rev-parse', '--verify', target_revision + '^{commit}').stdout.strip()
    def read(name):
        return local_git(manifest_repo, 'show', '--no-ext-diff', '--no-textconv', f'{sha}:{name}').stdout
    projects = parse_manifest(read, manifest_name)
    return ProjectCatalog(root, projects, {'manifest_commit': sha, 'manifest_name': manifest_name,
        'requested_revision': target_revision, 'scope': 'versioned_manifest',
        'local_overrides': 'NOT_APPLIED; unversioned checkout overlays are not part of this target revision'})
