"""Reusable static Blueprint facts, never a product graph or build receipt.

Only pinned repositories with the controller's bounded object cache reuse this
index. Identity includes the parser implementation and scan limit. Transient
reads never enter the index; immutable syntax limitations remain explicit.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import unicodedata

from . import blueprint_literals


def parser_identity():
    # Fail back to uncached evaluation if installed source is unavailable.
    digest = hashlib.sha256(b'blueprint-metadata-index-v1\0')
    for filename in (__file__, blueprint_literals.__file__):
        data = Path(filename).read_bytes()
        digest.update(Path(filename).name.encode() + b'\0')
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)
    digest.update(str((blueprint_literals.MAX_BYTES, blueprint_literals.MAX_ITEMS,
                       blueprint_literals.MAX_DEPTH, sys.version_info[:3], unicodedata.unidata_version)).encode())
    return digest.hexdigest()


def _read_metadata(repo, limit):
    files = sorted((p for p in repo.files if PurePosixPath(p).name == 'Android.bp'),
                   key=lambda p: (len(PurePosixPath(p).parts), p))
    result = {'modules': [], 'issues': [], 'metadata_inputs': [],
              'limit_exceeded': len(files) > limit, 'reusable': True}
    if result['limit_exceeded']:
        return result
    scopes = {}
    for bp in files:
        directory = PurePosixPath(bp).parent
        ancestor = next((p for p in directory.parents if p in scopes), None)
        inherited = scopes.get(ancestor, {})
        if inherited is None:
            result['issues'].append({'path': bp, 'reason': 'ancestor Blueprint scope is unresolved'})
            scopes[directory] = None
            continue
        try:
            text = repo.read(bp)
            result['metadata_inputs'].append({'path': bp, 'sha256': hashlib.sha256(text.encode()).hexdigest()})
            found, errors, exported = blueprint_literals.parse_metadata(text, bp, inherited)
            scopes[directory] = exported
            result['modules'].extend(found)
            result['issues'].extend(errors)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            # A failed read is environmental, not an immutable missing module.
            result['reusable'] = False
            scopes[directory] = None
            result['issues'].append({'path': bp, 'reason': str(exc)})
    return result


def _bounded_json(value, limit):
    chunks, size = [], 0
    for chunk in json.JSONEncoder(sort_keys=True, ensure_ascii=True).iterencode(value):
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return ''.join(chunks)


def _valid(value):
    if not isinstance(value, dict) or set(value) != {'modules', 'issues', 'metadata_inputs', 'limit_exceeded', 'reusable'}:
        return False
    if type(value['limit_exceeded']) is not bool or value['reusable'] is not True:
        return False
    if not all(isinstance(value[k], list) for k in ('modules', 'issues', 'metadata_inputs')):
        return False
    return (all(isinstance(m, dict) and all(isinstance(m.get(k), str) for k in ('name', 'kind', 'path'))
                and isinstance(m.get('properties'), dict) for m in value['modules'])
            and all(isinstance(i, dict) for i in value['issues'])
            and all(isinstance(i, dict) and isinstance(i.get('path'), str)
                    and isinstance(i.get('sha256'), str) and len(i['sha256']) == 64 for i in value['metadata_inputs']))


def load_metadata(repo, limit):
    from .retrieval import LazyTree
    tree = repo.files
    if not isinstance(tree, LazyTree) or tree.cache is None:
        return _read_metadata(repo, limit)
    if tree.head != repo.head or Path(tree.root).resolve() != Path(repo.root).resolve():
        raise ValueError('build metadata index requires matching pinned tree and repository')
    try:
        policy = parser_identity()
    except OSError:
        return _read_metadata(repo, limit)
    args = ('@blueprint-metadata-index-v1', policy, str(limit))
    built = None
    def compute():
        nonlocal built
        built = _read_metadata(repo, limit)
        payload = _bounded_json(built, tree.cache.max_entry_bytes // 2) if built['reusable'] else None
        # Nonzero results are intentionally not persisted by ObjectCache.
        return subprocess.CompletedProcess(args, 0 if payload is not None else 2, payload or '', '')
    result = tree.cache.query(repo.root, repo.head, args, compute)
    if built is not None:
        metadata = built
    else:
        try:
            metadata = json.loads(result.stdout)
        except (ValueError, TypeError):
            metadata = None
        if not _valid(metadata):
            metadata = _read_metadata(repo, limit)
    # Index identity is informational. The ownership resolver still evaluates
    # current requested paths, unknown consumers, exclusions and test roles.
    metadata['index'] = {'policy': policy, 'target_commit': repo.head,
                         'scope': 'pinned_static_metadata_not_product_graph'}
    return metadata
