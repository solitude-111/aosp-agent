"""Controlled Android build identities and scope-bound baseline evidence.

Only the declared build profile is cached. This is not a cache of arbitrary
commands, a compatibility oracle, or a proof of Android runtime correctness.
"""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sys
import time
import uuid

from .case import validate_relative_path
from .lifecycle import ACTIVE_SOURCE_LEASE, RecoveryBlocked, source_lease
from .execution_budget import controller_audit


class BuildEnvironmentBlocked(ValueError):
    kind = 'BUILD_ENVIRONMENT_BLOCKED'

    def __init__(self, message, *, kind='BUILD_ENVIRONMENT_BLOCKED', pause_batch=False):
        super().__init__(message)
        self.kind, self.pause_batch = kind, pause_batch


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode()).hexdigest()


def file_identity(path):
    p = Path(path)
    if not p.is_absolute() or not p.is_file():
        raise BuildEnvironmentBlocked('build identity file is unavailable: ' + str(p))
    digest = hashlib.sha256()
    with p.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': str(p), 'resolved_path': str(p.resolve()), 'sha256': digest.hexdigest(),
            'mode': p.stat().st_mode & 0o777}


def manifest_file_identity(source_root, operations, project_pins):
    """Bind only manifest-declared root copies/links; never scan the source root."""
    from .discovery import local_git
    root = Path(source_root).resolve()
    if not isinstance(operations, list) or len(operations) > 4096:
        raise BuildEnvironmentBlocked('manifest file operation list is invalid or oversized')
    result = {}
    for operation in operations:
        if (not isinstance(operation, dict) or set(operation) != {'kind', 'project', 'src', 'dest'}
                or operation['kind'] not in ('copyfile', 'linkfile')
                or operation['project'] not in project_pins):
            raise BuildEnvironmentBlocked('unsupported manifest file identity')
        key = validate_relative_path(operation['project'])
        source_name = operation['src']
        if source_name != '.': validate_relative_path(source_name)
        dest = validate_relative_path(operation['dest'])
        repo, path = root / key, root / dest
        source = repo / source_name
        if (dest in result or not source.resolve().is_relative_to(repo.resolve())
                or path.parent.resolve() != path.parent or not source.exists()):
            raise BuildEnvironmentBlocked('manifest file path is duplicate, missing or escapes its declared scope')
        row = {'operation': operation, 'source_commit': project_pins[key]}
        if operation['kind'] == 'copyfile':
            if path.is_symlink() or not path.is_file() or not source.is_file():
                raise BuildEnvironmentBlocked('manifest root copy is not a regular file: ' + dest)
            if path.stat().st_size > 32 * 1024 * 1024 or source.stat().st_size > 32 * 1024 * 1024:
                raise BuildEnvironmentBlocked('manifest root copy exceeds its bounded file scope: ' + dest)
            source_identity, destination = file_identity(source.resolve()), file_identity(path)
            if source_identity['sha256'] != destination['sha256']:
                raise BuildEnvironmentBlocked('manifest root copy differs from its pinned source: ' + dest)
            row.update(kind='regular_file', destination=destination, source_sha256=source_identity['sha256'])
        else:
            expected_link = os.path.relpath(source, path.parent)
            if not path.is_symlink() or os.readlink(path) != expected_link or path.resolve() != source.resolve():
                raise BuildEnvironmentBlocked('manifest root link differs from its declared target: ' + dest)
            row.update(kind='symlink', link_target=os.readlink(path), resolved_target=str(path.resolve()),
                       mode=path.lstat().st_mode & 0o777)
            if source.is_dir():
                relative = source.resolve().relative_to(repo.resolve()).as_posix()
                ref = project_pins[key] + ('^{tree}' if relative == '.' else ':' + relative)
                tree = local_git(repo, 'rev-parse', '--verify', ref).stdout.strip()
                if local_git(repo, 'cat-file', '-t', tree).stdout.strip() != 'tree':
                    raise BuildEnvironmentBlocked('manifest directory link does not reference a pinned Git tree')
                row.update(target_kind='directory', target_tree=tree, target_mode=source.stat().st_mode & 0o777)
            elif source.is_file():
                if source.stat().st_size > 32 * 1024 * 1024:
                    raise BuildEnvironmentBlocked('manifest root link file exceeds its bounded file scope: ' + dest)
                row.update(target_kind='regular_file', target=file_identity(source.resolve()))
            else:
                raise BuildEnvironmentBlocked('unsupported manifest link target: ' + dest)
        result[dest] = row
    return result


def verify_manifest_files(identity):
    try:
        observed = manifest_file_identity(identity['source_root'], identity.get('manifest_file_operations', []),
                                          identity['project_pins'])
    except (OSError, ValueError) as exc:
        raise RecoveryBlocked('declared manifest root files cannot be verified: ' + str(exc)) from exc
    if observed != identity.get('manifest_files', {}):
        raise RecoveryBlocked('declared manifest root file/link identity changed')
    return observed


def _pins(value):
    if not isinstance(value, dict) or not value or len(value) > 10000:
        raise BuildEnvironmentBlocked('a complete nonempty fixed project vector is required')
    result = {}
    for key, revision in value.items():
        validate_relative_path(key)
        if not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', revision):
            raise BuildEnvironmentBlocked('project vector contains an unfixed revision: ' + key)
        result[key] = revision
    return dict(sorted(result.items()))


def validate_build_config(value):
    if not isinstance(value, dict):
        raise ValueError('build configuration must be an object')
    allowed = {'enabled', 'runner', 'product', 'variant', 'arch', 'build_system', 'toolchain',
               'host', 'identity_files', 'environment', 'ninja', 'output_root', 'tmp_root',
               'baseline_cache', 'baseline_timeout', 'graph_timeout', 'compatibility_mappings'}
    if set(value) - allowed:
        raise ValueError('unknown build configuration fields: ' + ', '.join(sorted(set(value) - allowed)))
    config = deepcopy(value)
    enabled = config.setdefault('enabled', False)
    if type(enabled) is not bool:
        raise ValueError('build.enabled must be boolean')
    if not enabled:
        return config
    for name in ('runner', 'output_root', 'tmp_root', 'baseline_cache'):
        if not isinstance(config.get(name), str) or not Path(config[name]).is_absolute():
            raise ValueError('build.' + name + ' must be an absolute path')
    for name in ('product', 'variant', 'arch', 'build_system', 'toolchain'):
        if not isinstance(config.get(name), str) or not config[name].strip():
            raise ValueError('build.' + name + ' must declare a controlled identity')
    for name in ('product', 'variant', 'arch'):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', config[name]):
            raise ValueError('invalid build selection: ' + name)
    if config['variant'] not in ('user', 'userdebug', 'eng'):
        raise ValueError('unsupported Android build variant')
    host = config.get('host')
    if (not isinstance(host, dict) or set(host) - {'kind', 'identity', 'tools', 'image_digest'}
            or host.get('kind') not in ('host', 'container') or not host.get('identity')
            or not isinstance(host.get('tools'), dict) or not host['tools']):
        raise ValueError('build.host must declare kind, controlled identity and tool paths')
    if host['kind'] == 'container' and not re.fullmatch(r'sha256:[0-9a-f]{64}', host.get('image_digest', '')):
        raise ValueError('container builds require an immutable image digest')
    for name, path in {**host['tools'], **config.setdefault('identity_files', {})}.items():
        if not isinstance(name, str) or not isinstance(path, str) or not Path(path).is_absolute():
            raise ValueError('identity tool/config paths must be absolute')
    if config.get('ninja') and not Path(config['ninja']).is_absolute():
        raise ValueError('build.ninja must be an absolute path')
    environment = config.setdefault('environment', {})
    if not isinstance(environment, dict):
        raise ValueError('build.environment must be a string mapping')
    for key, val in environment.items():
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', key)
                or not isinstance(val, str) or '\x00' in val or key.startswith('AOSP_AGENT_')
                or re.search(r'KEY|TOKEN|PASSWORD|SECRET|AUTH', key)):
            raise ValueError('build.environment cannot contain credentials or controller contract fields')
    # Cache only this declared environment, never ambient model/build flags or
    # credentials. A private HOME prevents undeclared user rc/config input.
    environment.setdefault('PATH', os.defpath)
    environment.setdefault('LANG', 'C.UTF-8')
    environment.setdefault('LC_ALL', 'C.UTF-8')
    private_home = str(Path(config['tmp_root']) / 'home')
    if environment.get('HOME', private_home) != private_home:
        raise ValueError('build.environment.HOME must be the private temporary view home')
    environment['HOME'] = private_home
    if config.get('ninja') and '-d keeprsp' not in environment.get('NINJA_ARGS', ''):
        environment['NINJA_ARGS'] = (environment.get('NINJA_ARGS', '') + ' -d keeprsp').strip()
    for name, default in (('baseline_timeout', 1800), ('graph_timeout', 120)):
        limit = config.setdefault(name, default)
        if type(limit) not in (int, float) or not 0 < limit <= 86400:
            raise ValueError('invalid build timeout: ' + name)
    for mapping in config.setdefault('compatibility_mappings', []):
        if (not isinstance(mapping, dict) or set(mapping) != {
                'id', 'target_vector_sha256', 'validation_pins', 'basis'}
                or not isinstance(mapping['id'], str) or not mapping['id']
                or not isinstance(mapping['basis'], str) or not mapping['basis']
                or not re.fullmatch(r'[0-9a-f]{64}', mapping['target_vector_sha256'])):
            raise ValueError('compatibility mapping needs an exact source vector and recorded basis')
        _pins(mapping['validation_pins'])
    return config


def select_validation_vector(target_pins, protected_pins, mappings=()):
    """Only a server-declared exact-vector mapping may change dependencies."""
    original = _pins(target_pins)
    protected = _pins(protected_pins)
    if any(original.get(k) != v for k, v in protected.items()):
        raise BuildEnvironmentBlocked('case target pins do not match the original full manifest')
    matches = [m for m in mappings if m['target_vector_sha256'] == canonical_hash(original)]
    if len(matches) > 1:
        raise BuildEnvironmentBlocked('ambiguous compatible build environments')
    selected = _pins(matches[0]['validation_pins']) if matches else original
    if set(selected) != set(original):
        raise BuildEnvironmentBlocked('compatible mapping must pin the same complete project set')
    if any(selected.get(k) != v for k, v in protected.items()):
        raise BuildEnvironmentBlocked('compatible mapping would change a tested repository commit')
    differences = {k: {'target': original[k], 'validation': v} for k, v in selected.items()
                   if original[k] != v}
    return {'original_project_pins': original, 'project_pins': selected,
            'differences': differences,
            'selection': {'mode': 'trusted_compatibility_mapping', 'id': matches[0]['id'],
                          'basis': matches[0]['basis']} if matches else {'mode': 'original_manifest'},
            'evidence_revalidation_required': sorted(differences)}


def _source_view_proof(environment):
    """A declaration never grants audit credit without its active mount proof."""
    if 'source_view' not in environment:
        return None
    descriptor = environment['source_view']
    fields = {'version', 'base_id', 'base_receipt_sha256', 'base_vector_sha256',
              'project_pins_sha256', 'writable_repositories'}
    vector = environment['project_pins']
    if (not isinstance(descriptor, dict) or set(descriptor) != fields
            or type(descriptor.get('version')) is not int or descriptor['version'] != 1
            or any(not isinstance(descriptor.get(key), str)
                   or not re.fullmatch(r'[0-9a-f]{64}', descriptor[key])
                   for key in fields - {'version', 'writable_repositories'})
            or descriptor['project_pins_sha256'] != canonical_hash(vector)):
        raise RecoveryBlocked('immutable source view declaration is invalid')
    writable = descriptor['writable_repositories']
    if (not isinstance(writable, list) or any(not isinstance(key, str) for key in writable)
            or writable != sorted(set(writable)) or not set(writable) <= set(vector)):
        raise RecoveryBlocked('immutable source view writable scope is invalid')
    from .preparation import verify_active_source_view
    proof = verify_active_source_view(environment['source_root'], vector, descriptor)
    if (not isinstance(proof, dict) or proof.get('base_id') != descriptor['base_id']
            or proof.get('base_receipt_sha256') != descriptor['base_receipt_sha256']
            or proof.get('writable_repositories') != writable
            or not isinstance(proof.get('repositories'), dict)
            or set(proof['repositories']) != set(vector) - set(writable)
            or not isinstance(proof.get('runtime_mount_proof'), dict)
            or not proof['runtime_mount_proof']):
        raise RecoveryBlocked('active immutable source view proof is incomplete')
    return proof


def environment_identity(prepared_environment, config, protected_pins):
    config = validate_build_config(config)
    if not config['enabled']:
        raise BuildEnvironmentBlocked('build verification is disabled')
    vector = _pins(prepared_environment['project_pins'])
    original = _pins(prepared_environment.get('original_project_pins', vector))
    selected = select_validation_vector(original, protected_pins, config['compatibility_mappings'])
    if vector != selected['project_pins']:
        raise BuildEnvironmentBlocked('prepared validation view differs from the selected exact vector')
    manifest = prepared_environment.get('manifest') or prepared_environment.get('manifest_provenance')
    manifest_commit = (manifest.get('manifest_commit') or manifest.get('commit')) if isinstance(manifest, dict) else None
    if not isinstance(manifest_commit, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', manifest_commit):
        raise BuildEnvironmentBlocked('fixed manifest provenance is required for build caching')
    source = Path(prepared_environment['source_root']).resolve()
    for name in ('output_root', 'tmp_root', 'baseline_cache'):
        path = Path(config[name]).resolve()
        if path == source or path.is_relative_to(source):
            raise BuildEnvironmentBlocked('build outputs/cache must be outside the source view: ' + name)
        if name in prepared_environment and path != Path(prepared_environment[name]).resolve():
            raise BuildEnvironmentBlocked('configured build path differs from the private prepared view: ' + name)
    files = {name: file_identity(path) for name, path in config['identity_files'].items()}
    files['runner'] = file_identity(config['runner'])
    files['controller_python'] = file_identity(sys.executable)
    if config.get('ninja'):
        files['ninja'] = file_identity(config['ninja'])
    controller_sources = {path.name: file_identity(path) for path in sorted(Path(__file__).parent.glob('*.py'))}
    host = {**config['host'], 'tools': {k: file_identity(p) for k, p in config['host']['tools'].items()},
            'observed_platform': {'system': platform.system(), 'release': platform.release(),
                                  'machine': platform.machine()}}
    payload = {'version': 1, **selected, 'manifest': manifest,
               'manifest_file_operations': prepared_environment.get('manifest_files', []),
               'manifest_files': manifest_file_identity(source, prepared_environment.get('manifest_files', []), vector),
               'controlled_overrides': prepared_environment.get('controlled_overrides', {}),
               'product': config['product'], 'variant': config['variant'], 'arch': config['arch'],
               'build_system': config['build_system'], 'toolchain': config['toolchain'],
               'files': files, 'controller_sources': controller_sources, 'host': host, 'environment': config['environment'],
               'source_root': str(source), 'output_root': config['output_root'], 'tmp_root': config['tmp_root'],
               'scope': 'declared_controlled_build_profile', 'runtime_security_proven': False}
    if 'source_view' in prepared_environment:
        # Source reuse is independent of runner/controller/output identities.
        # Keep activation-specific mount IDs out of the stable cache key.
        _source_view_proof(prepared_environment)
        payload['source_view'] = deepcopy(prepared_environment['source_view'])
    return {**payload, 'environment_id': canonical_hash(payload)}


def verify_environment_identity(identity, config):
    payload = {k: v for k, v in identity.items() if k != 'environment_id'}
    if identity.get('environment_id') != canonical_hash(payload):
        raise BuildEnvironmentBlocked('build environment identity was altered')
    _source_view_proof(identity)
    verify_manifest_files(identity)
    for key in ('product', 'variant', 'arch', 'build_system', 'toolchain', 'environment', 'output_root', 'tmp_root'):
        if identity.get(key) != config.get(key):
            raise BuildEnvironmentBlocked('build profile changed after identification: ' + key)
    declared_files = {**config['identity_files'], 'runner': config['runner'], 'controller_python': sys.executable}
    if config.get('ninja'):
        declared_files['ninja'] = config['ninja']
    if declared_files != {k: v['path'] for k, v in identity['files'].items()}:
        raise BuildEnvironmentBlocked('declared build scripts changed after identification')
    host = {k: v for k, v in identity['host'].items() if k != 'observed_platform'}
    host['tools'] = {k: v['path'] for k, v in host['tools'].items()}
    if host != config['host']:
        raise BuildEnvironmentBlocked('controlled host profile changed after identification')
    current_sources = {path.name: file_identity(path) for path in sorted(Path(__file__).parent.glob('*.py'))}
    if current_sources != identity.get('controller_sources'):
        raise BuildEnvironmentBlocked('controller build implementation changed after identification')
    for evidence in [*identity['files'].values(), *identity['host']['tools'].values()]:
        if evidence != file_identity(evidence['path']):
            raise BuildEnvironmentBlocked('controlled build input changed: ' + evidence['path'])
    observed = {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine()}
    if observed != identity['host']['observed_platform']:
        raise BuildEnvironmentBlocked('controlled build host changed')


def _write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('x') as stream:
        json.dump(value, stream, sort_keys=True, ensure_ascii=False, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


class BaselineCache:
    def __init__(self, root):
        self.root = Path(root).resolve(); self.root.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def locked(self, environment_id):
        if not re.fullmatch(r'[0-9a-f]{64}', environment_id):
            raise ValueError('invalid build environment identity')
        with (self.root / (environment_id + '.lock')).open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def lookup(self, identity, modules):
        required = set(_modules(modules)); covered, receipts = set(), []
        directory = self.root / identity['environment_id']
        for path in sorted(directory.glob('*.json')):
            try:
                data = json.loads(path.read_text())
                receipt = data['receipt']
                if (data['sha256'] != canonical_hash(receipt)
                        or receipt['environment_id'] != identity['environment_id']
                        or receipt['phase'] != 'baseline' or receipt['returncode'] != 0
                        or receipt['source_restoration'] != 'PASS'
                        or receipt.get('patch_sha256') is not None):
                    continue
                scope = set(_modules(receipt['modules']))
                covered.update(scope); receipts.append({'path': str(path), 'sha256': data['sha256'],
                                                       'modules': sorted(scope)})
            except (OSError, ValueError, KeyError, TypeError):
                continue  # Corrupt receipts grant no baseline credit.
        return {'status': 'PASS' if required <= covered else 'NEEDS_BASELINE',
                'covered_modules': sorted(required & covered), 'missing_modules': sorted(required - covered),
                'receipts': receipts, 'environment_id': identity['environment_id']}

    def store(self, identity, receipt):
        if (receipt.get('environment_id') != identity['environment_id']
                or receipt.get('phase') != 'baseline' or receipt.get('returncode') != 0
                or receipt.get('source_restoration') != 'PASS' or receipt.get('patch_sha256') is not None):
            raise ValueError('only unpatched, restored baseline successes may be cached')
        _modules(receipt['modules'])
        if not re.fullmatch(r'[0-9a-f]{32}', receipt.get('validation_id', '')):
            raise ValueError('invalid baseline validation identity')
        path = self.root / identity['environment_id'] / (receipt['validation_id'] + '.json')
        if path.exists():
            raise ValueError('baseline receipts are immutable')
        _write(path, {'sha256': canonical_hash(receipt), 'receipt': receipt})
        return str(path)


def _modules(modules):
    if (not isinstance(modules, (list, tuple)) or not modules
            or any(not isinstance(m, str) or not re.fullmatch(r'[A-Za-z0-9_.+-]+', m)
                   or m.startswith('-') for m in modules)):
        raise ValueError('an explicit nonempty module scope is required')
    return sorted(set(modules))


def build_contract_environment(identity, config, run_dir, *, validation_id=None):
    """Construct fresh non-secret contract fields; never inherit stale patches."""
    run_dir = Path(run_dir).resolve()
    env = dict(config['environment'])
    env.update({'AOSP_AGENT_SOURCE_ROOT': identity['source_root'],
                'AOSP_AGENT_OUT_DIR': str(Path(config['output_root']).resolve()),
                'AOSP_AGENT_TMPDIR': str(Path(config['tmp_root']).resolve()),
                'AOSP_AGENT_LUNCH': config['product'] + '-' + config['variant'],
                'AOSP_AGENT_EXPECTED_ARCH': config['arch'],
                'AOSP_AGENT_BUILD_LOCK': str(Path(config['baseline_cache']) / (identity['environment_id'] + '.build.lock')),
                'AOSP_AGENT_BUILD_ENVIRONMENT_ID': identity['environment_id'],
                'AOSP_AGENT_PYTHON': sys.executable,
                'AOSP_AGENT_RUN_DIR': str(run_dir),
                'AOSP_AGENT_VALIDATION_ID': validation_id or uuid.uuid4().hex,
                'AOSP_AGENT_ARTIFACT_DIR': str(run_dir / 'build-artifacts')})
    return env


@controller_audit('build_environment._source_snapshot')
def _source_snapshot(identity, *, receipt_path=None):
    from .discovery import local_git
    root = Path(identity['source_root']).resolve(); result = {}
    declared = {Path(item['resolved_path']) for item in identity['files'].values()}
    complete, error, proof = False, None, None
    inherited, inspected, git_bindings = [], [], {}
    try:
        proof = _source_view_proof(identity)
        manifest_files = verify_manifest_files(identity)
        for key, pin in identity['project_pins'].items():
            repo = (root / key).resolve()
            if not repo.is_relative_to(root):
                raise RecoveryBlocked('build repository escapes the isolated source view')
            if proof is not None and key in proof['repositories']:
                current = result[key] = deepcopy(proof['repositories'][key])
                if (not isinstance(current, dict) or current.get('head') != pin
                        or not isinstance(current.get('tree'), str)
                        or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', current['tree'])
                        or current.get('status') != ''
                        or current.get('index_flags_verified') is not True
                        or type(current.get('index_check_returncode')) is not int
                        or current['index_check_returncode'] != 0
                        or type(current.get('worktree_check_returncode')) is not int
                        or current['worktree_check_returncode'] != 0
                        or current.get('undeclared_ignored_files') != []
                        or not isinstance(current.get('ignored_files'), list)
                        or not isinstance(current.get('declared_ignored_inputs'), dict)
                        or set(current['ignored_files']) != set(current['declared_ignored_inputs'])):
                    raise RecoveryBlocked('sealed source audit is not a complete clean proof: ' + key)
                for name, evidence in current['declared_ignored_inputs'].items():
                    path = (repo / validate_relative_path(name)).resolve()
                    if path not in declared or evidence != file_identity(path):
                        raise RecoveryBlocked('sealed ignored input is not currently declared: ' + key + '/' + name)
                inherited.append(key)
                continue
            inspected.append(key)
            paths = local_git(repo, 'rev-parse', '--show-toplevel', '--absolute-git-dir',
                              '--git-common-dir').stdout.splitlines()
            if len(paths) != 3:
                raise RecoveryBlocked('build repository Git path binding is unavailable: ' + key)
            top, git_dir, common = [((Path(path) if Path(path).is_absolute() else repo / path).resolve())
                                   for path in paths]
            git_bindings[key] = {'worktree': str(top), 'git_dir': str(git_dir), 'common_dir': str(common)}
            if (top != repo or any(path == root or not path.is_relative_to(root) for path in (git_dir, common))
                    or proof is not None and (git_dir != repo / '.git' or common != repo / '.git')):
                raise RecoveryBlocked('build repository Git paths escape their controlled binding: ' + key)
            flags = local_git(repo, 'ls-files', '-v', '-z').stdout.split('\0')
            if any(len(entry) < 3 or entry[1] != ' ' or entry[0].islower() or entry[0] == 'S'
                   for entry in flags if entry):
                raise RecoveryBlocked('build source index has assume-unchanged/skip-worktree flags: ' + key)
            # --quiet performs full index/worktree comparisons without returning
            # the complete index on every audit; every command is still charged.
            refs = local_git(repo, 'rev-parse', 'HEAD', 'HEAD^{tree}').stdout.splitlines()
            current = result[key] = {'head': refs[0], 'tree': refs[1],
                'index_flags_verified': True,
                'status': local_git(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout,
                'index_check_returncode': local_git(repo, 'diff', '--cached', '--quiet', '--no-ext-diff',
                    '--no-textconv', 'HEAD', check=False).returncode,
                'worktree_check_returncode': local_git(repo, 'diff', '--quiet', '--no-ext-diff',
                    '--no-textconv', 'HEAD', check=False).returncode}
            ignored = local_git(repo, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').stdout
            current['ignored_files'] = sorted(p for p in ignored.split('\0') if p)
            undeclared = [p for p in current['ignored_files'] if (repo / p).resolve() not in declared]
            current['undeclared_ignored_files'] = undeclared
            current['declared_ignored_inputs'] = {p: file_identity((repo / p).resolve())
                for p in current['ignored_files'] if p not in undeclared}
            if (current['head'] != pin or current['status']
                    or current['index_check_returncode'] or current['worktree_check_returncode']):
                raise RecoveryBlocked('unpatched build view differs from its fixed clean vector: ' + key)
            if undeclared:
                raise BuildEnvironmentBlocked('undeclared ignored input in build source view: ' + key + '/' + undeclared[0])
        complete = True
        return result
    except BaseException as exc:
        error = str(exc)
        raise
    finally:
        if receipt_path is not None:
            _write(receipt_path, {'environment_id': identity['environment_id'],
                'status': 'PASS' if complete else 'UNVERIFIED', 'repositories': result, 'error': error,
                'manifest_files': manifest_files if 'manifest_files' in locals() else None,
                'audit_mode': 'immutable_base_with_project_work_layers' if 'source_view' in identity else
                              'legacy_full_vector',
                'inherited_repositories': inherited, 'inspected_repositories': inspected,
                'repository_git_bindings': git_bindings,
                'source_base': ({'base_id': proof['base_id'],
                    'base_receipt_sha256': proof['base_receipt_sha256'],
                    'runtime_mount_proof': proof['runtime_mount_proof']} if proof is not None else None)})


def run_baseline(identity, config, modules, run_dir, *, runner=None, use_cache=True):
    """Build missing module scope without a patch, under source and build locks.

    The caller must already have materialized the selected private source view.
    Failures are recorded per attempt and are never cached as permanent blocks.
    """
    from .validation_process import run_check
    from .retrieval import suspend_investigation_budget
    modules = _modules(modules); run_dir = Path(run_dir).resolve()
    config = validate_build_config(config)
    verify_environment_identity(identity, config)
    cache = BaselineCache(config['baseline_cache'])
    env = build_contract_environment(identity, config, run_dir)
    validation_id = env['AOSP_AGENT_VALIDATION_ID']
    for name in ('output_root', 'tmp_root'):
        Path(config[name]).mkdir(parents=True, exist_ok=True)
    Path(config['environment']['HOME']).mkdir(parents=True, exist_ok=True)
    Path(env['AOSP_AGENT_ARTIFACT_DIR']).mkdir(parents=True, exist_ok=True)
    with source_lease(identity['source_root'], ACTIVE_SOURCE_LEASE.get()), cache.locked(identity['environment_id']), suspend_investigation_budget():
        before_path = run_dir / ('source-before-' + validation_id + '.json')
        after_path = run_dir / ('source-after-' + validation_id + '.json')
        before = _source_snapshot(identity, receipt_path=before_path)
        cached = (cache.lookup(identity, modules) if use_cache else
                  {'missing_modules': modules, 'covered_modules': [], 'receipts': []})
        if not cached['missing_modules']:
            return {**cached, 'phase': 'baseline', 'cache_hit': True,
                    'modules': modules, 'source_restoration': 'PASS', 'returncode': 0,
                    'validation_id': validation_id, 'patch_sha256': None,
                    'source_audits': {'current': str(before_path)}}
        receipt = {'phase': 'baseline', 'environment_id': identity['environment_id'],
                   'validation_id': validation_id, 'patch_sha256': None,
                   'modules': cached['missing_modules'], 'requested_modules': modules,
                   'source_audits': {'before': str(before_path), 'after': str(after_path)},
                   'source_restoration': 'PENDING', 'cache_hit': False, 'started_at': time.time()}
        env['AOSP_AGENT_BASELINE_ACTIVE'] = '1'
        env['AOSP_AGENT_WORKTREE'] = str(run_dir)
        argv = [config['runner'], '--baseline', *receipt['modules']]
        receipt['argv'] = argv
        receipt_path = run_dir / ('baseline-' + validation_id + '.json')
        _write(receipt_path, receipt)
        lock_path = Path(env['AOSP_AGENT_BUILD_LOCK']); lock_path.parent.mkdir(parents=True, exist_ok=True)
        cleanup_unverified = False
        try:
            with lock_path.open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                stdout, stderr, code = (runner or run_check)(argv, identity['source_root'], env,
                                                             timeout=config['baseline_timeout'])
            from .output_budget import write_text
            stdout_path = run_dir / ('baseline-' + validation_id + '.stdout')
            stderr_path = run_dir / ('baseline-' + validation_id + '.stderr')
            write_text(stdout_path, stdout); write_text(stderr_path, stderr)
            receipt.update(returncode=code, stdout=stdout[-65536:], stderr=stderr[-65536:],
                           stdout_log=str(stdout_path), stderr_log=str(stderr_path), finished_at=time.time())
        except OSError as exc:
            receipt.update(returncode=127, stdout='', stderr=str(exc), error=type(exc).__name__, finished_at=time.time())
        except BaseException as exc:
            cleanup_unverified = isinstance(exc, RecoveryBlocked)
            receipt.update(returncode=130, error=type(exc).__name__, finished_at=time.time())
            raise
        finally:
            try:
                after = _source_snapshot(identity, receipt_path=after_path)
                receipt['source_restoration'] = ('UNVERIFIED' if cleanup_unverified else
                                                 'PASS' if after == before else 'FAIL')
            except Exception as exc:
                receipt.update(source_restoration='FAIL', restoration_error=str(exc))
            _write(receipt_path, receipt)
            if receipt['source_restoration'] != 'PASS':
                raise RecoveryBlocked('baseline build changed source or left its state unverified')
        receipt['classification'] = classify_build_failure(receipt, phase='baseline')
        _write(receipt_path, receipt)
        if receipt['returncode'] == 0 and use_cache:
            receipt['cache_receipt'] = cache.store(identity, receipt)
            receipt['scope_receipts'] = cache.lookup(identity, modules)['receipts']
        receipt['record'] = str(receipt_path)
        return receipt


def classify_build_failure(result, *, phase, baseline=None, changed_paths=(), coverage='complete'):
    """Do not feed environmental failures to the patch-writing strategy."""
    if result.get('source_restoration') not in ('PASS', 'NOT_NEEDED'):
        return {'status': 'RECOVERY_BLOCKED', 'repair_candidate': False, 'pause_batch': True}
    code = result.get('returncode')
    output = str(result.get('stdout', '')) + '\n' + str(result.get('stderr', ''))
    if code == 0:
        return {'status': 'PASS' if coverage == 'complete' else 'PASS_PARTIAL',
                'coverage': coverage, 'repair_candidate': False, 'pause_batch': False}
    if re.search(r'No space left on device|Disk quota exceeded|Cannot allocate memory', output, re.I):
        return {'status': 'HOST_RESOURCE_BLOCKED', 'repair_candidate': False, 'pause_batch': True}
    if code in (124, 125, 130, -9, -15) or re.search(r'timed out|temporarily unavailable', output, re.I):
        return {'status': 'BUILD_INTERRUPTED', 'repair_candidate': False, 'pause_batch': False}
    if phase == 'baseline':
        return {'status': 'BUILD_ENVIRONMENT_BLOCKED', 'repair_candidate': False,
                'pause_batch': False, 'retryable': False, 'permanent_cache': False}
    if (not baseline or baseline.get('returncode') != 0
            or not result.get('environment_id')
            or baseline.get('environment_id') != result.get('environment_id')
            or not set(result.get('modules', ())) <= set(baseline.get('requested_modules', baseline.get('modules', ())))):
        return {'status': 'BASELINE_UNVERIFIED', 'repair_candidate': False, 'pause_batch': False}
    diagnostics = []
    root_prefix = (re.escape(str(Path(result['source_root']).resolve())) + '/' if result.get('source_root') else None)
    for path in changed_paths:
        validate_relative_path(path)
        location = ('(?:' + root_prefix + ')?' if root_prefix else '') + re.escape(path)
        pattern = rf'(?m)(?:^|\s){location}:\d+(?::\d+)?:[^\n]*(?:error:|depends on undefined module)'
        diagnostics.extend(match.group(0).strip()[:1000] for match in re.finditer(pattern, output))
    if diagnostics:
        return {'status': 'CANDIDATE_CODE_ERROR', 'repair_candidate': True,
                'pause_batch': False, 'diagnostics': diagnostics}
    return {'status': 'BUILD_FAILURE_UNATTRIBUTED', 'repair_candidate': False, 'pause_batch': False}
