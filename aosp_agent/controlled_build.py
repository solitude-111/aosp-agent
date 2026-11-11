"""Connect prepared private views to baseline and exact-candidate validation."""
from contextlib import contextmanager, nullcontext
import json
from pathlib import Path

from .build_environment import (BuildEnvironmentBlocked, build_contract_environment,
    environment_identity, run_baseline, select_validation_vector, classify_build_failure)
from .build_graph import collect_ninja_coverage, ninja_log_checkpoint
from .patches import split_hunks


def managed_build(controller):
    prepared = getattr(controller, 'prepared_case', None)
    runner = getattr(controller, 'build_runner', None)
    return bool(prepared or runner and Path(runner).name in ('module-build-r760.sh', 'r760-build-module.sh'))


def changed_paths(controller, repositories=None):
    result = []
    for key, child in controller.children.items():
        if repositories is not None and key not in repositories:
            continue
        for hunk in split_hunks(child._render_patch()):
            for path in {hunk.get('new_path'), hunk.get('old_path')} - {None}:
                result.append(key + '/' + path)
    return sorted(set(result))


class ControlledBuild:
    def __init__(self, controller, prepared, identity, config):
        self.controller, self.prepared, self.identity, self.config = controller, prepared, identity, config
        self.directory = controller.run_dir / 'build-environment'
        self.directory.mkdir(parents=True, exist_ok=True)
        from .diff_engine import _write
        _write(self.directory / 'identity.json', identity)
        controller.record['build_environment'] = {
            'environment_id': identity['environment_id'], 'identity': str(self.directory / 'identity.json'),
            'preparation_receipt': str(prepared.receipt_path), 'selection': identity['selection'],
            'differences': identity['differences'], 'source_scope': 'prepared_private_view',
            'validation_manifest_scope': 'derived' if identity['differences'] else 'original',
            'original_manifest_validated': False, 'baseline_receipts': []}
        if 'source_view' in identity:
            controller.record['build_environment'].update(
                source_scope='immutable_base_with_project_work_layers', source_view=identity['source_view'])

    def graph_file(self):
        root = Path(self.config['output_root'])
        for path in (root / ('combined-' + self.config['product'] + '.ninja'),
                     root / ('build-' + self.config['product'] + '.ninja'), root / 'soong/build.ninja'):
            if path.is_file():
                return path
        return root / ('combined-' + self.config['product'] + '.ninja')

    def baseline(self, modules, *, purpose='modules'):
        receipt = run_baseline(self.identity, self.config, modules,
            self.directory / ('baseline-' + purpose), use_cache=purpose != 'graph')
        self.controller.record['build_environment']['baseline_receipts'].append(receipt)
        return receipt

    def audit(self):
        self.controller._audit(validation_pins=self.identity['project_pins'])

    def validation_bundle(self, bundle):
        from copy import deepcopy
        result = deepcopy(bundle)
        for dependency in result.get('dependencies', []):
            dependency['target_commit'] = self.identity['project_pins'][dependency['key']]
        return result

    def refine_checks(self, checks):
        # Use actual graph relations only for paths static discovery left open.
        missing = []
        if self.controller.auto_validation:
            for key, child in self.controller.children.items():
                path = child.record.get('validation_plan')
                if not path:
                    continue
                plan = json.loads(Path(path).read_text())
                missing.extend(key + '/' + p for p in plan.get('build', {}).get('uncovered', []))
        if not missing or not self.config.get('ninja'):
            return list(checks)
        baseline = self.baseline(['nothing'], purpose='graph')
        if baseline['returncode']:
            self.controller.record['build_environment']['graph_preparation_blocked'] = baseline['classification']
            classification = baseline['classification']
            raise BuildEnvironmentBlocked('unpatched build graph generation failed',
                kind=classification['status'], pause_batch=classification['pause_batch'])
        graph = collect_ninja_coverage(self.identity, self.config, self.graph_file(), missing,
            self.directory, build_receipt=baseline, require_executed=False, for_discovery=True)
        self.controller.record['runtime_build_discovery'] = graph
        if graph['status'] == 'GRAPH_UNAVAILABLE':
            raise BuildEnvironmentBlocked('the successful graph-generation command produced no matching graph',
                                          kind='BUILD_GRAPH_UNAVAILABLE')
        found = {}
        for row in graph.get('files', []):
            owner = next((key for key in sorted(self.controller.children, key=len, reverse=True)
                          if row['path'].startswith(key + '/')), None)
            for action in row['actions']:
                if owner:
                    found.setdefault(owner, set()).add(action['module'])
        from copy import deepcopy
        result = deepcopy(checks)
        for key, modules in sorted(found.items()):
            names = []
            for module in sorted(modules):
                existing = next((check for check in result if check['stage'] == 'android_module_build'
                    and check['argv'][0] == self.config['runner'] and module in check['argv'][1:]), None)
                if existing is None:
                    names.append(module)
                else:
                    existing['covers'] = sorted(set(existing['covers']) | {key})
                    existing.update(coverage='partial', discovered_from_graph=graph['record'])
            if names:
                result.append({'stage': 'android_module_build',
                    'argv': [self.config['runner'], *names], 'artifacts': [], 'covers': [key],
                    'coverage': 'partial', 'discovered_from_graph': graph['record']})
        return result

    def prepare_check(self, check):
        if Path(check['argv'][0]).resolve() != Path(self.config['runner']).resolve():
            raise BuildEnvironmentBlocked('controlled builds cannot cache arbitrary verification commands')
        baseline = self.baseline(check['argv'][1:])
        if baseline['returncode']:
            return baseline, None, None
        from .build_environment import _source_snapshot
        import uuid
        self.source_audit_id = uuid.uuid4().hex
        self.source_before_candidate = _source_snapshot(self.identity,
            receipt_path=self.directory / ('candidate-source-before-' + self.source_audit_id + '.json'))
        from .build_environment import file_identity
        graph = self.graph_file()
        self.graph_before_candidate = file_identity(graph) if graph.is_file() else None
        checkpoint = ninja_log_checkpoint(Path(self.config['output_root']) / '.ninja_log')
        env = build_contract_environment(self.identity, self.config, self.controller.run_dir)
        return baseline, checkpoint, env

    def finish_check(self, check, result, baseline, checkpoint, transaction):
        from .build_environment import _source_snapshot
        from .lifecycle import RecoveryBlocked
        try:
            after = _source_snapshot(self.identity,
                receipt_path=self.directory / ('candidate-source-after-' + self.source_audit_id + '.json'))
        except Exception as exc:
            raise RecoveryBlocked('candidate build left the complete prepared source vector unverified') from exc
        if after != self.source_before_candidate:
            raise RecoveryBlocked('candidate build changed the complete prepared source vector')
        result.update(environment_id=self.identity['environment_id'], modules=check['argv'][1:],
            baseline=baseline, source_restoration=transaction.get('restore', 'UNVERIFIED'),
            source_root=self.identity['source_root'], patch_sha256=result.get('bundle_sha256'),
            source_audits={name: str(self.directory / ('candidate-source-' + name + '-' + self.source_audit_id + '.json'))
                           for name in ('before', 'after')})
        coverage = check.get('coverage', 'complete')
        if result['returncode'] == 0:
            graph = collect_ninja_coverage(self.identity, self.config, self.graph_file(),
                changed_paths(self.controller, check['covers']), self.directory,
                build_receipt=result, before_log=checkpoint)
            result['source_action_evidence'] = graph
            if not graph.get('complete_for_requested_sources'):
                coverage = 'partial'
            result['coverage'] = coverage
            from .build_environment import file_identity
            graph_path = self.graph_file()
            after_graph = file_identity(graph_path) if graph_path.is_file() else None
            result['graph_regeneration'] = {'before': self.graph_before_candidate, 'after': after_graph,
                'status': 'OBSERVED_CHANGED_GRAPH' if after_graph and after_graph != self.graph_before_candidate
                          else 'NOT_ESTABLISHED',
                'limitation': 'Graph bytes alone do not establish full build-metadata or product coverage.'}
        result['classification'] = classify_build_failure(result, phase='candidate', baseline=baseline,
            changed_paths=changed_paths(self.controller, check['covers']), coverage=coverage)
        result['validation_manifest_scope'] = 'derived' if self.identity['differences'] else 'original'
        result['original_manifest_validated'] = (not self.identity['differences']
            and result['returncode'] == 0 and coverage != 'partial')
        if result['classification']['status'] == 'RECOVERY_BLOCKED':
            from .diff_engine import _write
            _write(self.directory / 'candidate-restoration-blocked.json', result)
            raise RecoveryBlocked('candidate build restoration receipt is missing or unverified')
        return result


@contextmanager
def controlled_build_session(controller):
    if not managed_build(controller):
        yield None
        return
    prepared = getattr(controller, 'prepared_case', None)
    if prepared is None:
        raise BuildEnvironmentBlocked('a configured prepared private build view is required; use the unattended entrypoint')
    config = prepared.manager.config['build']
    if not config.get('enabled'):
        raise BuildEnvironmentBlocked('controlled build verification is disabled')
    protected = {key: child.case.target_commit for key, child in controller.children.items() if child.case.files}
    from .preparation import PreparationError
    try:
        if 'source_view' in prepared.environment:
            prepared.ensure_writable(protected.keys())
        prepared.materialize_all()
    except PreparationError as exc:
        raise BuildEnvironmentBlocked('fixed build view cannot be prepared: ' + str(exc)) from exc
    selection = select_validation_vector(prepared.environment['project_pins'], protected,
                                          config.get('compatibility_mappings', []))
    controller._audit()
    with _prepared_validation_view(prepared, selection) as environment:
        revalidate_dependency_trees(controller, selection)
        identity = environment_identity(environment, config, protected)
        yield ControlledBuild(controller, prepared, identity, config)


@contextmanager
def _prepared_validation_view(prepared, selection):
    from .preparation import PreparationError
    view = (prepared.validation_view(selection['project_pins']) if selection['differences']
            else nullcontext(prepared.environment))
    try:
        with view as environment:
            yield environment
    except PreparationError as exc:
        raise BuildEnvironmentBlocked('compatible build view cannot be prepared: ' + str(exc)) from exc


def revalidate_dependency_trees(controller, selection):
    """Rebind identical source trees without treating changed code as equivalent.

    A commit-message/parent-only change leaves all source evidence intact. Any
    actual tree change invalidates only that dependency's evidence and requires
    the impact stage; the build layer never invents a semantic equivalence.
    """
    from .discovery import local_git
    from .diff_engine import _write
    changed = sorted(set(selection['differences']) & set(controller.by_key))
    if not changed:
        return
    entries, unresolved = {}, []
    for key in changed:
        before, after = selection['original_project_pins'][key], selection['project_pins'][key]
        repo = controller.by_key[key].root
        old_tree = local_git(repo, 'rev-parse', '--verify', before + '^{tree}').stdout.strip()
        new_tree = local_git(repo, 'rev-parse', '--verify', after + '^{tree}').stdout.strip()
        same = old_tree == new_tree
        entries[key] = {'original_commit': before, 'validation_commit': after,
            'original_tree': old_tree, 'validation_tree': new_tree,
            'status': 'TREE_EQUIVALENT' if same else 'REQUIRED'}
        if not same:
            unresolved.append(key)
    record = {'status': 'REQUIRED' if unresolved else 'TREE_EQUIVALENT',
        'repositories': entries, 'invalidated_repositories': unresolved,
        'original_project_pins': selection['original_project_pins'], 'project_pins': selection['project_pins'],
        'basis': 'Exact immutable Git tree identity; no semantic inference across changed source.'}
    path = controller.run_dir / 'dependency-evidence-revalidation.json'
    _write(path, record)
    controller.record['dependency_evidence_revalidation'] = {**record, 'record': str(path)}
    if unresolved:
        raise BuildEnvironmentBlocked('compatible environment needs impact-evidence revalidation: ' + ', '.join(unresolved))
