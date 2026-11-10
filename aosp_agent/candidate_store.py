"""Immutable candidate bytes and attempt provenance, independent of delivery.

The case controller owns this store across repositories, replanning and resume.
An archived candidate is never a validation receipt. In particular, the latest
attempt, latest bytes, replayable bytes and deliverable bytes are separate views.
"""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from .lifecycle import RecoveryBlocked
from .output_budget import find_budget, write_bytes, OutputBudgetExceeded


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def agent_identity(agent):
    from .execution_budget import ACTIVE_EXECUTION
    repository = agent.mapping_repository or agent.case.repository
    targets = {repository: agent.record.get('target_commit', agent.case.target_commit)}
    if agent.mapping_plan is not None:
        targets = dict(agent.mapping_plan.data().get('targets') or targets)
    source = {'source_commit': agent.case.source_commit, 'source_parent': agent.case.source_parent,
              'donor_repository': agent.case.donor_repository or agent.case.repository}
    if agent.mapping_plan is not None:
        # One verified donor input may map to several differently named targets.
        source.pop('donor_repository')
    handoff = getattr(agent, 'location_handoff', None)
    if handoff:
        source['input_patch_sha256'] = handoff.controller.record['input_patch_sha256']
    elif agent.input_diff is not None:
        source['input_patch_sha256'] = hashlib.sha256(agent.input_diff.encode()).hexdigest()
    ledger = ACTIVE_EXECUTION.get()
    if ledger is not None:
        source = {'input_sha256': ledger.snapshot()['input_sha256']}
    return {'source': source, 'targets': targets, 'repository': repository}


def for_agent(agent):
    current = getattr(agent, '_candidate_store', None)
    if current is None:
        from .execution_budget import ACTIVE_EXECUTION
        ledger = ACTIVE_EXECUTION.get()
        current = CandidateStore((ledger.root if ledger is not None else agent.run_dir) / 'candidate-store')
        agent._candidate_store = current
    return current


class CandidateStore:
    VERSION = 1

    def __init__(self, root):
        supplied = Path(root)
        if supplied.is_symlink():
            raise RecoveryBlocked('candidate store must not be a symlink')
        self.root = supplied.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / 'index.json'
        with self._locked() as value:
            if not self.path.exists():
                self._save(value)

    @contextmanager
    def _locked(self):
        fd = os.open(self.root / 'index.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            if self.path.is_symlink():
                raise RecoveryBlocked('candidate index must not be a symlink')
            if self.path.exists():
                try:
                    value = json.loads(self.path.read_text())
                    if value.get('version') != self.VERSION:
                        raise ValueError('unsupported candidate index version')
                    for key in ('attempts', 'candidates', 'bundles'):
                        if not isinstance(value.get(key), dict):
                            raise ValueError('invalid candidate index ' + key)
                except (OSError, ValueError, TypeError) as exc:
                    raise RecoveryBlocked('cannot read candidate index: ' + str(exc)) from exc
            else:
                value = {'version': self.VERSION, 'attempts': {}, 'candidates': {}, 'bundles': {}}
            yield value

    def _save(self, value):
        data = (json.dumps(value, ensure_ascii=False, sort_keys=True) + '\n').encode()
        budget = find_budget(self.path)
        # Index records need their exact schema even when the ordinary log budget
        # is exhausted; the run.json compactor must not rewrite this document.
        if budget is not None:
            try:
                saved = budget.write(self.path, data, control=budget.data()['exhausted'])
            except OutputBudgetExceeded:
                saved = budget.write(self.path, data, control=True)
        else:
            saved = write_bytes(self.path, data)
        if saved is False or not self.path.is_file() or self.path.read_bytes() != data:
            raise RecoveryBlocked('candidate index was not durably saved')
        self._sync(self.path)

    def _sync(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _artifact(self, relative, data):
        path = self.root / relative
        if path.is_symlink() or not path.parent.resolve().is_relative_to(self.root):
            raise RecoveryBlocked('candidate artifact escapes its store')
        if path.exists():
            if path.read_bytes() != data:
                raise RecoveryBlocked('immutable candidate artifact changed: ' + relative)
        else:
            saved = write_bytes(path, data)
            if saved is False or not path.is_file() or path.read_bytes() != data:
                raise RecoveryBlocked('candidate artifact was not durably saved')
            self._sync(path)
        return relative

    def begin(self, identity, *, source_record, source_kind='model', strategy=None, parent=None,
              operation_id=None, recovery=None):
        with self._locked() as value:
            ident = uuid.uuid4().hex
            if parent is not None and (parent not in value['candidates'] or value['candidates'][parent]['identity'] != identity):
                raise RecoveryBlocked('candidate parent does not match the current pinned inputs')
            value['attempts'][ident] = {'id': ident, 'sequence': len(value['attempts']) + 1,
                'identity': deepcopy(identity),
                'source_record': str(source_record), 'source_kind': source_kind, 'strategy': strategy,
                'parent_candidate_id': parent, 'operation_id': operation_id, 'started_at': time.time(),
                'status': 'STARTED', 'candidate_id': None}
            if recovery is not None:
                value['attempts'][ident]['recovery'] = deepcopy(recovery)
            self._save(value)
            return ident

    def observe(self, attempt_id, patch, *, source_kind=None, outcome='EXPORTED'):
        data = patch.encode() if isinstance(patch, str) else patch
        with self._locked() as value:
            attempt = value['attempts'][attempt_id]
            attempt['status'] = outcome
            attempt['updated_at'] = time.time()
            if not data.strip():
                attempt.update(candidate_id=None, change='NO_NEW_CANDIDATE')
                self._save(value)
                return None
            sha = hashlib.sha256(data).hexdigest()
            ident = digest({'identity': attempt['identity'], 'patch_sha256': sha})
            relative = self._artifact('patches/' + ident + '.patch', data)
            new = ident not in value['candidates']
            if new:
                value['candidates'][ident] = {'id': ident, 'identity': deepcopy(attempt['identity']),
                    'patch_sha256': sha, 'artifact': relative, 'created_at': time.time(),
                    'source_kind': source_kind or attempt['source_kind'], 'created_by': attempt_id,
                    'created_sequence': len(value['candidates']) + 1,
                    'parent_candidate_id': attempt['parent_candidate_id'], 'evidence': []}
            attempt.update(candidate_id=ident, change='NEW_CANDIDATE' if new else 'NO_NEW_CANDIDATE')
            self._save(value)
            return ident

    def finish(self, attempt_id, *, status, error=None):
        with self._locked() as value:
            row = value['attempts'][attempt_id]
            row.update(status=status, finished_at=time.time())
            if error:
                row['error'] = deepcopy(error)
            self._save(value)

    def evidence(self, candidate_id, kind, receipt):
        with self._locked() as value:
            candidate = value['candidates'][candidate_id]
            if receipt.get('patch_sha256') != candidate['patch_sha256']:
                raise RecoveryBlocked('candidate evidence hash does not match archived bytes')
            if kind == 'replay' and receipt.get('target_commit') != candidate['identity']['targets'].get(candidate['identity']['repository']):
                raise RecoveryBlocked('candidate replay target does not match its pinned identity')
            if kind == 'delivery' and receipt.get('status') == 'VALIDATED' and not (
                    receipt.get('delivery', {}).get('status') == 'READY_FOR_HANDOFF'
                    and receipt.get('build_validation', {}).get('status') == 'PASS'
                    and receipt.get('build_validation', {}).get('candidate_bound') is True
                    and receipt.get('review_status', {}).get('status') == 'PASSED'):
                raise RecoveryBlocked('candidate lacks controller delivery evidence')
            data = (json.dumps(receipt, sort_keys=True, ensure_ascii=False) + '\n').encode()
            sha = hashlib.sha256(data).hexdigest()
            relative = self._artifact('evidence/' + sha + '.json', data)
            reference = {'kind': kind, 'artifact': relative, 'sha256': sha,
                         'status': receipt.get('status'), 'recorded_at': time.time()}
            # Same receipt is not new proof; preserve its original provenance.
            if not any(row['kind'] == kind and row['sha256'] == sha for row in candidate['evidence']):
                candidate['evidence'].append(reference)
                self._save(value)

    def bundle(self, candidate_ids, *, source_record):
        with self._locked() as value:
            rows = [value['candidates'][ident] for ident in candidate_ids]
            if not rows or len({r['identity']['repository'] for r in rows}) != len(rows):
                raise RecoveryBlocked('bundle requires distinct candidate repositories')
            if any(r['identity']['targets'] != rows[0]['identity']['targets']
                   or r['identity']['source'] != rows[0]['identity']['source'] for r in rows):
                raise RecoveryBlocked('bundle candidates have different pinned inputs')
            members = {r['identity']['repository']: r['id'] for r in rows}
            ident = digest({'members': members, 'targets': rows[0]['identity']['targets']})
            if ident not in value['bundles']:
                value['bundles'][ident] = {'id': ident, 'members': members,
                    'targets': rows[0]['identity']['targets'], 'source_record': str(source_record),
                    'status': 'UNVERIFIED', 'created_at': time.time()}
                self._save(value)
            return ident

    def bundle_evidence(self, bundle_id, receipt):
        """Bind controller verification to one exact bundle, never mixed members."""
        from .delivery import update_delivery
        with self._locked() as value:
            bundle = value['bundles'][bundle_id]
            hashes = {key: value['candidates'][ident]['patch_sha256'] for key, ident in bundle['members'].items()}
            if {key: row.get('sha256') for key, row in receipt.get('patches', {}).items()} != hashes:
                raise RecoveryBlocked('bundle evidence references different candidate bytes')
            checked = update_delivery(deepcopy(receipt))
            if receipt.get('status') == 'VALIDATED' and checked['status'] != 'VALIDATED':
                raise RecoveryBlocked('bundle lacks controller delivery evidence')
            data = (json.dumps(checked, sort_keys=True, ensure_ascii=False) + '\n').encode()
            sha = hashlib.sha256(data).hexdigest()
            relative = self._artifact('evidence/' + sha + '.json', data)
            reference = {'artifact': relative, 'sha256': sha, 'status': checked['status'],
                         'recorded_at': time.time()}
            proofs = bundle.setdefault('evidence', [])
            if not any(proof['sha256'] == sha for proof in proofs):
                proofs.append(reference)
                bundle['status'] = checked['status']
                self._save(value)
        # Member views retain the enclosing bundle identity. This is evidence
        # from a controller decision, not independent approval of each member.
        for key, ident in bundle['members'].items():
            self.evidence(ident, 'delivery', {name: checked[name] for name in
                ('status', 'delivery', 'build_validation', 'review_status') if name in checked} | {
                    'patch_sha256': hashes[key], 'bundle_id': bundle_id,
                    'bundle_receipt_sha256': sha, 'scope': 'member_of_exact_bundle'})

    def snapshot(self):
        with self._locked() as value:
            return deepcopy(value)

    def summary(self, identity=None):
        value = self.snapshot()
        attempts = sorted((a for a in value['attempts'].values() if identity is None or a['identity'] == identity),
                          key=lambda row: row['sequence'])
        ids = [a['candidate_id'] for a in attempts if a['candidate_id']]
        replayable, eligible = None, None
        for ident in ids:
            for proof in value['candidates'][ident]['evidence']:
                if proof['kind'] == 'replay' and proof['status'] == 'pass':
                    replayable = ident
                if proof['kind'] == 'delivery' and proof['status'] == 'VALIDATED':
                    eligible = ident
        return {'index': str(self.path), 'last_attempt': attempts[-1]['id'] if attempts else None,
                'latest_candidate': ids[-1] if ids else None,
                'latest_replayable_candidate': replayable,
                'latest_delivery_eligible_candidate': eligible,
                'candidate_count': len(set(ids)), 'attempt_count': len(attempts)}

    def load(self, candidate_id, identity):
        value = self.snapshot()
        row = value['candidates'].get(candidate_id)
        if row is None or row['identity'] != identity:
            raise RecoveryBlocked('candidate does not match the current pinned inputs')
        path = self.root / row['artifact']
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise RecoveryBlocked('candidate artifact escapes its store')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != row['patch_sha256']:
            raise RecoveryBlocked('candidate artifact checksum mismatch')
        return data.decode('utf-8')

    def restore(self, agent, candidate_id):
        """Restore bytes into a fresh baseline; callers must repeat every gate.

        No replay/build/coverage receipt is copied to the new agent. This method
        never chooses the historical candidate on the operator's behalf.
        """
        from .engine import _assert_patch_paths
        identity = agent_identity(agent)
        saved = self.snapshot()['candidates'].get(candidate_id)
        if saved is None:
            raise RecoveryBlocked('requested resume candidate is missing')
        patch = self.load(candidate_id, saved['identity'])
        agent.audit_diff(require_clean=True)
        def incompatible(reason):
            agent.record['restored_candidate'] = {'id': candidate_id, 'status': 'INCOMPATIBLE',
                'reason': reason, 'prior_validation_reused': False}
            agent._write_record()
            return None
        if saved['identity'] != identity:
            return incompatible('PINNED_INPUTS_CHANGED')
        try:
            _assert_patch_paths(patch, set(agent.case.files))
        except (ValueError, RuntimeError):
            return incompatible('EDIT_SCOPE_CHANGED')
        if agent._git('apply', '--check', '--binary', '-', cwd=agent.worktree, input=patch, check=False).returncode:
            return incompatible('REPLAY_NOT_APPLICABLE')
        agent._git('apply', '--binary', '-', cwd=agent.worktree, input=patch)
        try:
            audit = agent.audit_diff()
            gate = agent._new_file_integration_audit(audit, patch)
            reason = ('SOURCE_INTEGRATION_CHANGED' if gate['status'] != 'PASS' else
                      'REPLAY_BYTES_CHANGED' if agent._render_patch(audit) != patch else None)
        except Exception:
            self._undo_restore(agent, patch)
            raise
        if reason:
            self._undo_restore(agent, patch)
            return incompatible(reason)
        agent.record['restored_candidate'] = {'id': candidate_id, 'patch_sha256': hashlib.sha256(patch.encode()).hexdigest(),
                                             'status': 'DRAFT', 'prior_validation_reused': False}
        agent._write_record()
        return patch

    def _undo_restore(self, agent, patch):
        try:
            agent._git('apply', '--reverse', '--binary', '-', cwd=agent.worktree, input=patch)
            agent.audit_diff(require_clean=True)
        except Exception as exc:
            raise RecoveryBlocked('resume candidate rollback could not be verified') from exc


def archive_controller_candidates(controller, *, final=False):
    """Index only the controller's exported final vector and its exact receipts."""
    from .execution_budget import ACTIVE_EXECUTION
    ledger = ACTIVE_EXECUTION.get()
    store = CandidateStore((ledger.root if ledger else controller.run_dir) / 'candidate-store')
    ids = {}
    for key, exported in controller.record.get('patches', {}).items():
        child = controller.children[key]
        path = Path(exported['file'])
        if path.is_symlink() or not path.resolve().is_relative_to(child.run_dir.resolve()):
            raise RecoveryBlocked('controller candidate path escapes its repository run')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != exported['sha256'] or not data.strip():
            raise RecoveryBlocked('controller candidate bytes changed before aggregation')
        identity = agent_identity(child)
        ident = digest({'identity': identity, 'patch_sha256': exported['sha256']})
        if ident not in store.snapshot()['candidates']:
            attempt = store.begin(identity, source_record=child.run_dir / 'run.json',
                                  source_kind='controller_aggregation')
            ident = store.observe(attempt, data)
            store.finish(attempt, status=child.record['status'])
        else:
            store.load(ident, identity)
        replay = child.record.get('patch_replay_evidence')
        if replay:
            store.evidence(ident, 'replay', {**replay, 'patch_sha256': exported['sha256']})
        verification = child.record.get('final_verification')
        if verification and verification.get('patch_sha256') == exported['sha256']:
            store.evidence(ident, 'verification', verification)
        ids[key] = ident
    if ids:
        bundle = store.bundle(list(ids.values()), source_record=controller.run_dir / 'run.json')
        controller.record['candidate_bundle_id'] = bundle
        if final:
            keys = ('status', 'patches', 'verification', 'joint_verification', 'candidate_bundle_sha256',
                    'post_fix_review', 'post_fix_impact', 'completion_blocked_by')
            receipt = {key: controller.record[key] for key in keys if key in controller.record}
            receipt['source_record'] = str(controller.run_dir / 'run.json')
            store.bundle_evidence(bundle, receipt)
    controller.record['candidate_ids'] = ids
    controller.record['candidate_history'] = store.summary()


def recover_stopped_candidates(record_path):
    """Salvage registered controller-broker writes after a stopped execution.

    The caller holds the prior run lease and a newly acquired source lease.
    Unlike PID checks, that inherited source lease also excludes still-running
    verifier/restoration children. Broker writes execute in the controller, and
    its SDK has no native command/edit tools; unknown writer policies block.
    """
    from .case import validate_relative_path
    from .discovery import local_git
    from .engine import _assert_patch_paths
    from .lifecycle import ACTIVE_SOURCE_LEASE
    from .resume import verify_stopped_sources
    from .runtime_children import require_stopped

    path = Path(record_path).resolve()
    record = json.loads(path.read_text())
    owner_root = path.parent
    lineage_root = Path(record.get('execution_budget', {}).get('root', owner_root)).resolve()
    location = lineage_root / 'candidate-store'
    if not (location / 'index.json').exists():
        return {'status': 'NOTHING_TO_RECOVER', 'attempts': []}
    lease = ACTIVE_SOURCE_LEASE.get()
    if lease is None:
        raise RecoveryBlocked('candidate recovery requires the stopped source lease')
    store = CandidateStore(location)
    recovered = []
    verify_stopped_sources(owner_root)
    for attempt in store.snapshot()['attempts'].values():
        if (attempt['status'] != 'STARTED' or attempt.get('finished_at')
                or not Path(attempt['source_record']).resolve().is_relative_to(owner_root)):
            continue
        recovery = attempt.get('recovery') or {}
        if recovery.get('writer_policy') != 'controller_broker_only':
            raise RecoveryBlocked('interrupted candidate writer cleanup is unverified: ' + attempt['id'])
        runtime_cleanup = require_stopped(recovery.get('runtime_child'), owner_root)
        source_root = Path(recovery['source_root']).resolve()
        lease.require(root=source_root)
        workspace_path = Path(recovery['worktree'])
        worktree = workspace_path.resolve()
        if (workspace_path.is_symlink() or not worktree.is_relative_to(owner_root)
                or worktree.is_relative_to(source_root)):
            raise RecoveryBlocked('interrupted candidate worktree escapes its stopped run')
        source_repo = Path(recovery['source_repo']).resolve()
        if not source_repo.is_relative_to(source_root):
            raise RecoveryBlocked('interrupted candidate source repository escapes its source lease')
        source = {'head': local_git(source_repo, 'rev-parse', 'HEAD').stdout.strip(),
                  'status': local_git(source_repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout,
                  'diff_sha256': hashlib.sha256(local_git(source_repo, 'diff', '--binary', 'HEAD').stdout.encode()).hexdigest()}
        if source != recovery['source_state']:
            raise RecoveryBlocked('interrupted candidate original checkout changed')
        target = recovery['target_commit']
        if target != attempt['identity']['targets'].get(attempt['identity']['repository']):
            raise RecoveryBlocked('interrupted candidate target identity changed')
        if local_git(worktree, 'rev-parse', 'HEAD').stdout.strip() != target:
            raise RecoveryBlocked('interrupted candidate moved its HEAD')
        allowed = set(recovery['allowlist'])
        for relative in allowed:
            validate_relative_path(relative)
            candidate = worktree / relative
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(worktree):
                raise RecoveryBlocked('unsafe interrupted candidate path: ' + relative)
        tracked = set(filter(None, local_git(worktree, 'diff', '--name-only', '-z', '--no-renames', target).stdout.split('\0')))
        untracked = set(filter(None, local_git(worktree, 'ls-files', '--others', '--exclude-standard', '-z').stdout.split('\0')))
        artifacts = set(recovery.get('artifact_paths', []))
        untracked = {name for name in untracked - artifacts if not name.startswith('out-artifacts/')}
        ignored = local_git(worktree, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').stdout
        if (tracked | untracked) - allowed:
            raise RecoveryBlocked('interrupted candidate changed files outside its allowlist')
        if any(name and name not in artifacts and not name.startswith('out-artifacts/') for name in ignored.split('\0')):
            raise RecoveryBlocked('interrupted candidate contains unexpected ignored files')
        if local_git(worktree, 'diff', '--check', target, check=False).returncode:
            raise RecoveryBlocked('interrupted candidate failed the diff audit')
        patch = local_git(worktree, 'diff', '--binary', '--no-ext-diff', '--no-renames', target).stdout
        for relative in sorted(untracked):
            added = local_git(worktree, 'diff', '--no-index', '--binary', '--', '/dev/null', relative, check=False)
            if added.returncode not in (0, 1):
                raise RecoveryBlocked('cannot export interrupted candidate file: ' + relative)
            patch += added.stdout
        if patch.strip():
            _assert_patch_paths(patch, allowed)
        ident = store.observe(attempt['id'], patch, source_kind='recovered_workspace', outcome='INTERRUPTED_DRAFT')
        store.finish(attempt['id'], status='INTERRUPTED', error={'kind': 'PROCESS_EXITED',
            'message': 'Recovered raw bytes after source lease and workspace audit; validation remains unperformed.',
            'runtime_cleanup': runtime_cleanup})
        recovered.append({'attempt_id': attempt['id'], 'candidate_id': ident, 'status': 'DRAFT' if ident else 'NO_NEW_CANDIDATE'})
    return {'status': 'RECOVERED' if recovered else 'NOTHING_TO_RECOVER', 'attempts': recovered}
