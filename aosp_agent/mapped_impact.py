"""Bind the common causal proof contract to complete, namespaced mapping units.

Core repairs need the same causal checks as the donor run backend. Support
changes retain both their own evidence and an explicit grounded link to a core
repair. They never disappear from mapping, migration coverage or the hunk ledger.
"""
from pathlib import Path
import subprocess

from .discovery import Repository
from .impact_proof import AssessmentError, CausalityChecks
from .mapping_plan import _excerpt
from .prompts import parse_impact_response
from .retrieval import LazyTree
from .scope_evidence import ground_evidence, _mapped_anchor


class ImpactProofError(AssessmentError):
    pass


PROOF_CONTEXT = '''
Provide proof_groups for the complete repair input using the impact schema.
Every source unit must occur exactly once in one group. Groups may combine
dependent source steps, but each group's units must have the same impact status.
Use separate groups for independent repairs or different impact decisions.
primary_unit_ids name the core repair units; each AFFECTED core requires its own
changed donor-parent/fix evidence and executable target fault/harm evidence in
the causal_chain. All evidence entries name their exact unit_id, including the
source namespace (sNNN:...) when present. Never borrow evidence from a different
source step merely because the file name or line number is the same.
Other units are explicit support_links to primary units, with a reason and
1-based impact.evidence indices citing the support unit's available donor sides,
its target behavior and the target behavior of every supported primary unit.
This represents prerequisites, helper integration, tests and configuration,
not permission to discard difficult changes. A group cannot consist only of
support units. Every mapped target region and each available source side must
be cited by the proof steps, causal chain or support links, not unused padding.
The scope contract uses the same authorization_boundary, resource_bound,
persistent_state_pollution or generic_data_flow obligations as the run backend.
Unresolved required behavior remains UNKNOWN. Do not claim AFFECTED from
uncited framework assumptions. Negative conclusions still need independent
exclusion review. Exact excerpts establish provenance, not formal semantics.
Platform behavior needs implementation_evidence indices citing actual definitions
at the pinned target, separate from relied_at_evidence call sites. These may be
read_dependency mappings in admitted projects, included in scope_closure and
dependencies_checked but never edit targets merely to cite behavior. API names and
model prose alone cannot establish behavior; missing decisive evidence is UNKNOWN.
'''


class MappedProofChecks(CausalityChecks):
    def __init__(self, controller, units):
        self.controller = controller
        self._current_hunks = list(units)
        self._causality_repository_roots = {r.key.split('/')[0] for r in controller.repos}
        self.sources = ({s['id']: s for s in controller.donor['steps']}
                        if controller.donor['status'] == 'VERIFIED_SEQUENCE' else
                        {'': controller.donor} if controller.donor['status'] == 'VERIFIED' else {})
        self.donor_readers = {}

    def ground(self, entry, unit, mapped):
        if entry['revision'] == 'target':
            repo, path = self.controller._owner(entry['path'])
            _excerpt(repo.read(path).splitlines(), entry)
            normalized = {**entry, 'origin': 'target'}
            if not _mapped_anchor(normalized, mapped['targets']):
                raise ImpactProofError('causal target evidence is outside its unit mapping')
            return
        side = 'before' if entry['revision'] == 'source_parent' else 'after'
        source_path = unit['old_path'] if side == 'before' else unit['new_path']
        if entry['path'] != source_path:
            raise ImpactProofError('causal donor evidence path is not this unit diff side')
        source_id = unit.get('source_id', '')
        provenance = self.sources.get(source_id)
        if provenance is None:
            ground_evidence(self.controller, unit['id'], {**entry,
                'origin': 'patch_before' if side == 'before' else 'patch_after'})
            return
        commit = provenance['source_parent' if side == 'before' else 'source_commit']
        key = source_id, commit
        if key not in self.donor_readers:
            root = Path(provenance['donor_git'])
            self.donor_readers[key] = Repository('donor', root, commit,
                LazyTree(root, commit, self.controller.object_cache))
        _excerpt(self.donor_readers[key].read(entry['path']).splitlines(), entry)


def check_impact_proofs(controller, assessment, required=False):
    try:
        return _check(controller, assessment, required)
    except ImpactProofError:
        raise
    except (AssessmentError, ValueError, OSError, subprocess.SubprocessError) as exc:
        raise ImpactProofError(str(exc)) from exc


def _check(controller, assessment, required):
    groups = assessment.get('proof_groups') or []
    if not groups and not required:
        return {'status': 'NOT_REQUESTED_LEGACY', 'runtime_security_proven': False}
    units = {u['id']: u for u in controller.units}
    mapped = {u['id']: u for u in assessment['units']}
    assigned = [ident for g in groups for ident in g['unit_ids']]
    if len(assigned) != len(units) or set(assigned) != set(units):
        raise ImpactProofError('causal proof groups must cover every source unit exactly once')
    if len({g['id'] for g in groups}) != len(groups):
        raise ImpactProofError('causal proof group IDs must be unique')
    checks = MappedProofChecks(controller, units.values())
    receipts = []
    for group in groups:
        members, primaries = set(group['unit_ids']), set(group['primary_unit_ids'])
        if (not primaries or not primaries <= members or len(primaries) != len(group['primary_unit_ids'])):
            raise ImpactProofError('each causal group needs unique primary units from its own members')
        support = group['support_links']
        if len(support) != len(members - primaries) or {s['unit_id'] for s in support} != members - primaries:
            raise ImpactProofError('every non-primary unit needs exactly one explicit support link')
        raw = group['impact']
        if {mapped[u]['status'] for u in members} != {raw['status']}:
            raise ImpactProofError('causal group status conflicts with mapped unit status')
        # Parse with the original contract, then restore only the independently
        # checked namespace metadata. The common validator sees identical rules.
        proof = parse_impact_response({**raw, 'evidence': [
            {k: v for k, v in e.items() if k != 'unit_id'} for e in raw['evidence']]})
        proof['evidence'] = [dict(e) for e in raw['evidence']]
        evidence = proof['evidence']
        for entry in evidence:
            if entry['unit_id'] not in members:
                raise ImpactProofError('causal evidence belongs to another source unit/group')
            checks.ground(entry, units[entry['unit_id']], mapped[entry['unit_id']])
        checks._current_hunks = [units[u] for u in members]
        checks._validate_impact_causality(proof)
        if proof['status'] != 'UNKNOWN' and not any(e['revision'] != 'target' for e in evidence):
            raise ImpactProofError('determinate causal group requires donor evidence')

        used = {i for step in proof['proof_steps'] for i in step['evidence']}
        chain = proof.get('causal_chain') or {}
        fields = ('donor_fault_evidence', 'donor_fix_evidence', 'target_fault_evidence', 'target_harm_evidence')
        for field in fields:
            used.update(chain.get(field, []))
        for item in chain.get('platform_semantics', []):
            used.update(item['relied_at_evidence'])
            used.update(item['implementation_evidence'])
        for link in support:
            linked = set(link['supports'])
            if not linked or not linked <= primaries or len(linked) != len(link['supports']):
                raise ImpactProofError('support units must link directly to unique primary units in the same group')
            indices = link['evidence']
            if not indices or any(type(i) is not int or not 1 <= i <= len(evidence) for i in indices):
                raise ImpactProofError('support link requires valid evidence indices')
            entries = [evidence[i - 1] for i in indices]
            target_units = {e['unit_id'] for e in entries if e['revision'] == 'target'}
            if not (linked | {link['unit_id']}) <= target_units:
                raise ImpactProofError('support link must cite its target and each linked primary target')
            source = units[link['unit_id']]
            available = {rev for side, rev in (('before', 'source_parent'), ('after', 'source_fix')) if source[side]}
            own = {e['revision'] for e in entries if e['unit_id'] == link['unit_id']}
            if not available <= own:
                raise ImpactProofError('support link must retain its own available donor sides')
            used.update(indices)

        if proof['status'] != 'UNKNOWN':
            for ident in members:
                selected = [evidence[i - 1] for i in used if evidence[i - 1]['unit_id'] == ident]
                source = units[ident]
                available = {rev for side, rev in (('before', 'source_parent'), ('after', 'source_fix')) if source[side]}
                if not (available | {'target'}) <= {e['revision'] for e in selected}:
                    raise ImpactProofError('causal proof must use every unit target and available donor sides')
                for target in mapped[ident]['targets']:
                    if not any(target in _mapped_anchor({**e, 'origin': e['revision']}, [target]) for e in selected):
                        raise ImpactProofError('causal proof must use evidence from every mapped target region')
        if proof['status'] == 'AFFECTED':
            for ident in primaries:
                for field in fields:
                    own = [evidence[i - 1] for i in chain[field] if evidence[i - 1]['unit_id'] == ident]
                    if not own:
                        raise ImpactProofError('each primary unit needs its own causal role: ' + ident + '/' + field)
                    if field.startswith('donor_') and not any(checks._evidence_overlaps_donor_delta(e) for e in own):
                        raise ImpactProofError('primary donor causal evidence must overlap its own fix delta: ' + ident)
        from .platform_evidence import receipt
        receipts.append({'id': group['id'], 'unit_ids': group['unit_ids'], 'primary_unit_ids': group['primary_unit_ids'],
            'status': proof['status'], 'support_units': [s['unit_id'] for s in support],
            'platform_behavior_evidence': receipt(proof)})
    return {'status': 'GROUNDED_CAUSAL_PROOFS', 'contract': 'shared_run_impact_rules', 'groups': receipts,
            'runtime_security_proven': False, 'limitation': 'Grounded model proof obligations; not formal semantic proof.'}
