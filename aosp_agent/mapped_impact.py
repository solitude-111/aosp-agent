"""Bind the common causal proof contract to complete, namespaced mapping units.

Core repairs need the same causal checks as the donor run backend. Support
changes retain both their own evidence and an explicit grounded link to a core
repair. They never disappear from mapping, migration coverage or the hunk ledger.
"""
from pathlib import Path
import subprocess

from .discovery import Repository
from .flag_cleanup import check_flag_cleanup
from .impact_proof import AssessmentError, CausalityChecks, PROOF_STEP_REQUIREMENTS
from .mapping_plan import _excerpt
from .prompts import parse_impact_response
from .retrieval import LazyTree
from .scope_evidence import ground_evidence, _mapped_anchor


class ImpactProofError(AssessmentError):
    pass


PROOF_CONTEXT = '''
Provide proof_groups for the complete repair input using the impact schema.
Each group's impact object must include its own reasoning field as well as the required
status, scope_contract, proof_steps, root_cause, evidence and limitations fields. The top-level
reasoning does not replace the group's reasoning. For an excerpt already cited in
units[].evidence, use an impact.evidence entry {unit_id, evidence_index, claim}, where
evidence_index is the 1-based index in that unit's evidence array. Only use a full
evidence object for a new excerpt. All other proof indices still point into this group's
impact.evidence array, including references.
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
not permission to discard difficult changes. For a deletion-only .aconfig flag
declaration with no target declaration or consumer, put it in the same AFFECTED
group as the production guard removal, as a support unit with read_dependency
targets on the old production path. Set that link's target_disposition to
no_target_edit. Cite the removed flag name, both available donor sides, the removed
Flags accessor guard in the primary donor hunk, and the pinned target flow showing
the linked repair accounts for the old behavior. Explain why any old equivalent
configuration or consumer requires no edit. The controller checks flag identifiers
in admitted projects. Keep the primary edit mappings and the full causal proof.
If this evidence is incomplete, use UNKNOWN or request the missing dependency.
A group cannot consist only of support units. Every mapped target region and each available source side must
be cited by the proof steps, causal chain or support links, not unused padding.
Choose scope_contract.vulnerability_pattern from the donor fault: authorization_boundary
for missing authority checks, persistent_state_pollution for state reused by the wrong
consumer, resource_bound for attacker-influenced values reaching an expensive sink,
and generic_data_flow only when no specialized pattern fits. Category denial_of_service
requires resource_bound; permission_bypass requires authorization_boundary.
Use the exact required impact.proof_steps IDs below for the selected pattern:
''' + ''.join(f'- {pattern}: {", ".join(ids)}\n' for pattern, ids in PROOF_STEP_REQUIREMENTS.items()) + '''
These are distinct from scope_closure proof roles. Each resolved step requires 1-based
indices into this group's impact.evidence. For AFFECTED, every pattern-required step
except donor_fault must cite only executable target statements. Do not cite donor
code, imports, or comments in those steps. Use donor evidence in causal_chain.
Classify representation_change by the faulty value and operation, not by the name
of a new helper introduced by the fix. If it is equivalent_representation, include
representation_equivalence. For AFFECTED, that step must cite both executable target
and executable donor evidence, including at least one donor citation overlapping the
fix delta. Import-only donor citations can support a support_link, not equivalence.
For NOT_AFFECTED or ALREADY_FIXED include a resolved clearing step anchored to target
evidence (counterpart_absence or equivalent_protection, with equivalent_protection
mandatory for ALREADY_FIXED). UNKNOWN needs an unresolved material proof step.
For AFFECTED, causal_chain.external_behavior_assumptions must be an empty array.
Put source-backed facts in the reasoning and the causal chain, with evidence indices
that establish them. Keep nonblocking limitations separate. If a material fact
remains unverified, request its project with evidence or report UNKNOWN. Negative
conclusions still need independent exclusion review. Exact excerpts establish
provenance, not formal semantics.
Use ordinary mapped evidence for AOSP framework and app code, including android.*
and com.android.* implementations. Cite the actual definition and relying call site.
Reserve causal_chain.platform_semantics for recognized standard-library APIs such
as java.* and libc. These entries need implementation_evidence indices for the
pinned definition and relied_at_evidence indices from the causal target fault/harm
call sites. Use read_dependency mappings when reading definitions, and include them
in scope_closure. Missing decisive behavior remains UNKNOWN.
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
    for group_index, group in enumerate(groups):
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
        try:
            checks._validate_impact_causality(proof)
        except AssessmentError as exc:
            raise ImpactProofError(f'/proof_groups/{group_index}/impact: {exc}') from exc
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
        no_edit_support = []
        for link_index, link in enumerate(support):
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
            if link.get('target_disposition') == 'no_target_edit':
                if proof['status'] != 'AFFECTED' or any(
                        t['action'] != 'read_dependency' for t in mapped[source['id']]['targets']):
                    raise ImpactProofError('no_target_edit requires read-only support in an AFFECTED group')
                try:
                    no_edit_support.append(check_flag_cleanup(
                        controller, source, [units[u] for u in sorted(linked)], entries))
                except AssessmentError as exc:
                    raise ImpactProofError(f'/proof_groups/{group_index}/support_links/'
                                           f'{link_index}: {exc}') from exc
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
        if no_edit_support:
            receipts[-1]['no_target_edit_support'] = no_edit_support
    return {'status': 'GROUNDED_CAUSAL_PROOFS', 'contract': 'shared_run_impact_rules', 'groups': receipts,
            'runtime_security_proven': False, 'limitation': 'Grounded model proof obligations; not formal semantic proof.'}
