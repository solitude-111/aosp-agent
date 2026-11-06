"""Scripted ordinary counter proofs; never real CVE answers or reference patches."""
from test_impact_causality import assessment as ordinary_proof


def proof_groups_for(mapping):
    groups = []
    revisions = {'target': 'target', 'patch_before': 'source_parent', 'patch_after': 'source_fix'}
    for unit in mapping['units']:
        proof = ordinary_proof()
        proof['status'] = unit['status']
        proof['evidence'] = [{**{k: v for k, v in e.items() if k != 'origin'},
                              'revision': revisions[e['origin']], 'unit_id': unit['id']}
                             for e in unit['evidence']]
        indices = {rev: [n for n, e in enumerate(proof['evidence'], 1) if e['revision'] == rev]
                   for rev in revisions.values()}
        for step in proof['proof_steps']:
            step['evidence'] = indices['source_parent' if step['id'] == 'donor_fault' else 'target']
            if proof['status'] == 'UNKNOWN' and step['id'] == 'target_fault':
                step['resolved'] = False
        if proof['status'] == 'AFFECTED':
            for field, rev in (('donor_fault_evidence', 'source_parent'), ('donor_fix_evidence', 'source_fix'),
                               ('target_fault_evidence', 'target'), ('target_harm_evidence', 'target')):
                proof['causal_chain'][field] = indices[rev]
        else:
            proof.pop('causal_chain')
            proof['proof_steps'].append({'id': 'donor_fix', 'question': 'What changed in the donor counter?',
                'resolution': 'The counter is bounded after the repair.', 'resolved': True,
                'evidence': indices['source_fix']})
            if proof['status'] in ('NOT_AFFECTED', 'ALREADY_FIXED'):
                proof['proof_steps'].append({'id': 'equivalent_protection', 'question': 'Does the target bound the counter?',
                    'resolution': 'The fixture uses a bounded target counter.', 'resolved': True, 'evidence': indices['target']})
        groups.append({'id': 'g-' + unit['id'], 'unit_ids': [unit['id']], 'primary_unit_ids': [unit['id']],
                       'support_links': [], 'impact': proof})
    return groups
