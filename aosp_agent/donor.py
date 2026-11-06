"""Pin and verify optional donor history against the exact diff task."""
from pathlib import Path
import re

from .discovery import diff_units, local_git


def diff_facts(diff):
    facts = []
    for unit in diff_units(diff):
        metadata = [line for line in unit['patch'].splitlines()
                    if line.startswith(('old mode ', 'new mode ', 'new file mode ',
                                        'deleted file mode ', 'rename from ', 'rename to ',
                                        'copy from ', 'copy to '))]
        facts.append((unit['old_path'], unit['new_path'], unit['kind'],
                      unit['before'], unit['after'], metadata))
    return facts


def verify_donor(repo, commit, parent, patch):
    supplied = (repo is not None, commit is not None, parent is not None)
    if not any(supplied):
        return {'status': 'NOT_PROVIDED', 'evidence_scope': 'diff_lines_only',
                'history': 'NOT_AVAILABLE'}
    if not all(supplied):
        raise ValueError('donor-repo, source-commit and source-parent must be provided together')
    root = Path(repo).resolve()
    for ref in (commit, parent):
        if not isinstance(ref, str) or not re.fullmatch(r'[0-9a-fA-F]{4,64}', ref):
            raise ValueError('donor revisions must be Git object IDs')
    def resolve(ref):
        return local_git(root, 'rev-parse', '--verify', ref + '^{commit}').stdout.strip()
    commit, parent = resolve(commit), resolve(parent)
    raw = local_git(root, 'cat-file', '-p', commit).stdout
    parents = [line.split()[1] for line in raw.split('\n\n', 1)[0].splitlines()
               if line.startswith('parent ')]
    if parent not in parents:
        raise ValueError('source-parent is not a direct parent of source-commit')
    source_diff = local_git(root, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                            parent, commit).stdout
    if diff_facts(source_diff) != diff_facts(patch):
        raise ValueError('input patch does not match the pinned donor commit/parent diff')
    return {'status': 'VERIFIED', 'source_commit': commit, 'source_parent': parent,
            'donor_git': local_git(root, 'rev-parse', '--absolute-git-dir').stdout.strip(),
            'evidence_scope': 'pinned_donor_blobs', 'history': 'LOCAL_ONLY',
            'commit_message': raw.split('\n\n', 1)[-1]}


def verify_source_sequence(sequence, patch):
    """Verify every step before routing; IDs are evidence identities, not answers."""
    if not isinstance(sequence, list) or not sequence:
        raise ValueError('source sequence must be a nonempty list')
    if ''.join(s['patch'].rstrip('\n') + '\n' for s in sequence) != patch:
        raise ValueError('source sequence does not match the complete supplied patch')
    units, steps, seen = [], [], set()
    for step in sequence:
        ident = step['id']
        if not isinstance(ident, str) or not re.fullmatch(r's\d{3}', ident) or ident in seen:
            raise ValueError('invalid or duplicate source step identity')
        seen.add(ident)
        provenance = verify_donor(step['provenance']['donor_git'], step['source_commit'], step['source_parent'], step['patch'])
        steps.append({'id': ident, **provenance, 'source_candidates': step.get('source_candidates', [])})
        for unit in diff_units(step['patch']):
            units.append({**unit, 'id': ident + ':' + unit['id'], 'source_id': ident})
    edges = [{'before': a['id'], 'after': b['id'], 'basis': 'direct_parent'}
             for a in steps for b in steps if a['source_commit'] == b['source_parent']]
    return units, {'status': 'VERIFIED_SEQUENCE', 'steps': steps, 'history': 'LOCAL_ONLY',
                   'dependency_edges': edges, 'sequence_policy': 'input order is not ancestry proof'}
