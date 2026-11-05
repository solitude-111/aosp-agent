"""Offline input readiness inventory. Never fetch, build, or start a model."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess

from .case import validate_relative_path
from .discovery import local_git


def audit_row(row, donor_root):
    result = {'id': row.get('cve') if isinstance(row.get('cve'), str) else None, 'repository': row.get('repository'),
              'donor_repository': row.get('donor_repository') or row.get('repository'),
              'source_commit': row.get('source_commit'), 'source_parent': row.get('source_parent'),
              'status': 'INVALID_INPUT', 'identity_status': 'UNVERIFIED', 'network_access': False}
    if re.fullmatch(r'CVE-0000-\d+', str(result['id'])):
        result['identity_status'] = 'TEMPORARY_ID_NEEDS_AUTHORITATIVE_MAPPING'
    try:
        if not result['id']:
            result['detail'] = 'case identifier must be a nonempty string'
            return result
        donor = validate_relative_path(result['donor_repository'])
        refs = [result['source_commit'], result['source_parent']]
        if not all(isinstance(r, str) and re.fullmatch(r'[0-9a-fA-F]{4,64}', r) for r in refs):
            result['detail'] = 'source commit and parent must both be Git object IDs'
            return result
        root = Path(donor_root).resolve()
        repo = root / (donor.replace('/', '-') + '.git')
        if not repo.resolve().is_relative_to(root):
            result['detail'] = 'donor repository resolves outside donor root'
            return result
        if not repo.is_dir():
            result['status'] = 'MISSING_DONOR_REPOSITORY'
            return result
        if local_git(repo, 'rev-parse', '--git-dir', check=False).returncode:
            result['status'] = 'INVALID_DONOR_REPOSITORY'
            return result
        bare = local_git(repo, 'rev-parse', '--is-bare-repository').stdout.strip() == 'true'
        owning = local_git(repo, 'rev-parse', '--absolute-git-dir' if bare else '--show-toplevel').stdout.strip()
        if Path(owning).resolve() != repo.resolve():
            result['status'] = 'INVALID_DONOR_REPOSITORY'
            return result
        resolved, missing = [], []
        for name, ref in zip(('source_commit', 'source_parent'), refs):
            proc = local_git(repo, 'rev-parse', '--verify', ref + '^{commit}', check=False)
            if proc.returncode:
                missing.append(name)
            else:
                resolved.append(proc.stdout.strip())
        if missing:
            result.update(status='MISSING_COMMIT_OBJECT', missing=missing)
            return result
        commit, parent = resolved
        raw = local_git(repo, 'cat-file', '-p', commit).stdout
        parents = [line.split()[1] for line in raw.split('\n\n', 1)[0].splitlines() if line.startswith('parent ')]
        if parent not in parents:
            result['status'] = 'PARENT_MISMATCH'
            return result
        # Resolve changed trees/blobs too: commit objects alone do not establish
        # that a shallow/promisor repository can provide the donor input offline.
        proc = local_git(repo, 'diff', '--numstat', '--no-ext-diff', '--no-textconv',
                         '--no-renames', parent, commit, check=False)
        if proc.returncode:
            result['status'] = 'DIFF_UNAVAILABLE'
            return result
        result.update(status='READY' if proc.stdout.strip() else 'EMPTY_DIFF',
                      source_commit=commit, source_parent=parent,
                      changed_paths=len(proc.stdout.splitlines()))
    except (ValueError, TypeError, KeyError):
        result['detail'] = 'invalid donor repository path or input fields'
    except (OSError, subprocess.SubprocessError) as exc:
        result.update(status='LOCAL_GIT_ERROR', error_type=type(exc).__name__)
    return result


def audit_dataset(dataset, donor_root):
    dataset = Path(dataset)
    files = [dataset] if dataset.is_file() else sorted(dataset.glob('*.json'))
    results = []
    for path in files:
        try:
            raw = json.loads(path.read_text())
            rows = raw.get('cases', [raw]) if isinstance(raw, dict) else raw
            if not isinstance(rows, list):
                raise ValueError('rows must be a list')
            for index, row in enumerate(rows, 1):
                result = audit_row(row, donor_root) if isinstance(row, dict) else {'status': 'INVALID_INPUT'}
                results.append({**result, 'input_file': path.name, 'row': index})
        except (OSError, ValueError):
            results.append({'input_file': path.name, 'status': 'INVALID_INPUT'})
    counts = Counter(r.get('id') for r in results if r.get('id'))
    for result in results:
        if counts.get(result.get('id'), 0) > 1:
            result['donor_status'] = result['status']
            result['status'] = 'DUPLICATE_ID'
    return {'version': 1, 'scope': 'local_donor_input_readiness_only', 'rows': results,
            'total_rows': len(results), 'status_counts': dict(Counter(r['status'] for r in results)),
            'ready': bool(results) and all(r['status'] == 'READY' for r in results),
            'limitations': ['READY does not verify CVE identity, target applicability, or migration quality.',
                            'Rows absent from the supplied dataset cannot be audited.',
                            'Missing objects require separate input preparation; no fetch is performed.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--donor-root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = audit_dataset(args.dataset, args.donor_root)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        # Never overwrite a dataset or an earlier evidence file accidentally.
        with args.output.open('x') as output:
            output.write(rendered)
    print(rendered)
    return 0 if report['ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
