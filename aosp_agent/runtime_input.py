"""Four-field runtime JSONL: source identity, not target locations or answers.

Commit/parent positions form pairs. Donors form a candidate set, NOT a zipped
array. Input order is preserved without claiming that it proves ancestry.
Resolution is local-only and never fetches or checks out source repositories.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

from .case import validate_relative_path
from .discovery import local_git
from .donor import verify_donor


FIELDS = {'source_commit_sequence', 'source_parent_sequence', 'donor_repositories', 'target_revision'}


def project_name(value):
    if not isinstance(value, str) or not value:
        raise ValueError('donor repository must be a nonempty project name or HTTPS URL')
    if '://' in value:
        url = urlsplit(value)
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError('donor URL must be HTTPS without credentials, query or fragment')
        value = url.path.lstrip('/').rstrip('/')
    return validate_relative_path(value.removesuffix('.git'))


def revision_name(value):
    if (not isinstance(value, str) or not value or value.startswith('-')
            or not re.fullmatch(r'[A-Za-z0-9_./+-]+', value) or '..' in value or '//' in value):
        raise ValueError('invalid target revision; use a tag, branch or commit')
    return value


@dataclass(frozen=True)
class RuntimeInput:
    task_id: str
    commits: tuple[str, ...]
    parents: tuple[str, ...]
    donors: tuple[str, ...]
    target_revision: str

    @classmethod
    def parse(cls, row):
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError('runtime input must contain exactly the four documented fields')
        commits, parents, donors = (row[k] for k in ('source_commit_sequence', 'source_parent_sequence', 'donor_repositories'))
        if not isinstance(commits, list) or not isinstance(parents, list) or not 1 <= len(commits) <= 64 or len(commits) != len(parents):
            raise ValueError('commit and parent sequences must have the same nonzero length (at most 64)')
        if not all(isinstance(r, str) and re.fullmatch(r'[0-9a-fA-F]{4,64}', r) for r in commits + parents):
            raise ValueError('source revisions must be Git object IDs')
        if not isinstance(donors, list) or not 1 <= len(donors) <= 64:
            raise ValueError('donor repositories must be a nonempty candidate list (at most 64)')
        # Keep full origin URLs: stripping a hostname could merge unrelated
        # origins. Project names are derived separately for local routing.
        for donor in donors:
            project_name(donor)
        donors = tuple(dict.fromkeys(donors))
        revision = revision_name(row['target_revision'])
        canonical = dict(source_commit_sequence=[c.lower() for c in commits],
                         source_parent_sequence=[p.lower() for p in parents],
                         donor_repositories=list(donors), target_revision=revision)
        task_id = 'input-' + hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()[:20]
        return cls(task_id, tuple(canonical['source_commit_sequence']), tuple(canonical['source_parent_sequence']), donors, revision)


def load_jsonl(path):
    result = []
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            result.append(RuntimeInput.parse(json.loads(line)))
        except (ValueError, TypeError) as exc:
            raise ValueError(f'invalid runtime input at line {number}: {exc}') from exc
    if not result:
        raise ValueError('runtime input is empty')
    return result


def donor_path(origin, donor_root, donor_map=None):
    """An explicit origin map takes precedence over the legacy Android cache layout."""
    mapping = donor_map or {}
    if origin in mapping:
        return Path(mapping[origin]).resolve()
    if '://' in origin and urlsplit(origin).hostname != 'android.googlesource.com':
        raise ValueError('non-Android origin requires an explicit local donor map')
    project = project_name(origin).removeprefix('platform/')
    return Path(donor_root).resolve() / (project.replace('/', '-') + '.git')


def resolve_sources(task, donor_root, *, donor_map=None):
    sources, problems = [], []
    for number, (commit, parent) in enumerate(zip(task.commits, task.parents), 1):
        matches, failures = [], []
        for origin in task.donors:
            try:
                root = donor_path(origin, donor_root, donor_map)
                if not root.is_dir():
                    raise ValueError('local donor repository unavailable')
                git_dir = Path(local_git(root, 'rev-parse', '--absolute-git-dir').stdout.strip()).resolve()
                if git_dir != root.resolve():
                    owning = Path(local_git(root, 'rev-parse', '--show-toplevel').stdout.strip()).resolve()
                    if owning != root.resolve():
                        raise ValueError('configured donor directory is not a repository root or Git directory')
                # Verify both ancestry and the actual bytes, not merely a ref
                # name. Missing promisor objects remain input failures.
                content = local_git(root, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames', parent, commit).stdout
                provenance = verify_donor(root, commit, parent, content)
                matches.append({'origin': origin, 'project': project_name(origin),
                                'provenance': provenance, 'patch': content})
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                failures.append({'origin': origin, 'type': type(exc).__name__, 'detail': str(exc)[-1000:]})
        if not matches:
            problems.append({'step': number, 'status': 'SOURCE_UNAVAILABLE', 'candidates': failures})
            continue
        signatures = {(m['provenance']['source_commit'], m['provenance']['source_parent'],
                       hashlib.sha256(m['patch'].encode()).hexdigest()) for m in matches}
        if len(signatures) != 1:
            problems.append({'step': number, 'status': 'AMBIGUOUS_OBJECT_ID',
                             'detail': 'abbreviated source IDs resolve to different objects in candidate stores'})
            continue
        chosen = matches[0]  # Byte provider only, never a claim of unique project ownership.
        sources.append({'id': f's{number:03}', 'input_position': number,
                        'source_commit': chosen['provenance']['source_commit'],
                        'source_parent': chosen['provenance']['source_parent'],
                        'patch': chosen['patch'], 'provenance': chosen['provenance'],
                        'source_candidates': [{k: m[k] for k in ('origin', 'project')} for m in matches],
                        'candidate_failures': failures, 'unique_project': len(matches) == 1})
    edges = [{'before': a['id'], 'after': b['id'], 'basis': 'direct_parent'}
             for a in sources for b in sources if a['source_commit'] == b['source_parent']]
    return {'version': 1, 'task_id': task.task_id, 'target_revision': task.target_revision,
            'status': 'READY' if len(sources) == len(task.commits) else 'INPUT_UNRESOLVED',
            'sources': sources, 'problems': problems, 'dependency_edges': edges,
            'sequence_policy': 'input_order_preserved; only recorded dependency edges are proven',
            'donor_hints': [{'origin': d, 'project': project_name(d)} for d in task.donors],
            'network_access': False}
