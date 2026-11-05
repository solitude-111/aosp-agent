"""Dataset entry point: source identity in, runtime-derived target scope out."""
from pathlib import Path

from .diff_engine import DiffBackportAgent
from .discovery import local_git


def from_case(case, source_root, run_root, *, donor_root=None, **options):
    source_root = Path(source_root).resolve()
    donor_name = case.donor_repository or case.repository
    donor = (Path(donor_root).resolve() / (donor_name.replace('/', '-') + '.git')
             if donor_root else source_root / case.repository)
    patch = local_git(donor, 'diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                      case.source_parent, case.source_commit).stdout.encode()
    agent = DiffBackportAgent(patch, source_root, Path(run_root), donor_repo=donor,
        source_commit=case.source_commit, source_parent=case.source_parent,
        task_id=case.cve, pinned_heads={case.repository: case.target_commit}, **options)
    agent.record.update(cve=case.cve, dataset_scope='source_identity_and_target_revision_only',
                        ignored_dataset_fields=['files', 'validation', 'impact', 'migration', 'poc'])
    return agent
