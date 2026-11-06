"""Controller-derived lexical hints and conservative build ownership.

The plan is frozen before migration, using only supplied donor additions and
pinned target blobs. It is never a security oracle or a reference backport.
"""
import hashlib
import re

from .build_discovery import discover_build
from .case import Case
from .discovery import tokens
from .patches import text_hunks


def normalize_checks(spec):
    return list(Case.from_dict({
        'cve': 'CVE-2099-0000', 'project': 'validation contract', 'repository': 'repo',
        'source_commit': '0', 'source_parent': '0', 'target_commit': '0',
        'files': ['placeholder'], 'validation': spec,
    }).validation_checks)


def added_lines(unit):
    """Return actual '+' lines with donor coordinates, excluding diff headers."""
    return [{'line': line['new_line'], 'text': line['text']}
            for hunk in text_hunks(unit['patch']) for line in hunk['lines'] if line['marker'] == '+']


def make_plan(repo, units, mappings, files, diff, *, explicit=None, auto=True, build_runner=None,
              build_requested=True):
    plan = {'version': 2, 'target_commit': repo.head,
            'input_patch_sha256': hashlib.sha256(diff.encode()).hexdigest(),
            'scope': 'advisory_donor_symbols_and_literal_build_ownership',
            'runtime_security_proven': False, 'checks': [], 'provenance': [],
            'limitations': ['Token presence is not a semantic, reachability or runtime proof.',
                            'Generated symbol hints neither block equivalent rewrites nor satisfy validation.']}
    generated = []
    overrides = normalize_checks(explicit) if explicit is not None else []
    disable_all = explicit is not None and not overrides
    replaced = {c['stage'] for c in overrides}
    if auto and not disable_all:
        for unit in ([] if 'source_contract' in replaced else units):
            paths = sorted(set(mappings.get(unit['id'], [])))
            if not paths:
                continue
            additions = added_lines(unit)
            # Reject context-only markers and terms already present at baseline.
            # Source-side vocabulary is an investigation hint. A backport may
            # implement the same behavior using entirely different vocabulary;
            # conversely, a comment can contain every donor token without a fix.
            # Never turn these hints into executable validation commands.
            baseline = '\n'.join(repo.read(p) for p in paths if p in repo.files)
            novel = (tokens('\n'.join(row['text'] for row in additions))
                     - tokens('\n'.join(unit['before'].values())) - tokens(baseline))
            terms = sorted(t for t in novel if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', t))[:4]
            evidence = {'unit_id': unit['id'], 'donor_path': unit['new_path'],
                        'added_lines': additions, 'target_paths': paths, 'terms': terms,
                        'status': 'ADVISORY' if terms else 'NO_NOVEL_MARKER',
                        'role': 'lexical_hint', 'blocks_validation': False,
                        'provides_validation_credit': False}
            plan['provenance'].append(evidence)
        # Build metadata is useful only if a generated build will be executed.
        # Explicit build checks own their plan; an absent runner must not turn
        # a source-only investigation into a project-wide Android.bp scan.
        if build_requested and build_runner and files and 'android_module_build' not in replaced:
            plan['build'] = discover_build(repo, files)
        else:
            plan['build'] = {'status': 'DEFERRED', 'modules': [],
                             'reason': ('BUILD_NOT_REQUESTED' if not build_requested else
                                        'EXPLICIT_BUILD_OVERRIDE' if 'android_module_build' in replaced else
                                        'NO_CHANGED_FILES' if not files else 'NO_BUILD_RUNNER')}
        plan['build']['runner_configured'] = build_runner is not None
        if build_runner and plan['build']['status'] == 'RESOLVED':
            names = sorted({m['name'] for m in plan['build']['modules']})
            generated.append({'stage': 'android_module_build',
                              'argv': [str(build_runner), *names], 'artifacts': []})
    else:
        plan['build'] = {'status': 'DISABLED', 'modules': []}
    # A repository's explicit empty list disables auto checks for that repo;
    # nonempty overrides replace the complete corresponding generated stages.
    if disable_all:
        generated = []
        plan['override'] = 'DISABLE_ALL'
    else:
        generated = [c for c in generated if c['stage'] not in replaced]
        plan['override'] = sorted(replaced)
    plan['checks'] = generated + overrides
    plan['generated_check_count'] = len(generated)
    return plan
