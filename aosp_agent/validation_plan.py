"""Controller-derived smoke checks and conservative build ownership.

The plan is frozen before migration, using only supplied donor additions and
pinned target blobs. It is never a security oracle or a reference backport.
"""
import hashlib
import re

from .build_discovery import discover_build
from .case import Case
from .discovery import tokens


def normalize_checks(spec):
    return list(Case.from_dict({
        'cve': 'CVE-2099-0000', 'project': 'validation contract', 'repository': 'repo',
        'source_commit': '0', 'source_parent': '0', 'target_commit': '0',
        'files': ['placeholder'], 'validation': spec,
    }).validation_checks)


def added_lines(unit):
    """Return actual '+' lines with donor coordinates, excluding diff headers."""
    result, line_number = [], None
    for line in unit['patch'].splitlines():
        match = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
        if match:
            line_number = int(match[1])
        elif line_number is not None and line.startswith(('+', ' ')):
            if line.startswith('+'):
                result.append({'line': line_number, 'text': line[1:]})
            line_number += 1
    return result


def make_plan(repo, units, mappings, files, diff, *, explicit=None, auto=True, build_runner=None):
    plan = {'version': 1, 'target_commit': repo.head,
            'input_patch_sha256': hashlib.sha256(diff.encode()).hexdigest(),
            'scope': 'donor_symbol_smoke_and_literal_build_ownership',
            'runtime_security_proven': False, 'checks': [], 'provenance': [],
            'limitations': ['Token presence is not a semantic, reachability or runtime proof.']}
    generated = []
    if auto:
        for unit in units:
            paths = sorted(set(mappings.get(unit['id'], [])))
            if not paths:
                continue
            additions = added_lines(unit)
            # Reject context-only markers and terms already present at baseline.
            # This is intentionally only a lexical smoke check, not a contract
            # inferred by the patch-writing model.
            baseline = '\n'.join(repo.read(p) for p in paths if p in repo.files)
            novel = (tokens('\n'.join(row['text'] for row in additions))
                     - tokens('\n'.join(unit['before'].values())) - tokens(baseline))
            terms = sorted(t for t in novel if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', t))[:4]
            evidence = {'unit_id': unit['id'], 'donor_path': unit['new_path'],
                        'added_lines': additions, 'target_paths': paths, 'terms': terms,
                        'status': 'GENERATED' if terms else 'NO_NOVEL_MARKER'}
            plan['provenance'].append(evidence)
            if terms:
                generated.append({'stage': 'source_contract',
                                  'argv': ['grep', '-Ewq', '--', '|'.join(terms), *paths],
                                  'artifacts': []})
        plan['build'] = discover_build(repo, files)
        plan['build']['runner_configured'] = build_runner is not None
        if build_runner and plan['build']['status'] == 'RESOLVED':
            names = sorted({m['name'] for m in plan['build']['modules']})
            generated.append({'stage': 'android_module_build',
                              'argv': [str(build_runner), *names], 'artifacts': []})
    else:
        plan['build'] = {'status': 'DISABLED', 'modules': []}
    # A repository's explicit empty list disables auto checks for that repo;
    # nonempty overrides replace the complete corresponding generated stages.
    overrides = normalize_checks(explicit) if explicit is not None else []
    if explicit is not None and not overrides:
        generated = []
        plan['override'] = 'DISABLE_ALL'
    else:
        replaced = {c['stage'] for c in overrides}
        generated = [c for c in generated if c['stage'] not in replaced]
        plan['override'] = sorted(replaced)
    plan['checks'] = generated + overrides
    plan['generated_check_count'] = len(generated)
    return plan
