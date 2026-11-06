"""Diff-only contracts: complete change coverage, grounded mappings, explicit unknowns."""
import json
from copy import deepcopy
from .prompts import IMPACT_SCHEMA


def obj(properties):
    return {'type': 'object', 'additionalProperties': False, 'properties': properties, 'required': list(properties)}


def array(items):
    return {'type': 'array', 'items': items}


def enum(*values):
    return {'type': 'string', 'enum': list(values)}


STRING = {'type': 'string', 'minLength': 1}
LINE = {'type': 'integer', 'minimum': 1}
EVIDENCE = obj({'origin': enum('target', 'patch_before', 'patch_after'), 'path': STRING,
                'line_start': LINE, 'line_end': LINE, 'excerpt': STRING, 'claim': STRING})
TARGET = obj({'path': STRING, 'symbol': STRING, 'line_start': LINE, 'line_end': LINE,
              'action': enum('edit', 'read_dependency'),
              'relationship': enum('same_function', 'renamed', 'moved', 'split', 'merged', 'inlined',
                                   'caller', 'dependency', 'test', 'data_or_configuration'), 'reason': STRING})
UNIT = obj({'id': STRING, 'status': enum('AFFECTED', 'NOT_AFFECTED', 'ALREADY_FIXED', 'UNKNOWN'),
            'invariant': STRING, 'reasoning': STRING,
            'absence_basis': enum('none', 'feature_absent', 'equivalent_protection'),
            'targets': array(TARGET), 'evidence': array(EVIDENCE),
            'candidate_resolution': STRING})
ASSESSMENT_SCHEMA = obj({'reasoning': STRING, 'limitations': array(STRING), 'units': array(UNIT),
                         'new_files': array(obj({'path': STRING, 'anchor_path': STRING, 'reason': STRING}))})
ASSESSMENT_SCHEMA['properties']['repository_requests'] = array(obj({
    'repository': STRING, 'unit_id': STRING, 'reason': STRING, 'evidence': array(EVIDENCE)}))
ASSESSMENT_SCHEMA['properties']['scope_closure'] = obj({'units': array(obj({
    'unit_id': STRING, 'security_operation': STRING, 'entrypoint_and_flow': STRING,
    'dependencies_checked': array(STRING), 'unresolved_questions': array(STRING), 'evidence': array(EVIDENCE),
    'proof_steps': array(obj({'role': enum('entrypoint', 'state_flow', 'security_condition', 'dependency'),
                             'reasoning': STRING, 'evidence': array({'type': 'integer', 'minimum': 1})}))}))})
MAPPED_IMPACT_SCHEMA = deepcopy(IMPACT_SCHEMA)
MAPPED_IMPACT_SCHEMA['properties']['evidence']['items']['properties']['unit_id'] = STRING
MAPPED_IMPACT_SCHEMA['properties']['evidence']['items']['required'].append('unit_id')
PROOF_GROUP = obj({'id': STRING, 'unit_ids': array(STRING), 'primary_unit_ids': array(STRING),
    'impact': MAPPED_IMPACT_SCHEMA, 'support_links': array(obj({
        'unit_id': STRING, 'supports': array(STRING), 'reason': STRING,
        'evidence': array({'type': 'integer', 'minimum': 1})}))})
ASSESSMENT_SCHEMA['properties']['proof_groups'] = array(PROOF_GROUP)
MIGRATION_SCHEMA = obj({'summary': STRING, 'limitations': array(STRING), 'coverage': array(obj({
    'id': STRING, 'status': enum('implemented', 'not_required', 'unresolved'), 'explanation': STRING,
    'evidence': array(obj({'path': STRING, 'line_start': LINE, 'line_end': LINE, 'excerpt': STRING}))}))})

KNOWLEDGE = '''AOSP investigation guide (hypotheses, never reference answers):
- Identify the protection added by the diff: input validation, ownership/permission, memory bounds,
  lifetime, identity, race/lock order, or serialization contract. Explain the preconditions and data flow.
- For Binder/service code examine the entry point, calling UID/appId/userId, clear/restore identity,
  permission helper behavior, callbacks, locks and lifecycle at the target revision.
- For native code examine integer/length semantics, allocation and ownership, all relevant copies
  and upstream vendored/generated copies. For Parcel/AIDL examine writers and readers together.
- Inspect local Android.bp/Android.mk, permissions/manifest/resource XML, flags and direct API definitions.
  Do not infer product reachability from version number or from unknown build/device configuration.
- A new helper in the diff may express protection that belongs inside an old function. A missing name
  may be renamed, moved across repositories, split, merged or inlined. Compare callers, fields,
  constants, control flow and local history; file/name similarity alone proves nothing.
- Separate the faulty security operation from the mechanism introduced to fix it. Missing new
  hooks, blobs, flags, types, APIs or prerequisite commits does not prove the operation absent.
  Trace the old entrypoint, dispatch, object/identity flow and checks across repository boundaries.
  An old representation can retain the same fault even when the donor fix cannot be copied directly.
- Enumerate every change unit, including new/deleted files, tests and configuration. Explain dependencies
  between units. Equivalent existing protection is ALREADY_FIXED. NOT_AFFECTED requires affirmative
  target evidence about the feature/call path; failed search or missing Git objects is not absence.
- Source history beyond the supplied diff may be unavailable. Diff excerpts prove only the displayed
  before/after code, not unseen donor behavior. Use UNKNOWN if that prevents a defensible decision.
'''


def assessment_prompt(diff, inventory, location):
    # Keep complete evidence on disk but bound repeated retrieval hints in model context.
    # The model can read any pinned target file; truncation never means absence.
    compact = {'units': [], 'issues': location['issues'][:40], 'issues_truncated': len(location['issues']) > 40,
               'source_history': location['source_history'], 'target_history': location['target_history'][:8],
               'retrieval_summary': location.get('retrieval_summary', {})}
    for unit in location['units']:
        compact['units'].append({k: unit[k] for k in ('id', 'old_path', 'new_path', 'status', 'before', 'after')})
        retrieval = unit.get('retrieval', [])
        compact['units'][-1].update(
            retrieval=[{**{k: row[k] for k in ('repository', 'stage', 'project_search',
                                              'scope_complete', 'absence_proven')},
                        'queried_scope_count': len(row.get('queried_scopes', [])),
                        'text_anchor_count': len(row.get('text_anchors', [])),
                        'semantic_identity': 'UNASSESSED'} for row in retrieval[:12]],
            retrieval_records_total=len(retrieval), retrieval_records_truncated=len(retrieval) > 12)
        compact['units'][-1]['candidates'] = [
            {**{k: c[k] for k in ('workspace_path', 'score', 'signals', 'symbols')},
             'windows': [{k: w[k] for k in ('line_start', 'line_end', 'function')} for w in c['windows'][:2]]}
            for c in unit['candidates'][:6]]
    return '''Locate the target implementation and independently assess this higher-version patch.
The original diff and repositories are supplied, optionally with verified donor commit/parent
and read-only history tools. No reference conclusion or migration recipe is provided.
Repository HEADs below are pinned baselines. Target mappings must be derived from source evidence.
UNAVAILABLE entries are diagnostic scope gaps, not searchable or mappable repositories. Do not
retry object reads against them. Their absence from candidates proves nothing about impact.
Account for cross-repository callers and dependencies; unresolved required dependencies mean UNKNOWN.
Partial discovery cannot establish a global NOT_AFFECTED, ALREADY_FIXED or fully validated result.
Initial retrieval starts with exact files, then nearby directories, then an admitted project only
when earlier text hints are insufficient. DEFERRED means NOT SEARCHED, not no matches. Even a
complete old/new diff-side text match is only a candidate hint, not semantic identity or complete
scope. Investigate competing implementations, callers and dependencies before conclusions. Use
aosp_source search/paths with a literal path to expand within a directory first; omit path only
when project-wide investigation is necessary. Request other projects through grounded scope expansion.
Only retrieval counts/stages and bounded candidates are inlined; complete scopes and text-anchor
coordinates remain in location.json. Truncated hints never imply missing implementations.
Work READ ONLY. Use aosp_source view/search/paths/history with pinned revisions and repository
selectors from run metadata. The controller enforces offline reads; no native shell is available.
Never checkout/reset/clean/commit/stage/fetch or modify an original repository.
Do not read sibling project files, prior runs, oracles, credentials or reference patches.

''' + KNOWLEDGE + '''
Return the JSON schema. For EACH change-unit id exactly once:
1. State the safety invariant and compare the actual old-version code with the diff.
2. List ALL required target functions/callers/dependencies as targets (one-to-many is allowed).
   Paths are workspace paths prefixed by the repository key, e.g. frameworks/base/services/X.java.
   Give exact target function/region ranges and symbol names, or a descriptive name for data/config.
   action=edit means THIS region must change; read_dependency is inspected but remains read-only.
   For a split function list every old region needing the protection separately with action=edit.
   Explain ambiguity and why competing candidates do or do not represent the same functionality.
3. Cite exact contiguous target excerpts AND patch_before/patch_after excerpts. Target path includes
   repository key; patch evidence path is the original old/new diff path, with ORIGINAL source line
   numbers shown in the location report. Never cite lines outside the diff as patch evidence.
4. Missing/new helpers: locate the old callers and decide inline/adapt/create/irrelevant with evidence.
   NOT_AFFECTED with feature_absent needs at least two target excerpts including the relevant entry point.
   Feature-absence proposals receive a separate read-only challenge before acceptance. Prove why the
   faulty operation is absent/unreachable in the OLD implementation; naming missing modern APIs is
   insufficient. Equivalent existing protection is ALREADY_FIXED; uncertain equivalence is UNKNOWN.
   UNKNOWN blocks the entire migration. It is valid to report uncertainty rather than invent a mapping.
5. Include required existing tests/build/API dependencies among targets. If a new file is necessary,
   declare new_files with a related existing anchor_path and rationale. Only the resulting reviewed
   allowlist will be writable. You may search any tracked source in the supplied repositories;
   candidates are hints, not a limit on which files you may discover. Search progressively and bound
   output. Do not stop after finding one snippet when other units or callers remain unresolved.

Repository inventory:\n''' + json.dumps(inventory, ensure_ascii=False) + '\nCandidate retrieval and numbered diff sides (bounded hints):\n' + json.dumps(compact, ensure_ascii=False) + '\nOriginal diff:\n```diff\n' + diff + '\n```\n'


def migration_prompt(diff, assessment, writable, workspace):
    return f'''Implement the grounded backport in the isolated workspace {workspace}.
Only these exact workspace-relative paths may change: {json.dumps(writable)}.
Original repositories must remain untouched. Do not commit/stage/reset/clean/fetch. Do not run PoCs.
Use target-version APIs; inspect definitions and call sites before using a donor helper. Preserve normal
behavior. Apply the protection across all mapped old functions, including splits, merges, inline
implementations, vendored copies, new dependencies, tests and configuration described in the plan.
Do not mechanically copy donor hunk contexts or skip a missing function. If the plan proves insufficient,
return unresolved coverage and explain the missing mapping; do not edit outside the allowlist.

The controller will generate patches and independently replay them on fresh target worktrees. Runtime
validation is determined only by the controller's fixed checks; do not claim test PASS.
Return structured coverage for EVERY unit id in the supplied assessment. For affected units mark implemented only with
exact current candidate excerpts covering its invariant; all others use not_required with explanation.
Coverage is your source review, not independent proof of security. Never claim Android build/device
success from this source-only phase.

Assessment:\n{json.dumps(assessment, ensure_ascii=False)}
Original diff:\n```diff\n{diff}\n```\n'''
