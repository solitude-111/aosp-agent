"""Small model-authored corrections; the merged assessment is never trusted."""
from copy import deepcopy
import hashlib
import json
import re

from .diff_prompts import ASSESSMENT_RESPONSE_SCHEMA, STRING, array, obj
from .engine import AssessmentError
from .mapping_plan import _shape


MAX_REUSABLE_ASSESSMENT_BYTES = 1024 * 1024
INLINE_ASSESSMENT_BYTES = 128 * 1024


REPAIR_SCHEMA = obj({'base_sha256': STRING, 'replacements': array(obj({
    'path': STRING, 'value_json': STRING}))})
REPAIR_SCHEMA['properties']['replacements']['maxItems'] = 64
# A misplaced extra field can be relocated without deleting its claim. Moves
# are optional for wire/backwards compatibility and never move array entries.
REPAIR_SCHEMA['properties']['moves'] = array(obj({'from': STRING, 'path': STRING}))
REPAIR_SCHEMA['properties']['moves']['maxItems'] = 16
REPAIR_SCHEMA['properties']['retire_causal_claim'] = {'type': 'boolean'}


def digest(raw):
    return hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def seed_context(raw, path, *, pending_proof=False):
    """Inline a small checked seed or expose an indexed, read-only copy in this run."""
    label = ('Previous assessment with verified mappings and unresolved causal proof'
             if pending_proof else 'Accepted assessment from the previous round')
    encoded = json.dumps(raw, ensure_ascii=False)
    if len(encoded.encode()) <= INLINE_ASSESSMENT_BYTES:
        return '\n' + label + ':\n' + encoded

    lines, index = [], []

    def append(pointer, row, units=()):
        lines.append(pointer)
        first = len(lines) + 1
        lines.extend(json.dumps(row, ensure_ascii=False, indent=2).split('\n'))
        index.append({'pointer': pointer, 'unit_ids': list(units), 'start': first, 'end': len(lines)})

    for key, value in raw.items():
        if key == 'impact' and isinstance(value, dict):
            for section, content in value.items():
                if section in ('evidence', 'proof_steps') and isinstance(content, list):
                    for i, row in enumerate(content):
                        append(f'/impact/{section}/{i}', row)
                else:
                    append('/impact/' + section, content)
        elif key in ('evidence', 'proof_steps') and isinstance(value, list):
            for i, row in enumerate(value):
                append(f'/{key}/{i}', row)
        elif key in ('units', 'proof_groups'):
            for i, row in enumerate(value):
                append(f'/{key}/{i}', row, [row['id']] if key == 'units' else row['unit_ids'])
        elif key == 'scope_closure':
            for i, row in enumerate(value['units']):
                append(f'/scope_closure/units/{i}', row, [row['unit_id']])
        else:
            append('/' + key, value)
    from .output_budget import write_text
    write_text(path, '\n'.join(lines) + '\n')
    return ('\n' + label + '. Read only sections needed to repair '
            'the reported gaps with aosp_read_file, in small line ranges, from this run file: '
            + str(path) + '\n' + json.dumps(index, ensure_ascii=False))


def apply_repair(raw, repair, *, schema=ASSESSMENT_RESPONSE_SCHEMA):
    """Atomic replacement of existing fields (or optional top-level sections).

    No files, commands or controller-derived fields are addressable. Even a
    structurally valid result must pass the full mapping/scope/causal pipeline.
    """
    _shape(repair, REPAIR_SCHEMA)
    if repair['base_sha256'] != digest(raw):
        raise AssessmentError('assessment correction refers to a stale base_sha256')
    candidate, paths = deepcopy(raw), []
    def pointer(path):
        if not path.startswith('/') or re.search(r'~(?![01])', path):
            raise AssessmentError('invalid assessment correction JSON pointer: ' + path)
        return [p.replace('~1', '/').replace('~0', '~') for p in path[1:].split('/')]

    def register(parts, path):
        if any(parts[:len(old)] == old or old[:len(parts)] == parts for old in paths):
            raise AssessmentError('overlapping assessment corrections: ' + path)
        paths.append(parts)

    for change in repair['replacements']:
        path = change['path']
        parts = pointer(path)
        if parts[0] not in schema['properties']:
            raise AssessmentError('correction cannot set controller-derived or unknown fields: ' + path)
        register(parts, path)
        try:
            def invalid_constant(value):
                raise ValueError('non-JSON constant ' + value)
            value = json.loads(change['value_json'], parse_constant=invalid_constant)
            parent = candidate
            for part in parts[:-1]:
                if isinstance(parent, list):
                    if not re.fullmatch(r'0|[1-9][0-9]*', part):
                        raise ValueError('invalid array index')
                    parent = parent[int(part)]
                else:
                    parent = parent[part]
            key = parts[-1]
            if isinstance(parent, list):
                if not re.fullmatch(r'0|[1-9][0-9]*', key):
                    raise ValueError('invalid array index')
                parent[int(key)] = value
            elif isinstance(parent, dict) and (key in parent or len(parts) == 1):
                parent[key] = value
            else:
                raise ValueError('replacement path does not exist')
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AssessmentError(f'invalid assessment correction at {path}: {exc}') from exc
    for move in repair.get('moves', []):
        source, destination = pointer(move['from']), pointer(move['path'])
        register(source, move['from']); register(destination, move['path'])
        try:
            parent, source_schema = candidate, schema
            for part in source[:-1]:
                if not isinstance(parent, dict):
                    raise ValueError('moves cannot remove array entries or renumber evidence')
                parent = parent[part]
                source_schema = source_schema.get('properties', {}).get(part, {})
            if (not isinstance(parent, dict) or source[-1] not in parent
                    or source_schema.get('additionalProperties') is not False
                    or source[-1] in source_schema.get('properties', {})):
                raise ValueError('only schema-rejected extra fields can be moved')
            target, target_schema = candidate, schema
            for part in destination[:-1]:
                target = target[part]
                target_schema = target_schema.get('properties', {}).get(part, {})
            if (not isinstance(target, dict) or destination[-1] in target
                    or destination[-1] not in target_schema.get('properties', {})):
                raise ValueError('move destination must be an absent declared field')
            target[destination[-1]] = parent.pop(source[-1])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AssessmentError('invalid content-preserving field move: ' + str(exc)) from exc
    if repair.get('retire_causal_claim'):
        # This is not a generic delete operation. A failed AFFECTED argument
        # remains in the immutable base; a new UNKNOWN report must explicitly
        # retain a material unresolved premise and pass the full proof checker.
        impact = candidate.get('impact', candidate)
        impact_schema = schema['properties'].get('impact', schema)
        if (not isinstance(impact, dict) or impact.get('status') != 'UNKNOWN'
                or 'causal_chain' not in impact
                or 'causal_chain' not in impact_schema.get('properties', {})
                or 'causal_chain' in impact_schema.get('required', [])
                or not any(step.get('resolved') is False for step in impact.get('proof_steps', [])
                           if isinstance(step, dict))):
            raise AssessmentError('retiring a causal claim requires UNKNOWN with an explicit unresolved proof step')
        del impact['causal_chain']
    _shape(candidate, schema)
    return candidate


def repair_prompt(raw, error):
    return f'''Correct the current read-only assessment using small field replacements.
Current base_sha256: {digest(raw)}
Validation errors: {error}
The base is your last assessment with all successfully applied corrections, not a new investigation.
Return only base_sha256 and replacements. Each replacement has a JSON pointer path (zero-based array
indices, e.g. /units/0/targets/1/line_end) and value_json containing the JSON-encoded new value.
Replace only incorrect fields or entries. Do not re-emit unchanged units, quotations or proof groups.
To add array entries, replace that array with its existing entries and the additions. A pointer to
an index outside the existing array cannot be replaced. Preserve indices referenced by other fields.
Optional top-level sections may be added. Do not overlap replacement paths. If an attempted correction
was rejected structurally or had a stale hash, NONE of that attempt's replacements were applied.
For a schema-rejected extra object field in the wrong place, optional moves may relocate its unchanged
value: {{"from":"/wrong_field","path":"/correct_parent/field"}}. The destination must be an absent
declared field. Moves cannot delete claims, overwrite fields, move required fields, or renumber arrays.
Only when a material premise really remains unresolved, update status and proof_steps to UNKNOWN;
retire_causal_claim:true may then retire the former AFFECTED-only causal_chain. The original claim
stays in the saved base report. It cannot remove claims while retaining AFFECTED or NOT_AFFECTED.
Address all reported locations, including duplicate quotations in other sections. Read the pinned source
only where needed. For an absent or invalid path, find the actual pinned path and update all affected
references and their ranges and excerpts. Imports/includes/fields use data_or_configuration.
If an evidence entry is a reference, fix the referenced unit evidence or change the index.
Function ranges must stay within the file. Use the declaration or a narrow Java range entirely
inside the actual named method. Do not widen a mapping merely to silence a validator.
The merged document must still cover every unit and pass ALL original evidence, scope and causal checks.
Unresolved facts must remain UNKNOWN. Do not edit source files or claim successful validation.
'''
