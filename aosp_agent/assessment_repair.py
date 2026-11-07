"""Small model-authored corrections; the merged assessment is never trusted."""
from copy import deepcopy
import hashlib
import json
import re

from .diff_prompts import ASSESSMENT_RESPONSE_SCHEMA, STRING, array, obj
from .engine import AssessmentError
from .mapping_plan import _shape


REPAIR_SCHEMA = obj({'base_sha256': STRING, 'replacements': array(obj({
    'path': STRING, 'value_json': STRING}))})
REPAIR_SCHEMA['properties']['replacements']['maxItems'] = 64


def digest(raw):
    return hashlib.sha256(json.dumps(raw, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def apply_repair(raw, repair, *, schema=ASSESSMENT_RESPONSE_SCHEMA):
    """Atomic replacement of existing fields (or optional top-level sections).

    No files, commands or controller-derived fields are addressable. Even a
    structurally valid result must pass the full mapping/scope/causal pipeline.
    """
    _shape(repair, REPAIR_SCHEMA)
    if repair['base_sha256'] != digest(raw):
        raise AssessmentError('assessment correction refers to a stale base_sha256')
    candidate, paths = deepcopy(raw), []
    for change in repair['replacements']:
        path = change['path']
        if not path.startswith('/') or re.search(r'~(?![01])', path):
            raise AssessmentError('invalid assessment correction JSON pointer: ' + path)
        parts = [p.replace('~1', '/').replace('~0', '~') for p in path[1:].split('/')]
        if parts[0] not in schema['properties']:
            raise AssessmentError('correction cannot set controller-derived or unknown fields: ' + path)
        if any(parts[:len(old)] == old or old[:len(parts)] == parts for old in paths):
            raise AssessmentError('overlapping assessment corrections: ' + path)
        paths.append(parts)
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
Address all reported locations, including duplicate quotations in other sections. Read the pinned source
only where needed. For an absent or invalid path, find the actual pinned path and update all affected
references and their ranges and excerpts. Imports/includes/fields use data_or_configuration.
If an evidence entry is a reference, fix the referenced unit evidence or change the index.
Function ranges must contain the declaration and stay within the file. Do not widen a mapping merely
to silence a validator.
The merged document must still cover every unit and pass ALL original evidence, scope and causal checks.
Unresolved facts must remain UNKNOWN. Do not edit source files or claim successful validation.
'''
