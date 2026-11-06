"""Conservative source-integration evidence; not a whole-program reachability proof."""
import re
import xml.etree.ElementTree as ET

from .activation_flow import python_activation, tree_activation
from .patches import text_hunks


def added_numbers(hunks):
    return {line['new_line'] for unit in hunks for hunk in text_hunks(unit['patch'])
            for line in hunk['lines'] if line['marker'] == '+'}


def activation(path, baseline, candidate, hunks, identities, *, new_source):
    """Production entry point: an actual new source and bound edge are required."""
    from .case import validate_relative_path
    if not isinstance(new_source, dict) or not isinstance(new_source.get('text'), str):
        raise ValueError('new-file activation requires the actual new source text and path')
    validate_relative_path(new_source.get('path'))
    if max(len(text.encode()) for text in (baseline, candidate, new_source['text'])) > 4 * 1024 * 1024:
        return None
    return _activation(path, baseline, candidate, hunks, identities, new_source=new_source)


def local_flow_probe(path, baseline, candidate, hunks, identities):
    """Diagnostic-only flow filter. Its NOT_CHECKED binding cannot pass export."""
    return _activation(path, baseline, candidate, hunks, identities)


def _activation(path, baseline, candidate, hunks, identities, *, new_source=None):
    """Return an added call in an existing function or a new manifest component.

    The production gate supplies new_source={path, text}; names-only callers
    obtain a flow probe explicitly marked binding NOT_CHECKED, never a bound
    production-file result. No credit for comments, log strings, imports, tests,
    build inclusion or newly invented caller functions. Unsupported dynamic
    registration requires a future typed evidence adapter and fails closed here.
    """
    changed = added_numbers(hunks)
    names = {s for s in identities if re.fullmatch(r'[A-Za-z_$][\w$]*', s)}
    suffix = path.rsplit('.', 1)[-1]
    if path.endswith('AndroidManifest.xml'):
        try:
            def components(text):
                android = '{http://schemas.android.com/apk/res/android}'
                result = {}
                for app in ET.fromstring(text).iter('application'):
                    if app.get(android + 'enabled', 'true').lower() == 'false': continue
                    for node in (app, *list(app)):
                        if node.tag not in {'activity', 'service', 'receiver', 'provider', 'application'}: continue
                        if node.get(android + 'enabled', 'true').lower() == 'false': continue
                        result[(node.tag, node.get(android + 'name'))] = [value for value in
                            (app.get(android + 'enabled', 'true'), node.get(android + 'enabled', 'true'))
                            if value.lower() != 'true']
                return result
            before, after = components(baseline), components(candidate)
            for tag, name in sorted(set(after) - set(before), key=str):
                if name and (new_source or name.rsplit('.', 1)[-1] in names):
                    binding = None
                    if new_source:
                        from .activation_binding import manifest_binding
                        binding = manifest_binding(new_source['path'], new_source['text'], name,
                                                   ET.fromstring(candidate).get('package', ''))
                        if not binding: continue
                    return {'path': path, 'kind': 'manifest_component', 'identifier': name,
                            'component': tag, 'scope': 'manifest_registration_only',
                            'unresolved_conditions': after[(tag, name)], 'production_reachability_proven': False,
                            'binding': binding or {'status': 'NOT_CHECKED'}}
        except ET.ParseError:
            return None
        return None
    if max(len(baseline.encode()), len(candidate.encode())) > 4 * 1024 * 1024:
        return None  # No unbounded parser input or fallback to token matching.
    try:
        bind = None
        if new_source:
            from .activation_binding import binding_for
            if len(new_source['text'].encode()) > 4 * 1024 * 1024: return None
            bind = binding_for(new_source['path'], new_source['text'], path)
            if bind is None: return None
        check = python_activation if suffix == 'py' else tree_activation
        return check(path, baseline, candidate, changed, names, bind=bind)
    except RecursionError:
        return None
