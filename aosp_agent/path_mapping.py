"""Shared deterministic path hints; uniqueness never proves semantic equivalence."""
import re

_VERSION_COMPONENT = re.compile(r'^(?:.*?[-_])?v?\d+(?:[._]\d+)*$', re.I)


def version_normalized_paths(path):
    parts = path.split('/')
    return {'/'.join(part for i, part in enumerate(parts) if i != drop)
            for drop in range(len(parts) - 1)
            if _VERSION_COMPONENT.fullmatch(parts[drop])} - {path}
