"""Conservative resume compatibility, including deployments without a .git tree."""
from functools import lru_cache
import hashlib
from pathlib import Path

from .lifecycle import RecoveryBlocked


PROTOCOL = 1


@lru_cache(maxsize=1)
def code_identity():
    digest = hashlib.sha256()
    for path in sorted(Path(__file__).resolve().parent.glob('*.py')):
        if path.is_symlink():
            raise RecoveryBlocked('cannot identify checkpoint code through a symlink')
        data = path.read_bytes()
        digest.update(path.name.encode() + b'\0' + len(data).to_bytes(8, 'big') + data)
    return digest.hexdigest()


def checkpoint_metadata():
    # Snapshot once when a controller is created. Saving an old record must not
    # relabel it with the current protocol or erase its original code version.
    return {'checkpoint_protocol': PROTOCOL, 'checkpoint_code_sha256': code_identity()}


def validate_checkpoint(record):
    version = record.get('checkpoint_protocol')
    if type(version) is not int or version != PROTOCOL:
        raise RecoveryBlocked('checkpoint protocol is unsupported or missing; preserve this run and start an explicitly independent new task')
    if record.get('checkpoint_code_sha256') != code_identity():
        raise RecoveryBlocked('checkpoint code version changed or is missing; restore the original deployment or start an explicitly independent new task')
