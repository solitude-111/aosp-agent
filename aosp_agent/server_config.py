"""One strict JSON configuration for the unattended wrapper, never case answers."""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
from urllib.parse import urlsplit


AGENT_KEYS = {
    'model', 'model_provider', 'mapping_model', 'turn_timeout', 'max_projects', 'max_rounds',
    'investigation_seconds', 'max_git_operations', 'max_model_turns', 'max_output_bytes',
    'max_read_bytes', 'case_timeout', 'candidate_attempts', 'location_attempts',
    'impact_attempts', 'report_corrections', 'auto_validation', 'locate_first',
    'max_stage_extensions', 'extension_seconds',
}
PREPARATION_DEFAULTS = {'local_command_timeout': 60, 'fetch_timeout': 180, 'max_fetches': 128, 'max_ref_queries': 4096,
    'max_fetch_file_bytes': 512 * 1024 * 1024, 'max_cache_bytes': 32 * 1024**3,
    'min_free_bytes': 2 * 1024**3, 'max_seconds': 3600, 'allow_fetch': True}
REQUIRED_PATHS = {'source_root', 'donor_root', 'cache_root', 'isolation_root', 'run_root'}
TOP_KEYS = REQUIRED_PATHS | {'version', 'manifest_origin', 'manifest_name', 'allowed_upstreams',
    'donor_map', 'agent', 'preparation', 'build', 'credential_reference', 'batch_limits', 'retry_policy'}


def safe_origin(value):
    if not isinstance(value, str):
        raise ValueError('upstream must be an HTTPS URL')
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or any(x in parsed.path.split('/') for x in ('.', '..'))):
        raise ValueError('upstream must be HTTPS without credentials, query, fragment or dot segments')
    return value.rstrip('/')


def validate_config(raw):
    if not isinstance(raw, dict) or set(raw) - TOP_KEYS:
        raise ValueError('unknown server configuration field; case-specific overrides are forbidden')
    if raw.get('version', 1) != 1 or REQUIRED_PATHS - set(raw):
        raise ValueError('server configuration needs version 1 and all environment paths')
    config = deepcopy(raw)
    config['version'] = 1
    for key in REQUIRED_PATHS:
        value = config[key]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError(key + ' must be an absolute path')
        config[key] = str(Path(value).resolve())
    source = Path(config['source_root'])
    for key in ('cache_root', 'isolation_root', 'run_root'):
        if Path(config[key]).is_relative_to(source):
            raise ValueError(key + ' must be outside the shared source tree')
    if len({config[k] for k in ('cache_root', 'isolation_root', 'run_root')}) != 3:
        raise ValueError('cache, isolation and run roots must be distinct')
    origins = config.get('allowed_upstreams', ['https://android.googlesource.com'])
    if not isinstance(origins, list) or not origins:
        raise ValueError('allowed_upstreams must be a nonempty list')
    config['allowed_upstreams'] = [safe_origin(v) for v in origins]
    config['manifest_origin'] = safe_origin(config.get('manifest_origin', 'https://android.googlesource.com/platform/manifest'))
    from .case import validate_relative_path
    config['manifest_name'] = validate_relative_path(config.get('manifest_name', 'default.xml'))
    agent = config.get('agent', {})
    if not isinstance(agent, dict) or set(agent) - AGENT_KEYS:
        raise ValueError('agent settings may not inject repository, target files, validation or modules')
    config['agent'] = {'model': 'deepseek-flash', 'model_provider': 'deepseek',
                       'locate_first': True, **agent}
    for key, value in config['agent'].items():
        if key in ('auto_validation', 'locate_first'):
            if type(value) is not bool: raise ValueError(key + ' must be boolean')
        elif key in ('model', 'model_provider', 'mapping_model'):
            if not isinstance(value, str) or not value: raise ValueError(key + ' must be nonempty text')
        elif key == 'max_stage_extensions':
            if type(value) is not int or value < 0: raise ValueError(key + ' must be a nonnegative integer')
        elif (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
              or value <= 0 or key not in ('turn_timeout', 'investigation_seconds', 'case_timeout', 'extension_seconds')
              and type(value) is not int):
            raise ValueError(key + ' must be positive')
    preparation = config.get('preparation', {})
    if not isinstance(preparation, dict) or set(preparation) - set(PREPARATION_DEFAULTS):
        raise ValueError('unknown preparation setting')
    config['preparation'] = {**PREPARATION_DEFAULTS, **preparation}
    for key, value in config['preparation'].items():
        if key == 'allow_fetch':
            if type(value) is not bool: raise ValueError('allow_fetch must be boolean')
        elif type(value) is not int or value <= 0:
            raise ValueError(key + ' must be a positive integer')
    donors = config.get('donor_map', {})
    if not isinstance(donors, dict): raise ValueError('donor_map must be an object')
    for origin, directory in donors.items():
        if '://' in origin: safe_origin(origin)
        if not isinstance(directory, str) or not Path(directory).is_absolute():
            raise ValueError('donor map values must be local absolute cache paths')
    config['donor_map'] = donors
    build = config.get('build', {'enabled': False})
    if not isinstance(build, dict): raise ValueError('build must be an object')
    from .build_environment import validate_build_config
    config['build'] = validate_build_config(build)
    if config['build'].get('enabled'):
        roots = [source, *(Path(config[k]) for k in ('cache_root', 'isolation_root', 'run_root'))]
        build_paths = [Path(config['build'][k]).resolve() for k in ('output_root', 'tmp_root', 'baseline_cache')]
        # An overlay must never hide its own backing storage or control receipts.
        all_paths = [*roots, *build_paths]
        for index, path in enumerate(all_paths):
            for other in all_paths[index + 1:]:
                if path.is_relative_to(other) or other.is_relative_to(path):
                    raise ValueError('source, control, cache and build directories must not overlap')
    if 'credential_reference' in config and (not isinstance(config['credential_reference'], str)
            or not config['credential_reference'].startswith(('env:', 'codex:'))):
        raise ValueError('credentials must be environment/config references, not secret values')
    limits = config.get('batch_limits', {})
    allowed = {'max_output_bytes', 'min_free_bytes', 'max_model_calls', 'max_seconds'}
    if not isinstance(limits, dict) or set(limits) - allowed:
        raise ValueError('unknown batch limit')
    if any(type(v) is not int or v <= 0 for v in limits.values()):
        raise ValueError('batch limits must be positive integers')
    config['batch_limits'] = {'max_output_bytes': 1024**3, **limits}
    retry = config.get('retry_policy', {'max_terminal_retries': 1})
    if (not isinstance(retry, dict) or set(retry) != {'max_terminal_retries'}
            or type(retry['max_terminal_retries']) is not int or retry['max_terminal_retries'] < 0):
        raise ValueError('retry_policy requires a nonnegative max_terminal_retries')
    config['retry_policy'] = retry
    return config


def load_config(path, overrides=None):
    raw = json.loads(Path(path).read_text())
    for key, value in (overrides or {}).items():
        if value is None: continue
        if key in AGENT_KEYS:
            raw.setdefault('agent', {})[key] = value
        else:
            raw[key] = value
    return validate_config(raw)


def config_digest(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
