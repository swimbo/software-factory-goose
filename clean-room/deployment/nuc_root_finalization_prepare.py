"""Create-only unknown finalization inputs for the already closed r2 generation.

Does not publish authorization, start a unit, call the journal or alter a fence.
The native publisher must independently validate these protected inputs again.
"""
import hashlib
import json
import os

import nuc_grant_sidecar_install as old

G = '01M65RMR3F04YB1B016EBBSXGG'
TASK = '01M65RMR3FE6FQTFRBHERRHXRG'
STOP = old.pathlib.Path('/var/lib/software-factory-goose/stop')
DEST = old.ETC / 'finalization'
REQUEST = STOP / (G + '.root-finalization-request.json')
CONFIG = DEST / (G + '.runtime.json')
INTENT = old.ETC / (G + '.finalization-prepare-started.json')
DONE = old.ETC / (G + '.finalization-prepare-complete.json')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            old.require(key not in out, 'duplicate JSON field')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid number')))


def build(grant, catalog, recipe, observation, runtime, digests):
    reservation = grant['reservation']
    scope = reservation['scope']
    old.require(grant['schema'] == 1 and grant['generation'] == G
                and reservation['generation'] == G and scope['generation'] == G
                and scope['task_id'] == TASK and catalog['scope'] == scope,
                'fixed generation binding mismatch')
    left, right = canonical(reservation), canonical(catalog)
    binding = sha(b'sfactory-root-grant-v1\0' + len(left).to_bytes(8, 'big')
                  + left + len(right).to_bytes(8, 'big') + right)
    old.require(binding == grant['binding_sha256']
                and sha(canonical(recipe)) == catalog['recipe_sha256']
                and recipe['generation'] == G and recipe['task_id'] == TASK,
                'root recipe or reservation binding mismatch')
    old.require(observation['target_id'] == G
                and observation['boot_id'] == catalog['boot_id']
                and observation['cgroup_dev'] == catalog['cgroup_dev']
                and observation['cgroup_ino'] == catalog['cgroup_ino']
                and observation['observed'] is True
                and type(observation['observed_at_unix']) is int
                and observation['engine_reconciled'] is False,
                'unknown observation mismatch')
    request = {'schema': 1, 'reservation': reservation, 'catalog': catalog,
               'recipe': recipe, 'binding_sha256': binding, 'spend': 'unknown',
               'evidence': {'kind': 'unknown', 'phase': 'cleanup',
                            'reason': 'outcome_unknown',
                            'observation_sha256': digests['observation']}}
    raw = canonical(request) + b'\n'
    cfg = {key: runtime[key] for key in ('boot_id', 'namespace_dev', 'namespace_ino',
                                        'host_namespace_dev', 'host_namespace_ino')}
    old.require(cfg['boot_id'] == catalog['boot_id'], 'historical boot mismatch')
    cfg.update(schema=1, generation=G, scope=scope, request_sha256=sha(raw),
               **{key + '_sha256': value for key, value in digests.items()})
    return raw, canonical(cfg) + b'\n'


def inputs():
    paths = {'grant': STOP / (G + '.grant-verified'),
             'catalog': old.ETC / 'launch-catalog' / (G + '.json'),
             'recipe': old.ETC / 'launch-catalog' / (G + '.recipe.json'),
             'observation': STOP / (G + '.observation')}
    raw = {key: old.read(path, 0o600) for key, path in paths.items()}
    runtime = strict(old.read(old.ETC / 'registry-next-runtime.json', 0o644,
                             'd413213318a6555c62fc24ffa848c1dda42db510d92a1160c6f86f20a803b23b'))
    return build(**{key: strict(value) for key, value in raw.items()},
                 runtime=runtime, digests={key: sha(value) for key, value in raw.items()})


def plan():
    old.require(os.geteuid() == 0 and os.getegid() == 0, 'root required')
    old.directory(old.ETC, 0, 0, 0o711)
    old.directory(STOP, 0, 0, 0o700)
    old.directory(old.ETC / 'launch-catalog', 0, 0, 0o700)
    for path in (INTENT, DONE, REQUEST, CONFIG):
        old.require(not os.path.lexists(path), 'retained preparation occupied')
    if os.path.lexists(DEST):
        old.directory(DEST, 0, 0, 0o755)
    request, config = inputs()
    cfg = strict(config)
    old.require(cfg['boot_id'] == old.pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'current boot mismatch')
    return {'generation': G, 'task': TASK, 'request_sha256': sha(request),
            'config_sha256': sha(config), 'scope': 'unknown inputs only; no authorization or activation'}


def apply(reviewed):
    old.require(plan() == reviewed, 'preparation plan changed')
    request, config = inputs()
    old.require(sha(request) == reviewed['request_sha256']
                and sha(config) == reviewed['config_sha256'], 'inputs changed')
    old.store(INTENT, canonical(reviewed) + b'\n', 0o600)
    if not os.path.lexists(DEST):
        os.mkdir(DEST, 0o755)
        os.chmod(DEST, 0o755)
        old.syncdir(old.ETC)
    old.store(REQUEST, request, 0o600)
    old.store(CONFIG, config, 0o600)
    result = {'generation': G, 'prepared': True, 'authorized': False, 'activated': False}
    old.store(DONE, canonical(result) + b'\n', 0o600)
    return result
