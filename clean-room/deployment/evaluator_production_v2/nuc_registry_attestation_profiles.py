"""Fixed registry profile selection from protected active catalog/config bytes.

A caller must authenticate the manifest and config files and hold the registry
admission/transition lock. Selection alone never proves a process is live.
"""
import hashlib,json,pathlib,re
ETC=pathlib.Path('/etc/software-factory-goose')
PREFIX=pathlib.Path('/usr/local/libexec/software-factory-goose')
SDK4={'profile':'sdk4','intent':'01M65RMR3F959RPSERJ681DQ43','task':'01M65RMR3FE6FQTFRBHERRHXRG','generation':'01M65RMR3F04YB1B016EBBSXGG','config':'registry-next-runtime.json','port':9084,'attestation':ETC/'registry-process-attestation.json','probe':PREFIX/'registry-attestor-probe','probe_sha256':'aa2868160da22acbdae103c118f952cc8d8675fe31b0558dec969c7f96b21642'}
SDK5={'profile':'sdk5','intent':'01M66XF6HPWC3NXMAFDHKHDSP7','task':'01M66XF6HPKEC38CJJP78KQJVC','generation':'01M66XF6HPBETAJ5V0G45TM8NQ','config':'registry-v5-runtime.json','port':9085,'attestation':ETC/'registry-v5-process-attestation.json','probe':PREFIX/'registry-v5-attestor-probe','probe_sha256':'f24c28e5be506ccde5272fc4b8ba30330b65f2d11f79b4dc989926d0d0d684dd'}

def decode(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise RuntimeError('duplicate profile JSON field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(RuntimeError('invalid number')))
def select_for_registry(raw,read_config):
    manifest=decode(raw)
    if not isinstance(manifest,dict) or set(manifest)!={'schema','active_intent','entries'} or type(manifest['schema']) is not int or manifest['schema']!=1 or not isinstance(manifest['entries'],list):raise RuntimeError('registry profile manifest invalid')
    matches=[v for v in (SDK4,SDK5) if v['intent']==manifest['active_intent']]
    if len(matches)!=1:raise RuntimeError('unsupported active registry profile')
    selected=matches[0];entries=[e for e in manifest['entries'] if isinstance(e,dict) and e.get('config')==selected['config']]
    if len(entries)!=1 or set(entries[0])!={'config','evidence','config_sha256','evidence_sha256','catalog_sha256'}:raise RuntimeError('profile entry invalid')
    entry=entries[0];config_raw=read_config(ETC/selected['config'])
    if hashlib.sha256(config_raw).hexdigest()!=entry['config_sha256']:raise RuntimeError('profile config digest mismatch')
    cfg=decode(config_raw);scope=cfg.get('launch_scope') if isinstance(cfg,dict) else None
    if not isinstance(scope,dict) or cfg.get('sdk_port')!=selected['port'] or type(cfg.get('sdk_port')) is not int or cfg.get('intent_id')!=selected['intent'] or cfg.get('task_id')!=selected['task'] or scope.get('intent_id')!=selected['intent'] or scope.get('task_id')!=selected['task'] or scope.get('generation')!=selected['generation'] or scope.get('catalog_sha256')!=entry['catalog_sha256'] or not isinstance(entry['catalog_sha256'],str) or re.fullmatch('[0-9a-f]{64}',entry['catalog_sha256']) is None:raise RuntimeError('profile config scope mismatch')
    if selected['probe_sha256'] is None:raise RuntimeError('profile attestor probe unavailable')
    return dict(selected)
