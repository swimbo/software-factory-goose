"""Strict candidate SDK5 admission receipt contract; no producer is trusted yet.

The caller must derive expected bindings independently from protected root/PID1
state, hold the registry admission lock, and revalidate the live endpoint and
retirement fences. Parsing this receipt alone never establishes those facts.
"""
import json,re

PRODUCER_SHA256=None
MAX_BYTES=16384
SDK5_INTENT='01M66XF6HPWC3NXMAFDHKHDSP7'
SDK5_TASK='01M66XF6HPKEC38CJJP78KQJVC'
SDK5_GENERATION='01M66XF6HPBETAJ5V0G45TM8NQ'
OLD_ENDPOINTS=(('software-factory-goose-private-runtime.service',9081),('software-factory-goose-grant-canary-runtime.service',9082),('software-factory-goose-real-runtime.service',9083),('software-factory-goose-registry-runtime.service',9084))

def require(value,message):
    if not value:raise ValueError(message)
def digest(v):return isinstance(v,str) and re.fullmatch(r'[0-9a-f]{64}',v) is not None
def positive(v):return type(v) is int and v>0
def object_keys(value,keys):return isinstance(value,dict) and set(value)==set(keys)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()+b'\n'
def parse(raw):
    require(isinstance(raw,bytes) and 0<len(raw)<=MAX_BYTES,'receipt size invalid')
    def pairs(values):
        out={}
        for key,value in values:
            require(key not in out,'duplicate receipt field');out[key]=value
        return out
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite value')))
    require(canonical(value)==raw,'receipt encoding not canonical')
    return value

def validate(raw,expected):
    """Validate exact receipt and independent trusted bindings; does not attest liveness."""
    v=parse(raw)
    keys=('schema','producer_sha256','boot_id','private_namespace_dev','private_namespace_ino','registry_sha256','transition_id','sdk5','admin','ingress','retired')
    require(object_keys(v,keys) and type(v['schema']) is int and v['schema']==1,'receipt schema invalid')
    required=('producer_sha256','boot_id','private_namespace_dev','private_namespace_ino','registry_sha256','transition_id','deployment_id','process_manifest_sha256','admin_socket_dev','admin_socket_ino')
    require(object_keys(expected,required),'independent bindings missing')
    for key in ('producer_sha256','boot_id','private_namespace_dev','private_namespace_ino','registry_sha256','transition_id'):
        require(v[key]==expected[key],'independent binding mismatch')
    require(digest(v['producer_sha256']) and digest(v['registry_sha256']) and isinstance(v['boot_id'],str) and re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',v['boot_id']) and positive(v['private_namespace_dev']) and positive(v['private_namespace_ino']) and isinstance(v['transition_id'],str) and re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',v['transition_id']),'scope invalid')
    sdk=v['sdk5'];require(object_keys(sdk,('intent_id','task_id','generation','deployment_id','uri','process_manifest_sha256')),'SDK5 schema invalid')
    require((sdk['intent_id'],sdk['task_id'],sdk['generation'],sdk['uri'])==(SDK5_INTENT,SDK5_TASK,SDK5_GENERATION,'http://127.0.0.1:9085') and sdk['deployment_id']==expected['deployment_id'] and isinstance(sdk['deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',sdk['deployment_id']) and sdk['process_manifest_sha256']==expected['process_manifest_sha256'] and digest(sdk['process_manifest_sha256']),'SDK5 binding invalid')
    admin=v['admin'];require(object_keys(admin,('socket_dev','socket_ino','unix_only','sdk_uid_denied','trusted_journal_uid_allowed','no_inherited_admin_fd')),'admin schema invalid')
    require(positive(admin['socket_dev']) and positive(admin['socket_ino']) and admin['socket_dev']==expected['admin_socket_dev'] and admin['socket_ino']==expected['admin_socket_ino'] and all(admin[k] is True for k in ('unix_only','sdk_uid_denied','trusted_journal_uid_allowed','no_inherited_admin_fd')),'admin proof invalid')
    ingress=v['ingress'];require(object_keys(ingress,('port','old_forwarding_denied','unresolved_overlap_count','inventory_sha256','observation_sha256')),'ingress schema invalid')
    require(type(ingress['port']) is int and ingress['port']==8080 and ingress['old_forwarding_denied'] is True and type(ingress['unresolved_overlap_count']) is int and ingress['unresolved_overlap_count']==0 and digest(ingress['inventory_sha256']) and digest(ingress['observation_sha256']),'ingress or pending-work proof invalid')
    retired=v['retired'];require(isinstance(retired,list) and len(retired)==len(OLD_ENDPOINTS),'retirement set invalid')
    for entry,(unit,port) in zip(retired,OLD_ENDPOINTS):
        require(object_keys(entry,('unit','port','fence_sha256','stop_receipt_sha256','no_job','cgroup_empty','listener_closed','serving_fds_closed','restart_denied')),'retirement schema invalid')
        require(entry['unit']==unit and type(entry['port']) is int and entry['port']==port and digest(entry['fence_sha256']) and digest(entry['stop_receipt_sha256']) and all(entry[k] is True for k in ('no_job','cgroup_empty','listener_closed','serving_fds_closed','restart_denied')),'retirement proof invalid')
    return v
