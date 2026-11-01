"""Pure proposed before/after comparator; it collects and authenticates no host data."""
import re
from nuc_sdk5_admission_receipt import OLD_ENDPOINTS

def require(ok,message):
    if not ok:raise ValueError(message)
def keys(value,items):return isinstance(value,dict) and set(value)==set(items)
def positive(value):return type(value) is int and value>0
def digest(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None
def invocation(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{32}',value) is not None

def validate(before,after,approved_config_sha256):
    """Compare independently authenticated snapshots; inputs are never authority by themselves."""
    snapshot=('schema','stable','restate','old_sdks')
    stable=('boot_id','host_namespace_dev','host_namespace_ino','private_namespace_dev','private_namespace_ino','anchor_pid','anchor_invocation','postgres_pid','postgres_invocation','postgres_system_identifier','postgres_data_dev','postgres_data_ino','other_services_sha256')
    restate=('unit','pid','invocation','binary_sha256','data_dev','data_ino','node','config_sha256')
    for value in (before,after):
        require(keys(value,snapshot) and type(value['schema']) is int and value['schema']==1 and keys(value['stable'],stable) and keys(value['restate'],restate),'snapshot schema invalid')
        s=value['stable'];require(isinstance(s['boot_id'],str) and re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',s['boot_id']) and all(positive(s[k]) for k in ('host_namespace_dev','host_namespace_ino','private_namespace_dev','private_namespace_ino','anchor_pid','postgres_pid','postgres_data_dev','postgres_data_ino')) and isinstance(s['postgres_system_identifier'],str) and s['postgres_system_identifier'].isdigit() and len(s['postgres_system_identifier'])<=20 and 0<int(s['postgres_system_identifier'])<2**64 and invocation(s['anchor_invocation']) and invocation(s['postgres_invocation']) and digest(s['other_services_sha256']),'stable identity invalid')
        require((s['host_namespace_dev'],s['host_namespace_ino'])!=(s['private_namespace_dev'],s['private_namespace_ino']),'namespace collision')
        r=value['restate'];require(r['unit']=='software-factory-goose-private-restate.service' and r['node']=='sfgoose-private' and positive(r['pid']) and invocation(r['invocation']) and digest(r['binary_sha256']) and digest(r['config_sha256']) and positive(r['data_dev']) and positive(r['data_ino']),'restate identity invalid')
        require(isinstance(value['old_sdks'],list) and len(value['old_sdks'])==4,'legacy set invalid')
    require(before['stable']==after['stable'],'stable infrastructure changed')
    b=before['restate'];a=after['restate'];require(all(b[k]==a[k] for k in ('unit','binary_sha256','data_dev','data_ino','node')) and b['pid']!=a['pid'] and b['invocation']!=a['invocation'] and digest(approved_config_sha256) and a['config_sha256']==approved_config_sha256,'unapproved Restate delta')
    for b,a,(unit,port) in zip(before['old_sdks'],after['old_sdks'],OLD_ENDPOINTS):
        require(keys(b,('unit','port','identity_sha256')) and keys(a,('unit','port','identity_sha256','retirement_receipt_sha256','retired')) and b['unit']==a['unit']==unit and type(b['port']) is int and type(a['port']) is int and b['port']==a['port']==port and digest(b['identity_sha256']) and a['identity_sha256']==b['identity_sha256'] and digest(a['retirement_receipt_sha256']) and a['retired'] is True,'legacy retirement delta invalid')
    return True
