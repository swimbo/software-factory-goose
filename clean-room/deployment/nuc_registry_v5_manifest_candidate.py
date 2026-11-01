"""Construct the exact additive SDK5 manifest from independently protected inputs.

This is deterministic source preparation, not a registry write or admission.
"""
import hashlib,json
import nuc_registry_attestation_profiles as profiles

TRANSITION_ID='5DEX7YKFGSEJN362KKSRNWP262'
CONFIG='registry-v5-runtime.json'
EVIDENCE='registry-v5-evidence.json'

def require(v,msg):
 if not v:raise ValueError(msg)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()+b'\n'
def sha(v):return hashlib.sha256(v).hexdigest()
def build(old_raw,config_raw,evidence_raw):
 require(all(isinstance(x,bytes) and 0<len(x)<=65536 for x in (old_raw,config_raw,evidence_raw)),'input unavailable')
 old=profiles.decode(old_raw);cfg=profiles.decode(config_raw)
 require(isinstance(old,dict) and set(old)=={'schema','active_intent','entries'} and type(old['schema']) is int and old['schema']==1 and old['active_intent']==profiles.SDK4['intent'] and isinstance(old['entries'],list) and 1<=len(old['entries'])<16,'old manifest unavailable')
 entries=[e for e in old['entries'] if isinstance(e,dict) and e.get('config')==profiles.SDK4['config']]
 require(len(entries)==1 and entries[0].get('evidence_sha256')==sha(evidence_raw),'baseline evidence mismatch')
 require(all(isinstance(e,dict) and CONFIG!=e.get('config') and EVIDENCE!=e.get('evidence') for e in old['entries']),'new path already exists')
 scope=cfg.get('launch_scope') if isinstance(cfg,dict) else None
 require(isinstance(scope,dict) and type(cfg.get('sdk_port')) is int and cfg['sdk_port']==9085 and cfg.get('intent_id')==profiles.SDK5['intent'] and cfg.get('task_id')==profiles.SDK5['task'] and scope.get('intent_id')==profiles.SDK5['intent'] and scope.get('task_id')==profiles.SDK5['task'] and scope.get('generation')==profiles.SDK5['generation'] and isinstance(scope.get('catalog_sha256'),str) and len(scope['catalog_sha256'])==64 and all(x in '0123456789abcdef' for x in scope['catalog_sha256']),'SDK5 config mismatch')
 require(all(e.get('catalog_sha256')!=scope['catalog_sha256'] for e in old['entries']),'catalog reused')
 entry={'config':CONFIG,'evidence':EVIDENCE,'config_sha256':sha(config_raw),'evidence_sha256':sha(evidence_raw),'catalog_sha256':scope['catalog_sha256']}
 new={'schema':1,'active_intent':profiles.SDK5['intent'],'entries':[*old['entries'],entry]}
 return {'schema':1,'transition_id':TRANSITION_ID,'old_manifest_sha256':sha(old_raw),'new_manifest_sha256':sha(canonical(new)),'config_sha256':sha(config_raw),'evidence_sha256':sha(evidence_raw),'manifest':new}
