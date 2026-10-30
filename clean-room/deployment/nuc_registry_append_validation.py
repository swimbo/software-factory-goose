"""Pure registry append proposal validator; not an installer or grant authority.

The authoritative Rust loader still validates file ownership, hashes, protected
historical pins and the qualified fingerprint. This code never reads files,
changes a registry, restarts a service or requests a claim.
"""
import json,re
ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z');DIGEST=re.compile(r'[0-9a-f]{64}\Z');NAME=re.compile(r'[a-z0-9][a-z0-9.-]{0,74}\.json\Z')
ENTRY={'config','evidence','config_sha256','evidence_sha256','catalog_sha256'}

def denied(msg):raise ValueError(msg)
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:denied('duplicate JSON field')
  d[k]=v
 return d
def decode(raw):
 if not isinstance(raw,bytes) or len(raw)>65536:denied('manifest bound')
 try:return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:denied('nonfinite JSON'))
 except (UnicodeError,json.JSONDecodeError):denied('invalid JSON')
def validate_manifest(m):
 if not isinstance(m,dict) or set(m)!={'schema','active_intent','entries'} or type(m['schema']) is not int or m['schema']!=1 or not isinstance(m['active_intent'],str) or not ID.fullmatch(m['active_intent']) or not isinstance(m['entries'],list) or not 4<=len(m['entries'])<=16:denied('registry shape')
 seen=set()
 for e in m['entries']:
  if not isinstance(e,dict) or set(e)!=ENTRY:denied('entry shape')
  for field in ('config','evidence'):
   name=e[field]
   if not isinstance(name,str) or not NAME.fullmatch(name) or '..' in name or name in seen:denied('entry filename')
   seen.add(name)
  for field in ('config_sha256','evidence_sha256','catalog_sha256'):
   if not isinstance(e[field],str) or not DIGEST.fullmatch(e[field]):denied('entry digest')
 return m

def validate_append(old_raw,new_raw,previous_scopes,new_active_scope):
 """Check only append invariants on independently authenticated Rust scopes.

 All scopes must be provided by the protected Rust loader in a future caller;
 arbitrary client-provided scopes must never be treated as launch authority.
 """
 old=validate_manifest(decode(old_raw));new=validate_manifest(decode(new_raw))
 if len(old['entries'])>=16 or new['entries'][:-1]!=old['entries'] or len(new['entries'])!=len(old['entries'])+1:denied('history changed or capacity exhausted')
 if not isinstance(previous_scopes,list) or len(previous_scopes)!=len(old['entries']):denied('history scope count')
 for scope in [*previous_scopes,new_active_scope]:
  if not isinstance(scope,dict) or set(scope)!={'intent_id','task_id','generation','catalog_sha256'} or any(not isinstance(scope[k],str) or not ID.fullmatch(scope[k]) for k in ('intent_id','task_id')) or (scope['generation'] is not None and (not isinstance(scope['generation'],str) or not ID.fullmatch(scope['generation']))) or not isinstance(scope['catalog_sha256'],str) or not DIGEST.fullmatch(scope['catalog_sha256']):denied('scope invalid')
 if sum(scope['intent_id']==old['active_intent'] for scope in previous_scopes)!=1 or new_active_scope['intent_id']!=new['active_intent']:denied('active intent mismatch')
 if new_active_scope['generation'] is None or any(new_active_scope[k] in {scope[k] for scope in previous_scopes} for k in ('intent_id','task_id','generation')):denied('scope reused')
 if any(e['catalog_sha256']!=scope['catalog_sha256'] for e,scope in zip(old['entries'],previous_scopes)) or new['entries'][-1]['catalog_sha256']!=new_active_scope['catalog_sha256']:denied('catalog mismatch')
 if new_active_scope['catalog_sha256'] in {e['catalog_sha256'] for e in old['entries']}:denied('catalog reused')
 return {'previous_count':len(old['entries']),'new_count':len(new['entries']),'new_intent':new_active_scope['intent_id'],'new_generation':new_active_scope['generation'],'requires_rust_loader':True,'admission_authorized':False}
