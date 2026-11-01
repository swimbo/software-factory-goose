"""Root-controlled history capture/replay coordinator, source-only and uninstalled.

Requires an already-held registry transition lock, protected old/new registry
records and a reviewed root-owned SDK restart/attestation receipt. It does not
register, restart, launch, clear a marker, or expose raw journal state.
"""
import hashlib,json,os,pathlib,re,subprocess
import nuc_registry_transition_gate as gate
import nuc_grant_sidecar_install as old
PROBE=pathlib.Path('/usr/local/libexec/software-factory-goose/registry-replay-probe.py')
PROBE_SHA='5b3afd53cf5478abcb692f4cf8db03046533bb1db23ac8e82337ce1078118499'
# Completion is withheld until the fixed SDK restart receipt producer is reviewed.
RUNTIME_RECEIPT_PRODUCER_SHA=None
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'}

def require(v,msg):
 if not v:raise RuntimeError(msg)
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def derive_targets(manifest_raw,read_config):
 manifest=gate._json(manifest_raw);require(isinstance(manifest,dict) and set(manifest)=={'schema','active_intent','entries'} and type(manifest['schema']) is int and manifest['schema']==1 and isinstance(manifest['entries'],list) and 4<=len(manifest['entries'])<=16,'registry manifest unavailable')
 result=set();names=set()
 for entry in manifest['entries']:
  require(isinstance(entry,dict) and set(entry)=={'config','evidence','config_sha256','evidence_sha256','catalog_sha256'},'registry entry unavailable')
  for key in ('config','evidence'):
   name=entry[key];require(isinstance(name,str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,74}\.json',name) and '..' not in name and name not in names,'registry path unavailable');names.add(name)
  raw=read_config(entry['config']);require(sha(raw)==entry['config_sha256'],'registry config changed');cfg=gate._json(raw)
  for service,key in (('ClaimLeaseJournal',cfg.get('task_id')),('RuntimeIntakeJournal',cfg.get('intent_id')),('WorkerQueueJournal',cfg.get('queue_id'))):
   require(isinstance(key,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}',key),'registry target unavailable')
   if service!='WorkerQueueJournal':require(re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',key),'registry ID unavailable')
   result.add((service,key))
 return [{'service':s,'key':k} for s,k in sorted(result)]
def run_probe(name,phase,targets,deployment,uri):
 require(re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',name) and phase in ('before','after'),'probe identity unavailable')
 require(sha(gate._protected_read(PROBE,0o755,1_000_000))==PROBE_SHA,'probe source unavailable')
 unit='sfactory-registry-replay-'+name.lower()+'-'+phase+'.service';require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','probe unit occupied')
 request={'schema':1,'targets':targets,'deployment_id':deployment,'sdk_uri':uri}
 argv=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=sfgoose-control','--property=Group=sfgoose-control','--property=PrivateNetwork=yes','--property=JoinsNamespaceOf=software-factory-goose-private-net.service','--property=BindsTo=software-factory-goose-private-net.service','--property=After=software-factory-goose-private-net.service','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet=','--property=AmbientCapabilities=','--property=MemoryMax=128M','--property=TasksMax=32','--property=RuntimeMaxSec=45s','/usr/bin/python3','-I','-B',str(PROBE)]
 p=subprocess.run(argv,input=canonical(request),env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=55,check=False)
 require(p.returncode==0 and len(p.stdout)<=65536 and len(p.stderr)<=8192,'replay probe outcome unknown')
 out=gate._json(p.stdout);require(isinstance(out,dict) and set(out)=={'schema','deployment_id','deployment_metadata_sha256','histories'} and out['schema']==1 and out['deployment_id']==deployment and isinstance(out['histories'],list) and len(out['histories'])==len(targets),'probe result unavailable')
 require([(x.get('service'),x.get('key')) for x in out['histories']]==[(x['service'],x['key']) for x in targets] and re.fullmatch(r'[0-9a-f]{64}',out['deployment_metadata_sha256']),'probe scope changed')
 return out

def assert_attestor(registry_raw):
 profile=gate.registry_profile(registry_raw)
 require(sha(gate._protected_read(profile['probe'],0o755,10_000_000))==profile['probe_sha256'],'attestor executable changed')
 p=subprocess.run([str(profile['probe'])],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=50,check=False,env=ENV)
 require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192 and gate._json(p.stdout)=={'service_attested':True,'grant_requested':False},'registry attestor unavailable')
 return profile
def load_transition_plan(intent):
 name=intent['transition_id'];raw=gate._protected_read(gate.ROOT/'history'/(name+'.plan.json'),0o600,16384);plan=gate._json(raw)
 keys={'schema','transition_id','old_manifest_sha256','new_manifest_sha256','old_deployment_id','old_sdk_uri','new_deployment_id','new_sdk_uri'}
 require(set(plan)==keys and type(plan['schema']) is int and plan['schema']==1 and plan['transition_id']==name and plan['old_manifest_sha256']==intent['old_manifest_sha256'] and plan['new_manifest_sha256']==intent['new_manifest_sha256'],'transition plan mismatch')
 require(isinstance(plan['old_deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',plan['old_deployment_id']),'old deployment ID unavailable')
 require(plan['new_deployment_id'] is None or (isinstance(plan['new_deployment_id'],str) and re.fullmatch(r'dp_[A-Za-z0-9]{1,80}',plan['new_deployment_id'])),'new deployment ID unavailable')
 for key in ('old_sdk_uri','new_sdk_uri'):require(plan[key] in ('http://127.0.0.1:9084','http://127.0.0.1:9085'),'SDK endpoint unavailable')
 return plan,sha(raw)
def capture_before(intent,old_deployment,old_uri):
 name=intent['transition_id'];plan,_=load_transition_plan(intent);require((old_deployment,old_uri)==(plan['old_deployment_id'],plan['old_sdk_uri']),'old deployment differs from root plan');hist=gate.ROOT/'history';marker=gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000);require(gate._json(marker)==intent,'transition changed')
 raw=gate._protected_read(gate.REGISTRY,0o644,65536);require(sha(raw)==intent['old_manifest_sha256'],'old registry changed');profile=assert_attestor(raw);require(old_uri=='http://127.0.0.1:'+str(profile['port']),'old SDK profile mismatch')
 targets=derive_targets(raw,lambda name:gate._protected_read(gate.REGISTRY.parent/name,0o644,65536))
 gate._store_history(hist,name+'.old-registry.json',raw)
 gate._store_history(hist,name+'.before-started.json',canonical({'schema':1,'transition_id':name,'phase':'before'})+b'\n')
 result=run_probe(name,'before',targets,old_deployment,old_uri)
 baseline={'schema':1,'transition_id':name,'old_manifest_sha256':sha(raw),'targets':targets,'histories':result['histories'],'old_deployment_id':old_deployment,'old_deployment_metadata_sha256':result['deployment_metadata_sha256']}
 gate._store_history(hist,name+'.baseline.json',canonical(baseline)+b'\n');return baseline

def capture_after(intent):
 # No caller may assert successful SDK registration. A future reviewed root
 # restart/attestation producer must mint the fixed runtime receipt first.
 require(RUNTIME_RECEIPT_PRODUCER_SHA is not None,'reviewed SDK restart receipt producer unavailable')
 name=intent['transition_id'];plan,plan_sha=load_transition_plan(intent);hist=gate.ROOT/'history';require(gate._json(gate._protected_read(gate.ROOT/gate.MARKER,0o440,4096,2000))==intent,'transition changed')
 baseline=gate._json(gate._protected_read(hist/(name+'.baseline.json'),0o600,65536));runtime=gate._json(gate._protected_read(hist/(name+'.runtime.json'),0o600,16384))
 require(set(runtime)=={'schema','transition_id','producer_sha256','deployment_id','sdk_uri','attestation_sha256','manifest_sha256','boot_id'} and runtime['schema']==1 and runtime['transition_id']==name and runtime['producer_sha256']==RUNTIME_RECEIPT_PRODUCER_SHA and runtime['manifest_sha256']==intent['new_manifest_sha256'] and runtime['deployment_id']==gate.resolve_deployment(plan,hist) and runtime['sdk_uri']==plan['new_sdk_uri'],'runtime receipt invalid')
 newraw=gate._protected_read(gate.REGISTRY,0o644,65536);oldraw=gate._protected_read(hist/(name+'.old-registry.json'),0o600,65536);require(sha(newraw)==intent['new_manifest_sha256'] and sha(oldraw)==intent['old_manifest_sha256'],'registry changed');profile=assert_attestor(newraw);require(runtime['sdk_uri']=='http://127.0.0.1:'+str(profile['port']),'new SDK profile mismatch');att=gate._protected_read(profile['attestation'],0o600,16384);boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 require(sha(att)==runtime['attestation_sha256'] and runtime['boot_id']==boot,'new identity changed')
 targets=derive_targets(oldraw,lambda file:gate._protected_read(gate.REGISTRY.parent/file,0o644,65536));require(baseline['transition_id']==name and baseline['old_manifest_sha256']==sha(oldraw) and baseline['targets']==targets,'baseline changed')
 gate._store_history(hist,name+'.after-started.json',canonical({'schema':1,'transition_id':name,'phase':'after'})+b'\n')
 result=run_probe(name,'after',targets,runtime['deployment_id'],runtime['sdk_uri']);require(result['histories']==baseline['histories'],'prior journal history changed')
 oldmanifest=gate._json(oldraw);receipt={'schema':1,'transition_id':name,'old_manifest_sha256':sha(oldraw),'new_manifest_sha256':sha(newraw),'prior_catalogs_sha256':sha(canonical(oldmanifest['entries'])),'prior_catalog_count':len(oldmanifest['entries']),'replayed_catalog_count':len(oldmanifest['entries']),'deployment_id':runtime['deployment_id'],'attestation_sha256':sha(att),'producer_sha256':PROBE_SHA,'plan_sha256':plan_sha}
 gate._store_history(hist,name+'.replay.json',canonical(receipt)+b'\n');return receipt
