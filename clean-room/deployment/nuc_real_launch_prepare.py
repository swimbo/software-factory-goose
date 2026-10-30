"""Fixed real-task preclaim provisioning; no claim, key read or provider call.

A fresh generation slice and callback socket are the only started units. A failed
or uncertain effect retains the root-owned intent and must never be replayed.
"""
import errno,hashlib,json,os,pathlib,re,sqlite3,stat,subprocess
import nuc_grant_sidecar_install as old
import nuc_real_sidecar_activate as real
G='01M65NEH5T767H8Q5X71TTFR5S';TASK='01M65NEH5TBPKNDW21TE6FR3XA';LOW=G.lower()
ROOT=old.ETC;RUN=old.RUN;STATE=pathlib.Path('/var/lib/software-factory-goose');SYSTEM=old.UNIT
INTENT=ROOT/(G+'.launch-prepare-started.json');DONE=ROOT/(G+'.launch-prepare-complete.json')
GOLD=pathlib.Path('/tmp/sfactory-goose-protected-c0tz3oa4/adapter-output.json');GOLD_SHA='8b3cb616a674cd37f82ebe3c9594bc08e5aa0df4fa4eb9c27d744184fa253eba'
CONFIG_SHA='1fe972454f55de3f6dd9e3f7783e810470e628a7f9da304a740412062a9dc1bf'
GOOSE_SHA='802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db'
CID='94f32c4f1399d74fffaa909c878422ee0f86bb31127e3c83c4c3dac4de03facc';IMAGE='sha256:d0b4708ace1aa175766f94afa715fd9bba3a1b56c1dc2afff15a21edf3ae4e2a';PID=3519722;NET='/var/run/docker/netns/afba2384c3c2'
KEY='/home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential'
MODELS=['deepseek-v4-pro:0813','deepseek-v4.1-flash:1017','ollama-cloud/deepseek-v4-pro:0813','ollama-cloud/deepseek-v4.1-flash:1017']
PROMPT_SUFFIX='\nUse factory__write_files exactly once to provide both full files. Do not request shell commands or any other tools. After the successful tool result, confirm completion.'

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def require(x,msg):
 if not x:raise RuntimeError(msg)
def root_json(path):return json.loads(old.read(path,0o600))
def gold():
 fd=os.open(GOLD,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);require(stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and s.st_size<=65536,'gold source invalid');data=os.read(fd,65537);require(len(data)==s.st_size and digest(data)==GOLD_SHA,'gold source changed')
 finally:os.close(fd)
 return json.loads(data)['requests'][0]['body']
def provider():
 args=['/usr/bin/docker','--host','unix:///run/docker.sock','inspect','--format','{{.Id}} {{.Image}} {{.State.Pid}} {{.State.Status}} {{.NetworkSettings.SandboxKey}}',CID]
 p=subprocess.run(args,env=old.ENV,capture_output=True,timeout=8,check=True);require(len(p.stdout)<=4096 and p.stdout.decode()==f'{CID} {IMAGE} {PID} running {NET}\n','provider identity changed')
 s=os.stat(NET);return {'schema':1,'container_id':CID,'image_id':IMAGE,'pid':PID,'network_device':s.st_dev,'network_inode':s.st_ino,'sandbox_key':NET,'port':8080}
def route():
 # Read only the factory key name and route metadata; never select or read key value.
 c=sqlite3.connect('file:/home/bo/.hermes/bifrost/config.db?mode=ro',uri=True)
 try:
  keys=c.execute('select id,is_active,allow_all_providers from governance_virtual_keys where name=?',('software-factory-goose-int-loop-c085b7e',)).fetchall();require(len(keys)==1 and keys[0][1:]==(1,0),'factory key metadata changed')
  providers=c.execute('select id,provider,allowed_models,blacklisted_models,allow_all_keys from governance_virtual_key_provider_configs where virtual_key_id=?',(keys[0][0],)).fetchall()
  require(len(providers)==1 and providers[0][1]=='ollama-cloud' and json.loads(providers[0][2])==['auto','deepseek-v4.1-flash:1017','deepseek-v4-pro:0813'] and json.loads(providers[0][3])==[] and providers[0][4]==0,'factory provider scope changed')
  require(c.execute('select count(*) from governance_virtual_key_provider_config_keys where table_virtual_key_provider_config_id=?',(providers[0][0],)).fetchone()==(1,),'factory provider key scope changed')
  rows=c.execute('select r.cel_expression,r.fallbacks,t.provider,t.model from routing_rules r join routing_targets t on t.rule_id=r.id where r.scope_id=? and r.enabled=1 order by r.priority',(keys[0][0],)).fetchall()
  expected=[('model == "auto" && complexity_tier == "COMPLEX"',None,'ollama-cloud','deepseek-v4-pro:0813'),('model == "auto" && complexity_tier == "MEDIUM"',None,'ollama-cloud','deepseek-v4.1-flash:1017'),('model == "auto"',None,'ollama-cloud','deepseek-v4.1-flash:1017')]
  require(rows==expected and c.execute('select json_extract(network_config_json,"$.max_retries") from config_providers where name=?',('ollama-cloud',)).fetchall()==[(0,)],'router metadata changed')
 finally:c.close()
 s=os.lstat(KEY);require(stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_gid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'credential metadata changed')
 try:os.getxattr(KEY,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'credential ACL unavailable')
 else:raise RuntimeError('credential ACL forbidden')
def units():
 writer='sfactorywriter'+LOW;relay='sfactoryrelay'+LOW;slice_name='sfactory'+LOW+'.slice';pkg='/usr/local/libexec/software-factory-goose/relay'
 writer_sock=f'[Unit]\nDescription=Factory fixed writer socket\n[Socket]\nListenStream={RUN}/writer/{G}.sock\nSocketUser=root\nSocketGroup=sfgoose-control\nSocketMode=0660\nFileDescriptorName=writer\nAccept=no\nService={writer}.service\n'
 writer_svc=f'[Unit]\nRequires={writer}.socket\nAfter={writer}.socket\n[Service]\nType=exec\nUser=root\nGroup=root\nSlice=system.slice\nSockets={writer}.socket\nExecStart=/usr/bin/python3 -I -B {pkg}/nuc_root_writer_service.py {G}\nRestart=no\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths={STATE}/stop {STATE}/handoff/{G}/input\nMemoryMax=256M\nTasksMax=32\nCPUQuota=100%\nLimitCORE=0\nUMask=0077\n'
 relay_sock=f'[Unit]\nDescription=Factory fixed relay socket\n[Socket]\nListenStream={RUN}/relay/{G}/relay.sock\nSocketUser=root\nSocketGroup=sfgoose-worker\nSocketMode=0660\nFileDescriptorName=callback\nAccept=no\nService={relay}.service\n'
 relay_svc=f'''[Unit]\nRequires={relay}.socket\nAfter={relay}.socket\n[Service]\nType=exec\nUser=sfgoose-control\nGroup=sfgoose-control\nSlice={slice_name}\nSockets={relay}.socket\nNetworkNamespacePath={NET}\nOpenFile={ROOT}/relay-catalog/{G}.scope.json:scope:read-only\nOpenFile={ROOT}/launch-catalog/{G}.json:catalog:read-only\nOpenFile={STATE}/stop/{G}.launch-consumed:consumed:read-only\nOpenFile={ROOT}/relay-catalog/{G}.provider.json:provider-binding:read-only\nOpenFile={KEY}:provider:read-only\nExecStart=/usr/bin/python3 -I -B {pkg}/nuc_relay_server.py\nRestart=no\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestrictAddressFamilies=AF_UNIX AF_INET\nIPAddressDeny=any\nIPAddressAllow=localhost\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths={STATE}/relay/{G}\nMemoryMax=256M\nTasksMax=32\nCPUQuota=100%\nLimitCORE=0\nUMask=0077\n'''
 slice_unit='[Unit]\nDescription=Factory fixed generation slice\n[Slice]\nMemoryMax=2G\nTasksMax=128\nCPUQuota=200%\n'
 return {writer+'.socket':writer_sock.encode(),writer+'.service':writer_svc.encode(),relay+'.socket':relay_sock.encode(),relay+'.service':relay_svc.encode(),slice_name:slice_unit.encode()}
def artifacts(cfg,bind,images):
 scope=cfg['launch_scope'];require(scope['generation']==G and scope['task_id']==TASK and scope['catalog_sha256']=='cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7','real scope changed')
 prompt=(cfg['request']['intent']+PROMPT_SUFFIX).encode();body=gold();require(body['model']=='gpt-4o-mini' and len(body['messages'])==2 and body['messages'][0]['role']=='system' and body['messages'][1]['role']=='user','gold request mismatch');body['messages'][1]['content']=prompt.decode()
 request_sha=digest(canonical(body));provider_raw=canonical(bind)
 core={'purpose':'nuc-goose-write-files-v1','generation':G,'task_id':TASK,'worker_uid':2001,'goose_binary_sha256':GOOSE_SHA,'worker_image_id':images['worker']['image_id'],'worker_program_sha256':images['worker']['program_sha256'],'writer_image_id':images['writer']['image_id'],'writer_program_sha256':images['writer']['program_sha256'],'fixed_parent':'sfactory'+LOW+'.slice'}
 profile=canonical({'schema':1,'profile':'nuc-root-supervised-stdio-v1','task_id':TASK,'generation':G,'recipe_sha256':digest(canonical(core)),'worker_uid':2001})
 template=canonical({'schema':2,'request_contract':'goose-turn-context-v1','generation':G,'task_id':TASK,'request_sha256':request_sha,'allowed_models':MODELS,'provider_binding_sha256':digest(provider_raw)})
 recipe={'schema':1,**core,'profile_sha256':digest(profile),'prompt_sha256':digest(prompt),'relay_scope_template_sha256':digest(template),'provider_binding_sha256':digest(provider_raw)}
 return prompt,profile,template,provider_raw,recipe

def directory(path,uid,gid,mode,create=False):
 path=pathlib.Path(path)
 if not os.path.lexists(path):
  require(create,'required directory missing');os.mkdir(path,mode);os.chmod(path,mode)
  if (uid,gid)!=(0,0):os.chown(path,uid,gid)
  old.syncdir(path.parent)
 old.directory(path,uid,gid,mode)

def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (INTENT,DONE)),'preparation already attempted')
 # Root-only catalog, active prior services and a separately installed package are prerequisites.
 for path,uid,gid,mode in [(ROOT,0,0,0o711),(RUN,0,0,0o755),(STATE,0,0,0o711),(STATE/'stop',0,0,0o700),(ROOT/'tasks',0,0,0o700),(old.PREFIX/'relay',0,0,0o755)]:old.directory(path,uid,gid,mode)
 cfg=json.loads(old.read(ROOT/'real-runtime.json',0o644,CONFIG_SHA));require(cfg['sdk_port']==9083,'runtime scope changed')
 marker=old.read(ROOT/'real-activation-complete.json',0o600);status=json.loads(marker);require(status['engine_enabled'] is False and status['task_submitted'] is False and status['sidecar']==real.service_running(),'real sidecar not ready')
 package=root_json(ROOT/'relay-package.json');require(package.get('schema')==1 and isinstance(package.get('files'),dict) and len(package['files'])>=13,'relay package unavailable')
 for name,sha in package['files'].items():
  require(re.fullmatch(r'[A-Za-z0-9_.-]+',name) is not None and re.fullmatch(r'[0-9a-f]{64}',sha) is not None,'package scope mismatch')
  old.read(old.PREFIX/'relay'/name,0o444,sha,1_000_000)
 images=root_json(ROOT/'worker-images.json');require(images.get('schema')==1 and images.get('goose_sha256')==GOOSE_SHA and images.get('engine_started') is False,'image receipt unavailable')
 bind=provider();route();parts=artifacts(cfg,bind,images)
 unitfiles=units();paths=[INTENT,DONE]+[SYSTEM/name for name in unitfiles]+[ROOT/'launch-catalog'/(G+'.json'),ROOT/'launch-catalog'/(G+'.recipe.json'),ROOT/'tasks'/(G+'.json')]+[ROOT/'relay-catalog'/(G+'.'+suffix) for suffix in ('profile.json','prompt.txt','template.json','provider.json','units.json','scope.json','writer.json')]+[STATE/'handoff'/G,STATE/'relay'/G,RUN/'relay'/G,RUN/'writer'/(G+'.sock')]
 require(not any(os.path.lexists(p) for p in paths),'generation path occupied')
 require(not any(name.startswith(G+'.') for name in os.listdir(STATE/'stop')),'generation stop state occupied')
 for name in unitfiles:
  load=old.ctl('show',name,'--property=LoadState','--value')
  if name.endswith('.slice'):
   require(load=='loaded' and old.ctl('show',name,'-p','ActiveState','--value')=='inactive' and old.ctl('show',name,'-p','FragmentPath','--value')=='' and old.ctl('show',name,'-p','DropInPaths','--value')=='','synthesized slice occupied')
  else:require(load=='not-found','unit name occupied')
  for parent in ['/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system']:
   for p in (pathlib.Path(parent)/name,pathlib.Path(parent)/(name+'.d'),pathlib.Path(parent)/(name.rsplit('.',1)[1]+'.d')):require(not os.path.lexists(p),'unit collision')
 cg=pathlib.Path('/sys/fs/cgroup')/('sfactory'+LOW+'.slice');require(not os.path.lexists(cg),'generation cgroup already exists')
 hashes={'prompt':digest(parts[0]),'profile':digest(parts[1]),'template':digest(parts[2]),'provider':digest(parts[3]),'recipe':digest(canonical(parts[4]))}
 return {'generation':G,'task':TASK,'catalog_sha256':cfg['launch_scope']['catalog_sha256'],'baseline':cfg['request']['base_revision'],'provider':bind,'artifacts':hashes,'units':{k:digest(v) for k,v in unitfiles.items()},'old_snapshot':old.old_snapshot(),'prior_sidecar':old.sidecar_running(),'real_sidecar':status['sidecar'],'scope':'preclaim only; no provider request, key read, claim or container'}

def apply(approved):
 require(plan()==approved,'preparation plan changed');old.store(INTENT,canonical(approved)+b'\n',0o600)
 for path,uid,gid,mode in [(ROOT/'launch-catalog',0,0,0o700),(ROOT/'relay-catalog',0,0,0o700),(STATE/'relay',0,0,0o711),(STATE/'handoff',0,0,0o700),(RUN/'writer',0,2000,0o710),(RUN/'relay',0,0,0o755),(RUN/'docker-empty-config',0,0,0o700)]:directory(path,uid,gid,mode,True)
 require(not os.listdir(RUN/'docker-empty-config'),'Docker config directory not empty')
 for path,uid,gid,mode in [(STATE/'relay'/G,2000,2000,0o700),(STATE/'handoff'/G,0,0,0o700),(RUN/'relay'/G,2000,2000,0o700)]:directory(path,uid,gid,mode,True)
 for name,uid in [('input',0),('output',2001),('candidate',2001)]:directory(STATE/'handoff'/G/name,uid,uid,0o755,True)
 cfg=json.loads(old.read(ROOT/'real-runtime.json',0o644,CONFIG_SHA));images=root_json(ROOT/'worker-images.json');bind=provider();route();prompt,profile,template,provider_raw,recipe=artifacts(cfg,bind,images)
 require({'prompt':digest(prompt),'profile':digest(profile),'template':digest(template),'provider':digest(provider_raw),'recipe':digest(canonical(recipe))}==approved['artifacts'],'artifacts changed')
 for suffix,data,mode in [('prompt.txt',prompt,0o444),('profile.json',profile,0o444),('template.json',template,0o600),('provider.json',provider_raw,0o600)]:old.store(ROOT/'relay-catalog'/(G+'.'+suffix),data,mode)
 old.store(ROOT/'launch-catalog'/(G+'.recipe.json'),canonical(recipe),0o600)
 unitfiles=units();manifest={'schema':1,'generation':G,'units':{n:digest(v) for n,v in unitfiles.items() if not n.endswith('.slice')}}
 old.store(ROOT/'relay-catalog'/(G+'.units.json'),canonical(manifest),0o600)
 for n,data in unitfiles.items():old.store(SYSTEM/n,data,0o644)
 old.ctl('daemon-reload')
 for name in unitfiles:
  for prop,expected in [('LoadState','loaded'),('Names',name),('FragmentPath',str(SYSTEM/name)),('DropInPaths',''),('NeedDaemonReload','no')]:require(old.ctl('show',name,'-p',prop,'--value')==expected,'loaded unit mismatch')
 for name in unitfiles:
  if name.endswith('.service'):
   for prop,expected in [('MemoryMax',str(256*1024**2)),('TasksMax','32'),('CPUQuotaPerSecUSec','1s')]:require(old.ctl('show',name,'-p',prop,'--value') in (expected,'1000000us' if prop=='CPUQuotaPerSecUSec' else expected),'loaded resource limit mismatch')
 slice_name='sfactory'+LOW+'.slice';old.ctl('start',slice_name)
 cg=pathlib.Path('/sys/fs/cgroup')/slice_name;st=os.stat(cg);require(st.st_uid==0 and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1 and (cg/'memory.max').read_text().strip()==str(2*1024**3) and (cg/'pids.max').read_text().strip()=='128','generation slice unavailable')
 quota=(cg/'cpu.max').read_text().split();require(len(quota)==2 and all(x.isdigit() for x in quota) and int(quota[0])==2*int(quota[1]),'generation CPU limit mismatch')
 boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();stop={'schema':1,'target_id':G,'task_id':TASK,'generation':G,'boot_id':boot,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino}
 launch={'schema':1,'scope':cfg['launch_scope'],'boot_id':boot,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'recipe_sha256':digest(canonical(recipe)),'max_expiry_ms':1793491200000}
 old.store(ROOT/'tasks'/(G+'.json'),canonical(stop),0o600);old.store(ROOT/'launch-catalog'/(G+'.json'),canonical(launch),0o600)
 callback='sfactoryrelay'+LOW+'.socket';old.ctl('start',callback)
 require(old.ctl('show',callback,'-p','ActiveState','--value')=='active' and (cg/'cgroup.events').read_text().splitlines().count('populated 0')==1,'callback or slice state unavailable')
 sock=RUN/'relay'/G/'relay.sock';ss=os.lstat(sock);require(stat.S_ISSOCK(ss.st_mode) and (ss.st_uid,ss.st_gid,stat.S_IMODE(ss.st_mode),ss.st_nlink)==(0,2001,0o660,1),'callback socket mismatch')
 try:os.getxattr(sock,'system.posix_acl_access',follow_symlinks=False)
 except OSError as e:require(e.errno==errno.ENODATA,'callback ACL unavailable')
 else:raise RuntimeError('callback ACL forbidden')
 current=os.stat(cg);require((current.st_dev,current.st_ino)==(st.st_dev,st.st_ino),'generation cgroup changed')
 require(old.old_snapshot()==approved['old_snapshot'] and old.sidecar_running()==approved['prior_sidecar'] and real.service_running()==approved['real_sidecar'],'preserved runtime changed')
 result={'generation':G,'cgroup_dev':st.st_dev,'cgroup_ino':st.st_ino,'catalog_sha256':digest(canonical(launch)),'recipe_sha256':digest(canonical(recipe)),'callback_started':True,'task_claimed':False,'provider_called':False,'container_started':False}
 old.store(DONE,canonical(result)+b'\n',0o600);return result
