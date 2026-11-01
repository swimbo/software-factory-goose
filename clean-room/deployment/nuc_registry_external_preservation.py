"""Non-secret snapshot of unrelated containers and fixed Hermes services.

 Trusted root/Docker/PID1 are assumed. This collects no environment, command
 arguments, logs or credentials, and never restarts or removes anything.
"""
import hashlib,json,os,pathlib,re,stat,subprocess
import nuc_grant_sidecar_install as old
DOCKER='/usr/bin/docker';SOCKET='/run/docker.sock'
SERVICES=('hermes-dashboard.service','hermes-gateway.service')
BRIDGE_IMAGE='sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','DOCKER_CONFIG':'/nonexistent'}
def require(v,m):
 if not v:raise RuntimeError(m)
def call(args):
 p=subprocess.run(args,env=ENV,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=25,check=False)
 require(p.returncode==0 and len(p.stdout)<=1048576 and len(p.stderr)<=8192,'container observation unavailable');return p.stdout.decode('utf-8').strip()
def bridge_receipt(cid,name,token):
 matches=[]
 with os.scandir('/tmp') as entries:
  for entry in entries:
   if not entry.name.startswith('sfactory-identity-admin-'):continue
   require(len(matches)<2,'ambiguous bridge receipt')
   try:
    d=os.open(entry.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
     st=os.fstat(d);require((st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(1000,1000,0o700),'bridge receipt directory unavailable');old.noacl(d,True)
     def read(n):
      f=os.open(n,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=d)
      try:
       st=os.fstat(f);require(stat.S_ISREG(st.st_mode) and (st.st_uid,st.st_gid,st.st_nlink,stat.S_IMODE(st.st_mode))==(1000,1000,1,0o600) and st.st_size<=8192,'bridge receipt unavailable');old.noacl(f);data=os.read(f,8193);require(len(data)==st.st_size,'bridge receipt changed');return json.loads(data)
      finally:os.close(f)
     manifest=read('manifest.json');intent=read('intent.json')
     if manifest=={'id':cid,'name':name,'token':token}:
      require(set(intent)=={'name','token','operation','source_sha256'} and intent['name']==name and intent['token']==token and intent['operation'] in ('plan','apply') and re.fullmatch('[0-9a-f]{64}',intent['source_sha256']),'bridge intent unavailable');matches.append({'manifest_dir':entry.name,'operation':intent['operation'],'source_sha256':intent['source_sha256']})
    finally:os.close(d)
   except FileNotFoundError:continue
 require(len(matches)==1,'exact bridge receipt unavailable');return matches[0]
def current_transport(base):
 raw=pathlib.Path('/proc/self/cgroup').read_text();ids=re.findall(r'(?:^|/)docker-([0-9a-f]{64})\.scope(?:/|$)',raw,re.MULTILINE);require(len(ids)==1,'bridge cgroup unavailable');cid=ids[0]
 fmt='[{{json .Id}},{{json .Image}},{{json .State.Pid}},{{json .State.Status}},{{json .Name}},{{json (index .Config.Labels "org.software-factory.identity-admin")}}]'
 row=json.loads(call(base+['inspect','--format',fmt,cid]));require(isinstance(row,list) and len(row)==6 and row[0]==cid and row[1]==BRIDGE_IMAGE and row[2]==os.getpid() and row[3]=='running' and isinstance(row[5],str) and re.fullmatch('[0-9a-f]{32}',row[5]) and row[4]=='/sfactory-identity-admin-'+row[5],'current bridge identity unavailable')
 receipt=bridge_receipt(cid,row[4][1:],row[5]);return {'id':cid,'image':row[1],'pid':row[2],'receipt':receipt}
def collect_with_transport():
 st=os.lstat(DOCKER);require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'docker CLI unavailable')
 sock=os.lstat(SOCKET);require(stat.S_ISSOCK(sock.st_mode) and sock.st_uid==0 and not sock.st_mode&0o002,'docker socket unavailable')
 base=[DOCKER,'--host','unix://'+SOCKET]
 daemon=call(base+['info','--format','{{.ID}}']);require(re.fullmatch(r'[A-Za-z0-9:._-]{1,128}',daemon),'daemon identity unavailable')
 transport=current_transport(base)
 lines=call(base+['ps','--no-trunc','--quiet']).splitlines();require(len(lines)<=128 and len(lines)==len(set(lines)) and all(re.fullmatch('[0-9a-f]{64}',x) for x in lines),'container identity unavailable')
 rows=[]
 if lines:
  fmt='[{{json .Id}},{{json .Image}},{{json .State.Status}},{{json .State.Pid}},{{json .State.StartedAt}}]'
  raw=call(base+['inspect','--format',fmt,*sorted(lines)]).splitlines();require(len(raw)==len(lines),'container inventory incomplete')
  for line in raw:
   row=json.loads(line);require(isinstance(row,list) and len(row)==5 and re.fullmatch('[0-9a-f]{64}',row[0]) and re.fullmatch('sha256:[0-9a-f]{64}',row[1]) and row[2]=='running' and type(row[3]) is int and row[3]>1 and isinstance(row[4],str) and 1<=len(row[4])<=64,'container state unavailable');rows.append(row)
  require(sorted(x[0] for x in rows)==sorted(lines),'container inventory changed');rows.sort()
  require(sorted(call(base+['ps','--no-trunc','--quiet']).splitlines())==sorted(lines),'container set changed')
  again=call(base+['inspect','--format',fmt,*sorted(lines)]).splitlines();require(len(again)==len(rows) and sorted(json.loads(line) for line in again)==rows,'container identity changed')
 require(sum(x[0]==transport['id'] for x in rows)==1,'bridge absent from inventory');rows=[x for x in rows if x[0]!=transport['id']]
 services={}
 for unit in SERVICES:
  text=old.ctl('show',unit,'--property=Names,LoadState,ActiveState,MainPID,InvocationID,Job,FragmentPath','--all','--no-pager');values={}
  for line in text.splitlines():
   key,sep,value=line.partition('=');require(sep and key not in values,'service observation unavailable');values[key]=value
  require(values.get('Names')==unit and values.get('LoadState')=='loaded' and values.get('ActiveState')=='active' and values.get('MainPID','').isdigit() and int(values['MainPID'])>1 and re.fullmatch('[0-9a-f]{32}',values.get('InvocationID','')) and values.get('Job','')=='','Hermes service unavailable');services[unit]=values
 return {'schema':1,'daemon_id':daemon,'docker_socket_dev':sock.st_dev,'docker_socket_ino':sock.st_ino,'containers':rows,'services':services},transport
def collect():return collect_with_transport()[0]
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
