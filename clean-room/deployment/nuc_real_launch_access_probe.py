"""Fixed, read-only root capability comparison for the closed launch generation."""
import hashlib,json,os,pathlib,stat,subprocess
import nuc_grant_sidecar_install as old
G='01M65NEH5T767H8Q5X71TTFR5S';LOW=G.lower()
PATHS=('/run/software-factory-goose/relay/'+G,'/var/lib/software-factory-goose/relay/'+G)
START=old.ETC/'real-launch-access-probe-started.json';DONE=old.ETC/'real-launch-access-probe-complete.json'
ENV={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','SYSTEMD_IN_CHROOT':'0'}
CODE=r'''import errno,json,os,pathlib,stat,sys
mode=sys.argv[1];expected={'empty':0,'dac-read-search':4}[mode]
if os.geteuid()!=0 or os.getegid()!=0:raise RuntimeError('wrong probe identity')
fields=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
if int(fields['CapEff'].strip(),16)!=expected or fields['NoNewPrivs'].strip()!='1':raise RuntimeError('wrong capability state')
out=[]
for path in ('/run/software-factory-goose/relay/01M65NEH5T767H8Q5X71TTFR5S','/var/lib/software-factory-goose/relay/01M65NEH5T767H8Q5X71TTFR5S'):
 try:
  fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   st=os.fstat(fd)
   if not stat.S_ISDIR(st.st_mode) or st.st_uid!=2000 or st.st_gid!=2000 or stat.S_IMODE(st.st_mode)!=0o700:raise RuntimeError('path identity mismatch')
   out.append('opened')
  finally:os.close(fd)
 except OSError as e:
  if e.errno!=errno.EACCES:raise RuntimeError('unexpected path error')
  out.append('eacces')
print(json.dumps({'mode':mode,'paths':out,'cap_eff':expected},sort_keys=True))
'''

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not os.path.lexists(START) and not os.path.lexists(DONE),'probe already attempted')
 identities=[]
 for path in PATHS:
  s=os.lstat(path);require(stat.S_ISDIR(s.st_mode) and (s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode))==(2000,2000,0o700),'path changed')
  identities.append({'path':path,'dev':s.st_dev,'ino':s.st_ino})
 for mode in ('empty','dac-read-search'):
  unit='sfactory-access-'+mode+'-'+LOW+'.service';require(old.ctl('show',unit,'-p','LoadState','--value')=='not-found','unit occupied')
 return {'generation':G,'paths':identities,'code_sha256':hashlib.sha256(CODE.encode()).hexdigest(),'scope':'root native access-only probes; no journal or generation writes'}
def run(mode):
 unit='sfactory-access-'+mode+'-'+LOW+'.service';cap='' if mode=='empty' else 'CAP_DAC_READ_SEARCH'
 args=['/usr/bin/systemd-run','--unit='+unit,'--wait','--pipe','--quiet','--property=User=root','--property=Group=root','--property=NoNewPrivileges=yes','--property=CapabilityBoundingSet='+cap,'--property=AmbientCapabilities='+cap,'--property=MemoryMax=64M','--property=TasksMax=16','--property=RuntimeMaxSec=15s','/usr/bin/python3','-I','-B','-c',CODE,mode]
 p=subprocess.run(args,env=ENV,capture_output=True,timeout=25,check=False);require(p.returncode==0 and len(p.stdout)<=8192 and len(p.stderr)<=8192,'probe unknown')
 return json.loads(p.stdout)
def apply(approved):
 require(plan()==approved,'probe plan changed');old.store(START,json.dumps(approved,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600)
 empty=run('empty');permit=run('dac-read-search')
 require(empty=={'mode':'empty','paths':['eacces','eacces'],'cap_eff':0} and permit=={'mode':'dac-read-search','paths':['opened','opened'],'cap_eff':4},'hypothesis not established')
 for before in approved['paths']:
  s=os.lstat(before['path']);require((s.st_dev,s.st_ino)==(before['dev'],before['ino']),'path changed')
 result={'empty_capabilities':empty['paths'],'dac_read_search':permit['paths'],'generation_unchanged':True,'grant_requested':False,'engine_started':False}
 old.store(DONE,json.dumps(result,sort_keys=True,separators=(',',':')).encode()+b'\n',0o600);return result
