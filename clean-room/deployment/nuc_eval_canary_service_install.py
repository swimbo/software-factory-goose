"""Install fixed synthetic evaluator service/socket; never start or attest."""
import hashlib,json,os,pathlib
import nuc_grant_sidecar_install as old
ROOT=old.ETC;RUN=old.RUN;SYSTEM=old.UNIT;DEST=old.PREFIX/'evaluator';G='01M65RMR3F04YB1B016EBBSXGK'
NAME='software-factory-goose-eval-canary';START=ROOT/'evaluator-canary-service-started.json';DONE=ROOT/'evaluator-canary-service-complete.json';PARENT=RUN/'evaluator'
SOCKET=('''[Unit]\nDescription=Software factory synthetic evaluator socket\nConditionPathExists=/etc/software-factory-goose/evaluator-canary-provision-complete.json\n[Socket]\nListenStream=/run/software-factory-goose/evaluator/broker.sock\nSocketUser=root\nSocketGroup=sfgoose-eval\nSocketMode=0660\nFileDescriptorName=evaluator\nAccept=no\nRemoveOnStop=yes\nService='''+NAME+'''.service\n''').encode()
SERVICE=('''[Unit]\nDescription=Software factory synthetic evaluator broker\nRequires='''+NAME+'''.socket\nAfter='''+NAME+'''.socket\nConditionPathExists=/etc/software-factory-goose/evaluator-canary-provision-complete.json\n[Service]\nType=exec\nUser=root\nGroup=root\nSlice=system.slice\nSockets='''+NAME+'''.socket\nExecStart=/usr/bin/python3 -I -B /usr/local/libexec/software-factory-goose/evaluator/nuc_registry_eval_canary_runtime.py\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nReadWritePaths=/var/lib/software-factory-goose/evaluator /var/lib/software-factory-goose/stop /sys/fs/cgroup\nMemoryMax=256M\nTasksMax=32\nCPUQuota=100%\nLimitCORE=0\nRestart=no\nUMask=0077\n''').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def require(x,msg):
 if not x:raise RuntimeError(msg)
def plan():
 require(os.geteuid()==0 and not any(os.path.lexists(p) for p in (START,DONE,PARENT,SYSTEM/(NAME+'.socket'),SYSTEM/(NAME+'.service'))),'canary service occupied')
 receipt=json.loads(old.read(ROOT/'evaluator-canary-provision-complete.json',0o600));require(receipt.get('generation')==G and receipt.get('fixture_only') is True and receipt.get('targets')==22,'fixture unavailable')
 data=old.read(ROOT/'evaluator-canary-catalog.json',0o600,receipt['catalog_sha256'],65536);cat=json.loads(data);require(cat.get('generation')==G and cat.get('purpose')=='synthetic-evaluator-canary-only','fixture catalog mismatch')
 old.directory(DEST,0,2002,0o710)
 for name in (NAME+'.socket',NAME+'.service'):
  require(old.ctl('show',name,'-p','LoadState','--value')=='not-found','unit occupied')
  for parent in ('/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system'):
   for path in (pathlib.Path(parent)/name,pathlib.Path(parent)/(name+'.d'),pathlib.Path(parent)/(name.rsplit('.',1)[1]+'.d')):require(not os.path.lexists(path),'alias or drop-in occupied')
 return {'generation':G,'catalog_sha256':receipt['catalog_sha256'],'socket_sha256':sha(SOCKET),'service_sha256':sha(SERVICE),'scope':'create-only synthetic service; no activation'}
def apply(approved):
 require(plan()==approved,'plan changed');old.store(START,json.dumps(approved,sort_keys=True).encode()+b'\n',0o600)
 os.mkdir(PARENT,0o710);os.chmod(PARENT,0o710);os.chown(PARENT,0,2002);old.syncdir(RUN);old.store(SYSTEM/(NAME+'.socket'),SOCKET,0o644);old.store(SYSTEM/(NAME+'.service'),SERVICE,0o644);old.ctl('daemon-reload')
 for unit in (NAME+'.socket',NAME+'.service'):
  for prop,val in [('LoadState','loaded'),('Names',unit),('FragmentPath',str(SYSTEM/unit)),('DropInPaths',''),('ActiveState','inactive'),('Job','')]:require(old.ctl('show',unit,'-p',prop,'--value')==val,'unit identity mismatch')
 result={'generation':G,'installed':True,'started':False,'fixture_only':True};old.store(DONE,json.dumps(result,sort_keys=True).encode()+b'\n',0o600);return result
