import copy,json,unittest
import nuc_registry_eval_backend_v2 as m
class ContainerChecks(unittest.TestCase):
 def setUp(self):
  self.entry={'target':'01M65RMR3F04YB1B016EBBSXGH','snapshot_path':'/fixed/snapshot'};self.ident='a'*64;self.name='fixed';self.cmd=['-I','-B','/work/hello.py']
  self.obj={'Id':self.ident,'Name':'/'+self.name,'Image':m.IMAGE,'State':{'Status':'created'},'Config':{'User':'2001:2001','Entrypoint':['/usr/local/bin/python3'],'Cmd':self.cmd,'Labels':{'org.software-factory.evaluation':self.entry['target']}},'HostConfig':{'LogConfig':{'Type':'json-file','Config':{'max-size':'1m','max-file':'2'}},'NetworkMode':'none','CgroupnsMode':'private','IpcMode':'private','SecurityOpt':['no-new-privileges'],'RestartPolicy':{'Name':'no'},'CgroupParent':'sfactory'+self.entry['target'].lower()+'.slice','ReadonlyRootfs':True,'Privileged':False,'CapDrop':['ALL'],'CapAdd':None,'PidsLimit':32,'Memory':128*1024**2,'NanoCpus':500000000},'Mounts':[{'Type':'bind','Source':'/fixed/snapshot','Destination':'/work','RW':False}]}
 def run_check(self,obj):
  b=m.Backend.__new__(m.Backend);b.h={'DOCKER':['docker'],'fixed_run':lambda args:json.dumps([obj]).encode()};b.inspect(self.entry,self.ident,self.name,'created',self.cmd)
 def test_snapshot_mismatch_refuses_before_deadline_or_engine(self):
  b=m.Backend.__new__(m.Backend);b.c={'generation':'01M65RMR3F04YB1B016EBBSXGG','snapshot_sha256':{'hello.py':'a'*64,'test_hello.py':'b'*64},'challenges':[{'target':self.entry['target'],'task_id':'01M65RMR3FE6FQTFRBHERRHXRG','cgroup_dev':29,'cgroup_ino':42,'snapshot_path':'/fixed/snapshot','snapshot_dev':1,'snapshot_ino':2,'generation':'01M65RMR3F04YB1B016EBBSXGG'}]*22};b.snapshot=lambda entry:{'hello.py':'f'*64,'test_hello.py':'b'*64};b.deadline=None;b.h={}
  with self.assertRaises(m.Unavailable):b.launch_and_reconcile({'sequence':1},'a'*64)
 def test_valid_and_unsafe_network_writable_mount_capability_denied(self):
  self.run_check(self.obj)
  for change in ('network','mount','capability','identity','logging'):
   obj=copy.deepcopy(self.obj)
   if change=='network':obj['HostConfig']['NetworkMode']='host'
   if change=='mount':obj['Mounts'][0]['RW']=True
   if change=='capability':obj['HostConfig']['CapDrop']=[]
   if change=='identity':obj['Id']='b'*64
   if change=='logging':obj['HostConfig']['LogConfig']['Config']={}
   with self.subTest(change=change),self.assertRaises(m.Unavailable):self.run_check(obj)
if __name__=='__main__':unittest.main()
