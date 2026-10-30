import json,os,tempfile,unittest
from pathlib import Path
import nuc_root_docker_deadline_canary as c
class Fake:
 def __init__(self,obj):self.obj=obj;self.calls=[]
 def run(self,*args,**kwargs):self.calls.append(args);return json.dumps([self.obj])
class DockerCanaryTests(unittest.TestCase):
 def test_root_record_rejects_fifo_without_wait(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/'fifo';os.mkfifo(p,0o600)
   with self.assertRaises(RuntimeError):c.root_record(p)
 def test_owned_object_refuses_wrong_parent_or_id(self):
  g='01M65J0JBJN1CAS5SVTXZTEPZG';i='a'*64
  obj={'Id':i,'Name':'/sfactory-launch-'+g.lower(),'Config':{'Labels':{'org.software-factory.root-launch-canary':g}},'HostConfig':{'CgroupParent':'sfactory'+g.lower()+'.slice'},'Image':'sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937'}
  fake=Fake(obj);self.assertEqual(c.owned_object(fake,g,i),obj)
  obj['HostConfig']['CgroupParent']='wrong.slice'
  with self.assertRaises(RuntimeError):c.owned_object(fake,g,i)
  obj['HostConfig']['CgroupParent']='sfactory'+g.lower()+'.slice';obj['Id']='b'*64
  with self.assertRaises(RuntimeError):c.owned_object(fake,g,i)
if __name__=='__main__':unittest.main()
