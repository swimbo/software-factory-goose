import os,stat,tempfile,types,unittest
from unittest.mock import patch
import nuc_registry_eval_broker as m
def broker_for(fd,b):
 st=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0,st_gid=0)
 with patch.object(m.os,"fstat",return_value=st):return m.Broker(fd,S,b,G,lambda fd,directory:None)
S={'hello.py':'a'*64,'test_hello.py':'b'*64};G='01M65RMR3F04YB1B016EBBSXGG'
def request():return {'schema':1,'generation':G,'sequence':1,'kind':'hello','args':[],'candidate_sha256':S}
class Backend:
 def __init__(self):self.calls=0;self.fail=False
 def launch_and_reconcile(self,q,digest):
  self.calls+=1
  if self.fail:raise RuntimeError('unknown')
  return {'generation':G,'sequence':1,'intent_sha256':digest,'candidate_sha256':S,'container_id':'c'*64,'deadline_armed':True,'kernel_empty':True,'exact_id_removed':True,'exit_code':0,'stdout':b'hello world\n','stderr':b''}
class BrokerTests(unittest.TestCase):
 def test_wrong_uid_scope_and_commands_rejected_before_effect(self):
  with tempfile.TemporaryDirectory() as p:
   fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);b=Backend();broker=broker_for(fd,b)
   try:
    for uid,q in [(2001,request()),(2002,{**request(),'args':['--bogus']}),(2002,{**request(),'candidate_sha256':{'hello.py':'f'*64,'test_hello.py':'b'*64}})]:
     with self.assertRaises(m.Unavailable):broker.run(uid,q)
    self.assertEqual(os.listdir(p),[]);self.assertEqual(b.calls,0)
   finally:os.close(fd)
 def test_unknown_outcome_is_not_replayed(self):
  with tempfile.TemporaryDirectory() as p:
   fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);b=Backend();b.fail=True;broker=broker_for(fd,b)
   try:
    with self.assertRaises(m.Unavailable):broker.run(2002,request())
    self.assertEqual(os.listdir(p),['01.intent'])
    b.fail=False
    with self.assertRaises(m.Unavailable):broker.run(2002,request())
    self.assertEqual(b.calls,1)
   finally:os.close(fd)
 def test_unknown_cleanup_withholds_all_output(self):
  with tempfile.TemporaryDirectory() as p:
   fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);b=Backend();launch=b.launch_and_reconcile
   def unsafe(q,digest):
    value=launch(q,digest);value['kernel_empty']=False;return value
   b.launch_and_reconcile=unsafe;broker=broker_for(fd,b)
   try:
    with self.assertRaises(m.Unavailable):broker.run(2002,request())
    self.assertEqual(os.listdir(p),['01.intent'])
   finally:os.close(fd)
 def test_completed_receipt_precedes_release_and_duplicate_denied(self):
  with tempfile.TemporaryDirectory() as p:
   fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY);b=Backend();broker=broker_for(fd,b)
   try:
    self.assertEqual(broker.run(2002,request())['stdout'],b'hello world\n');self.assertEqual(set(os.listdir(p)),{'01.intent','01.done'})
    with self.assertRaises(m.Unavailable):broker.run(2002,request())
    self.assertEqual(b.calls,1)
   finally:os.close(fd)
if __name__=='__main__':unittest.main()
