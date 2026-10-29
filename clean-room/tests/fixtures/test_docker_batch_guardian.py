#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, tempfile, threading, unittest
from unittest.mock import patch
from docker_batch_guardian import Batch, LABEL, APPROVED_SLICE, _bounded_exec

class Fake:
 def __init__(self, cg): self.cg=cg; self.items={}; self.actions=[]; self.commands=[]; self.ambiguous=False
 def __call__(self,*args,check=True):
  self.actions.append(args[0]); self.commands.append(args); op=args[0]
  if op=='create':
   name=args[args.index('--name')+1]; token=args[args.index('--label')+1].split('=',1)[1]; parent=args[args.index('--cgroup-parent')+1]
   memory=args[args.index('--memory')+1]; ident=f'{len(self.items)+1:064x}'; self.items[ident]={'Id':ident,'Name':'/'+name,'Config':{'Labels':{LABEL:token}},'HostConfig':{'CgroupParent':parent,'Memory':int(memory[:-1])*1024*1024},'State':{'Running':False,'Status':'created'}}
   if self.ambiguous: raise subprocess.TimeoutExpired('create',8)
   return subprocess.CompletedProcess(args,0,ident+'\n','')
  if op=='inspect':
   target=args[1]; found=[x for x in self.items.values() if x['Id']==target or x['Name']=='/'+target]
   return subprocess.CompletedProcess(args,0,json.dumps(found),'') if found else subprocess.CompletedProcess(args,1,'','no such object')
  if op=='start':
   self.items[args[1]]['State']={'Running':True,'Status':'running'}; (self.cg/'cgroup.events').write_text('populated 1\n'); return subprocess.CompletedProcess(args,0,'','')
  if op=='kill': self.items[args[1]]['State']={'Running':False,'Status':'exited'}; return subprocess.CompletedProcess(args,0,'','')
  if op=='rm':
   if self.items[args[1]]['State']['Running']: raise RuntimeError('running')
   del self.items[args[1]]
   if not any(o['State']['Running'] for o in self.items.values()): (self.cg/'cgroup.events').write_text('populated 0\n')
   return subprocess.CompletedProcess(args,0,'','')
  if op=='ps': return subprocess.CompletedProcess(args,0,'\n'.join(self.items)+'\n','')
  raise RuntimeError('unexpected '+op)

class Tests(unittest.TestCase):
 def setup_batch(self,root):
  cg=root/'cg'; cg.mkdir(); cg=cg.resolve(); (cg/'cgroup.events').write_text('populated 0\n'); data=root/'data'; data.mkdir(mode=0o700)
  patcher=patch('docker_batch_guardian.CGROUP_PATH',cg); patcher.start(); self.addCleanup(patcher.stop)
  return Batch(data,APPROVED_SLICE,cg),Fake(cg)
 def test_two_roots_sealed_before_start_and_closed_before_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    batch.prepare_fixed('goose',image,['worker']);
    with self.assertRaises(RuntimeError): batch.start('goose')
    batch.prepare_fixed('executor',image,['executor']); batch.seal(); batch.start('goose'); batch.start('executor')
    self.assertTrue(batch.stop()); self.assertFalse(fake.items)
    self.assertTrue(batch.stop())
    with self.assertRaises(RuntimeError): batch.start('goose')
    with self.assertRaises(RuntimeError): batch.prepare_fixed('goose',image,['worker'])
    self.assertEqual(fake.actions.count('kill'),2)
 def test_role_memory_caps_are_fixed_and_sealed(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor'])
    creates=[x for x in fake.commands if x[0]=='create']
    self.assertEqual(creates[0][creates[0].index('--memory')+1],'512m')
    self.assertEqual(creates[1][creates[1].index('--memory')+1],'128m')
    goose=batch.read('goose.manifest')['id']; fake.items[goose]['HostConfig']['Memory']=128*1024*1024
    with self.assertRaises(RuntimeError):batch.seal()
    fake.items[goose]['HostConfig']['Memory']=512*1024*1024;batch.seal()
    fake.items[goose]['HostConfig']['Memory']=128*1024*1024
    with self.assertRaises(RuntimeError):batch.start('goose')
    self.assertTrue(batch.stop())
 def test_ambiguous_create_recovers_only_never_started_owned_root(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); fake.ambiguous=True
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    with self.assertRaises(subprocess.TimeoutExpired): batch.prepare_fixed('goose','sha256:'+'a'*64,['worker'])
    self.assertTrue(batch.stop()); self.assertFalse(fake.items); self.assertNotIn('kill',fake.actions)
    with self.assertRaises(RuntimeError): batch.prepare_fixed('executor','sha256:'+'a'*64,['worker'])
 def test_stop_closes_admission_even_when_an_operation_holds_lock(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d))
   with batch.locked():
    with self.assertRaises(BlockingIOError): batch.stop()
    self.assertTrue((batch.root/'closed.json').is_file())
   with patch('docker_batch_guardian.docker',side_effect=fake):
    with self.assertRaises(RuntimeError): batch.prepare_fixed('goose','sha256:'+'a'*64,['worker'])
    self.assertEqual(fake.actions,[])

 def test_inflight_start_is_unresolved_then_stopped(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   entered=threading.Event(); release=threading.Event(); errors=[]
   def controlled(*args,**kwargs):
    if args[0]=='start':
     entered.set()
     if not release.wait(3): raise RuntimeError('test start gate expired')
    return fake(*args,**kwargs)
   with patch('docker_batch_guardian.docker',side_effect=controlled), patch('docker_owner_guardian.docker',side_effect=controlled):
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor']); batch.seal()
    def launch():
     try: batch.start('goose')
     except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=launch); thread.start()
    try:
     self.assertTrue(entered.wait(3))
     with self.assertRaises(BlockingIOError): batch.stop()
     self.assertTrue((batch.root/'closed.json').is_file())
    finally:
     release.set(); thread.join(4)
    self.assertFalse(thread.is_alive()); self.assertEqual(len(errors),1)
    self.assertIn('launch raced stop',str(errors[0]))
    self.assertTrue(batch.stop()); self.assertFalse(fake.items)
    with self.assertRaises(RuntimeError): batch.start('executor')

 def test_inflight_create_is_quarantined_after_stop(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   entered=threading.Event(); release=threading.Event(); errors=[]
   def controlled(*args,**kwargs):
    if args[0]=='create':
     entered.set()
     if not release.wait(3): raise RuntimeError('test create gate expired')
    return fake(*args,**kwargs)
   with patch('docker_batch_guardian.docker',side_effect=controlled), patch('docker_owner_guardian.docker',side_effect=controlled):
    def create():
     try: batch.prepare_fixed('goose',image,['worker'])
     except Exception as exc: errors.append(exc)
    thread=threading.Thread(target=create); thread.start()
    try:
     self.assertTrue(entered.wait(3))
     with self.assertRaises(BlockingIOError): batch.stop()
    finally:
     release.set(); thread.join(4)
    self.assertFalse(thread.is_alive()); self.assertEqual(len(errors),1)
    self.assertIn('admission closed',str(errors[0]))
    self.assertTrue(batch.stop()); self.assertFalse(fake.items)
    self.assertNotIn('start',fake.actions)

 def test_observation_path_must_match_declared_slice(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); data=root/'data'; data.mkdir(mode=0o700); decoy=root/'empty'; decoy.mkdir()
   (decoy/'cgroup.events').write_text('populated 0\n')
   with self.assertRaises(RuntimeError):
    Batch(data,APPROVED_SLICE,decoy)

 def test_candidate_is_pinned_and_writable_only_for_executor(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d).resolve(); batch,fake=self.setup_batch(root); private=root/'private'; private.mkdir(mode=0o700); candidate=private/'work'; candidate.mkdir(mode=0o777)
   b=Batch(batch.root,APPROVED_SLICE,batch.cgroup,candidate)
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    image='sha256:'+'a'*64; b.prepare_fixed('goose',image,['worker']); b.prepare_fixed('executor',image,['executor'])
    creates=[x for x in fake.commands if x[0]=='create']; mount='type=bind,src='+str(candidate)+',dst=/work'
    self.assertNotIn(mount,creates[0]); self.assertIn(mount,creates[1]); b.seal()
    candidate.rename(private/'old'); candidate.mkdir(mode=0o777)
    with self.assertRaises(RuntimeError): b.start('executor')
    self.assertTrue(b.stop())
 def test_candidate_rejects_git_symlinks_and_unprivate_parent(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d).resolve(); batch,_=self.setup_batch(root); parent=root/'parent'; parent.mkdir(mode=0o700); candidate=parent/'work'; candidate.mkdir()
   (candidate/'.git').write_text('not permitted')
   with self.assertRaises(RuntimeError): Batch(batch.root,APPROVED_SLICE,batch.cgroup,candidate)
   (candidate/'.git').unlink(); (candidate/'link').symlink_to('/tmp')
   with self.assertRaises(RuntimeError): Batch(batch.root,APPROVED_SLICE,batch.cgroup,candidate)
   (candidate/'link').unlink(); parent.chmod(0o755)
   with self.assertRaises(RuntimeError): Batch(batch.root,APPROVED_SLICE,batch.cgroup,candidate)
 def test_readonly_candidate_mode_is_bound_and_cannot_be_reopened_writable(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d).resolve(); batch,fake=self.setup_batch(root); private=root/'private'; private.mkdir(mode=0o700); candidate=private/'work'; candidate.mkdir()
   b=Batch(batch.root,APPROVED_SLICE,batch.cgroup,candidate,candidate_readonly=True)
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    image='sha256:'+'a'*64; b.prepare_fixed('goose',image,['worker']); b.prepare_fixed('executor',image,['executor']); b.seal()
    creates=[x for x in fake.commands if x[0]=='create']
    self.assertIn('type=bind,src='+str(candidate)+',dst=/work,readonly',creates[1])
    self.assertIn('--log-driver',creates[1]); self.assertIn('json-file',creates[1])
    self.assertIn('max-size=1m',creates[1]); self.assertIn('max-file=2',creates[1])
    writable=Batch(batch.root,APPROVED_SLICE,batch.cgroup,candidate)
    with self.assertRaises(RuntimeError): writable.start('executor')
    self.assertTrue(b.stop())
 def test_exec_once_uses_fixed_argv_and_cannot_replay(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor']); batch.seal(); ident=batch.start('executor')
    with patch('docker_batch_guardian._bounded_exec',return_value=b'ok') as run:
     self.assertEqual(batch.exec_once(b'{"command":"x"}'),b'ok')
     self.assertEqual(run.call_args.args[0],['docker','exec','-i',ident,'/execution','--tool-request'])
     self.assertEqual(run.call_args.args[1],b'{"command":"x"}')
     with self.assertRaises(RuntimeError): batch.exec_once(b'other')
    self.assertTrue(batch.stop())
 def test_writer_mode_has_fixed_argv_and_cannot_switch_or_replay(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   opts=['--mount','type=bind,src=/trusted/writer,dst=/factory-writer.py,readonly','--mount','type=bind,src=/trusted/contract,dst=/nuc_file_contract.py,readonly']
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor'],opts,executor_kind='writer'); batch.seal(); ident=batch.start('executor')
    with patch('docker_batch_guardian._bounded_exec',return_value=b'ok') as run:
     with self.assertRaises(RuntimeError): batch.exec_once(b'{}')
     run.assert_not_called()
     with self.assertRaises(RuntimeError): batch.write_once(b'x'*12289)
     run.assert_not_called()
     self.assertEqual(batch.write_once(b'{}'),b'ok')
     self.assertEqual(run.call_args.args[0],['docker','exec','-i',ident,'/usr/local/bin/python3','-B','/factory-writer.py','--tool-request'])
     with self.assertRaises(RuntimeError): batch.write_once(b'{}')
    self.assertTrue(batch.stop())
 def test_writer_requires_fixed_mounts_and_kind_is_sealed(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    with self.assertRaises(RuntimeError): batch.prepare_fixed('executor',image,['executor'],executor_kind='writer')
    self.assertEqual(fake.actions,[])
    duplicate=['--mount','type=bind,src=/a,dst=/factory-writer.py,readonly','--mount','type=bind,src=/b,dst=/nuc_file_contract.py,readonly','--tmpfs','/factory-writer.py:rw']
    with self.assertRaises(RuntimeError): batch.prepare_fixed('executor',image,['executor'],duplicate,executor_kind='writer')
    self.assertEqual(fake.actions,[])
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor']); batch.seal(); batch.start('executor')
    with patch('docker_batch_guardian._bounded_exec') as run:
     with self.assertRaises(RuntimeError): batch.write_once(b'{}')
     run.assert_not_called()
    self.assertTrue(batch.stop())
 def test_exec_rejects_externally_started_executor(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake):
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor']); batch.seal()
    ident=batch.read('executor.manifest')['id']; fake('start',ident)
    with patch('docker_batch_guardian._bounded_exec',return_value=b'wrong') as run:
     with self.assertRaises(RuntimeError): batch.exec_once(b'{}')
     run.assert_not_called()
    self.assertTrue(batch.stop())

 def test_brake_during_exec_withholds_output_and_requires_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d)); image='sha256:'+'a'*64; entered=threading.Event(); release=threading.Event(); outcomes=[]
   def waiting(command,payload,cancelled):
    entered.set()
    if not release.wait(3): raise RuntimeError('test timeout')
    if cancelled(): raise RuntimeError('stop requested during exec')
    return b'should never escape'
   with patch('docker_batch_guardian.docker',side_effect=fake), patch('docker_owner_guardian.docker',side_effect=fake), patch('docker_batch_guardian._bounded_exec',side_effect=waiting):
    batch.prepare_fixed('goose',image,['worker']); batch.prepare_fixed('executor',image,['executor']); batch.seal(); batch.start('executor')
    def execute():
     try: outcomes.append(batch.exec_once(b'{}'))
     except Exception as exc: outcomes.append(exc)
    thread=threading.Thread(target=execute); thread.start()
    try:
     self.assertTrue(entered.wait(3))
     with self.assertRaises(BlockingIOError): batch.stop()
     self.assertTrue((batch.root/'closed.json').exists())
    finally:
     release.set(); thread.join(4)
    self.assertFalse(thread.is_alive()); self.assertEqual(len(outcomes),1)
    self.assertIsInstance(outcomes[0],RuntimeError)
    self.assertTrue(batch.stop()); self.assertFalse(fake.items)

 def test_bounded_exec_output_timeout_and_owned_cleanup(self):
  self.assertEqual(_bounded_exec([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],b'hello',lambda:False),b'hello')
  with self.assertRaises(RuntimeError): _bounded_exec([sys.executable,'-c','print("x"*100000)'],b'',lambda:False,cap=1024)
  with self.assertRaises(RuntimeError): _bounded_exec([sys.executable,'-c','import time;time.sleep(5)'],b'',lambda:False,timeout=.1)

 def test_unapproved_option_is_rejected_before_mutation(self):
  with tempfile.TemporaryDirectory() as d:
   batch,fake=self.setup_batch(pathlib.Path(d))
   with patch('docker_batch_guardian.docker',side_effect=fake):
    with self.assertRaises(RuntimeError): batch.prepare_fixed('goose','sha256:'+'a'*64,['worker'],['--privileged','true'])
    self.assertEqual(fake.actions,[])

if __name__=='__main__': unittest.main()
