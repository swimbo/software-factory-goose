import contextlib,importlib.util,io,json,pathlib,unittest
from unittest import mock
p=pathlib.Path(__file__).with_name('nuc_private_bootstrap_resume2.py')
spec=importlib.util.spec_from_file_location('recover',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Tests(unittest.TestCase):
 def test_plan_mismatch_precedes_any_write(self):
  with mock.patch.object(m,'preflight',return_value={'version':1}),mock.patch.object(m,'store') as store:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'version':2})
   store.assert_not_called()
 def test_resume_sequence_and_registration_failure_withholds_admission(self):
  old_host={'role':'host','netns_dev':1,'netns_ino':2}
  old_private={'role':'private','netns_dev':1,'netns_ino':3}
  fresh_private={'role':'private','netns_dev':1,'netns_ino':4}
  info={'dev':1,'ino':1,'sha256':'test','size':1}
  cfg={'boot_id':'boot','namespace_dev':1,'namespace_ino':3,'host_namespace_dev':1,'host_namespace_ino':2}
  plan={'config':info,'anchors':{'host':{'metadata':info},'private':{'metadata':info}},'bootstrap_nonce':'x','machine_sha256':'y'}
  def read(path,*args,**kwargs):
   if path==m.ETC/'runtime.json':return json.dumps(cfg).encode(),info
   if path==m.RUN/'host-netns.json':return json.dumps(old_host).encode(),info
   if path==m.RUN/'private-netns.json':return json.dumps(old_private).encode(),info
   raise AssertionError(path)
  def run(fail, same_namespace=False):
   writes=[];calls=[]
   def ctl(*args):
    calls.append(args)
    if fail and args==('start',m.NAME+'register.service'):raise RuntimeError('lost registration')
    return ''
   def save(path,data,*args):writes.append(path)
   patches=[mock.patch.object(m,'preflight',return_value=plan),mock.patch.object(m,'read',side_effect=read),
    mock.patch.object(m,'store',side_effect=save),mock.patch.object(m,'systemctl',side_effect=ctl),
    mock.patch.object(m,'new_anchor',side_effect=lambda role:old_host if role=='host' else (old_private if same_namespace else fresh_private)),
    mock.patch.object(m,'postgres_id',return_value=m.SYSTEM_ID),mock.patch.object(m,'directory'),mock.patch.object(m,'syncdir'),
    mock.patch.object(m,'verify_genesis_receipts'),mock.patch.object(m.os,'rename'),mock.patch.object(m.os,'replace'),
    mock.patch.object(m.os.path,'lexists',return_value=False),mock.patch.object(pathlib.Path,'exists',return_value=True)]
   with __import__('contextlib').ExitStack() as stack:
    for patch in patches:stack.enter_context(patch)
    if fail:
     with self.assertRaisesRegex(RuntimeError,'lost registration'):m.apply(plan)
    else:
     with contextlib.redirect_stdout(io.StringIO()):m.apply(plan)
   return writes,calls
  writes,calls=run(False)
  self.assertIn(m.ETC/'private-bootstrap-complete',writes)
  self.assertFalse(any('initdb' in ' '.join(x) or 'createdb' in ' '.join(x) for x in calls))
  self.assertLess(calls.index(('start',m.NAME+'genesis.service')),calls.index(('start',m.NAME+'register.service')))
  writes,calls=run(False,same_namespace=True)
  self.assertIn(m.ETC/'private-bootstrap-complete',writes)
  writes,calls=run(True)
  self.assertNotIn(m.ETC/'private-bootstrap-complete',writes)
  self.assertNotIn(m.DONE,writes)
 def test_nonroot_denied(self):
  with mock.patch.object(m.os,'geteuid',return_value=1000):
   with self.assertRaisesRegex(RuntimeError,'root required'):m.preflight()
 def test_loaded_override_and_alias_denied(self):
  def properties(*args):
   name=args[1].removeprefix(m.NAME);d={'LoadState':'loaded','ActiveState':'inactive','Names':m.NAME+name,'FragmentPath':str(m.UNIT/(m.NAME+name)),'DropInPaths':''}
   if name in m.LIMITS:
    mem,tasks,cpu=m.LIMITS[name];d.update(MainPID='0',DropInPaths=str(m.UNIT/(m.NAME+name+'.d')/'50-resources.conf'),MemoryMax=str(int(mem[:-1])*{'M':1024**2,'G':1024**3}[mem[-1]]),TasksMax=str(tasks),CPUQuotaPerSecUSec={'50%':'500ms','100%':'1s','200%':'2s'}[cpu])
   return '\n'.join(k+'='+v for k,v in d.items())
  with mock.patch.object(m,'systemctl',side_effect=properties):m.verify_loaded_units()
  def alias(*args):
   text=properties(*args)
   return text.replace('Names='+m.NAME+'restate.service','Names='+m.NAME+'restate.service alias.service')
  with mock.patch.object(m,'systemctl',side_effect=alias):
   with self.assertRaisesRegex(RuntimeError,'identity mismatch'):m.verify_loaded_units()
 def test_only_original_pg_identity_accepted(self):
  self.assertEqual(m.SYSTEM_ID,'7702303394074795435')
  self.assertEqual(m.PG_INODE,(66306,19138550));self.assertEqual(m.SOCKET_INODE,(66306,19138868))

if __name__=='__main__':unittest.main()
