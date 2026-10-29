import contextlib,io,json,os,pathlib,subprocess,sys,tempfile,unittest
from unittest import mock
from nuc_file_contract import canonical_arguments
from nuc_factory_write_files import execute
from nuc_int_loop_evaluator import freeze,store
from nuc_int_loop_task import create
from nuc_run_fence import RunFence,Denied

class WriterQuarantine(unittest.TestCase):
 def setup_task(self,parent):
  root=pathlib.Path(parent).resolve()/'task'
  with contextlib.redirect_stdout(io.StringIO()):create(root)
  baseline=json.loads((root/'task.json').read_text())['baseline']
  candidate=root/'candidate';candidate.mkdir();(candidate/'README.md').write_bytes((root/'repo'/'README.md').read_bytes())
  scope={'run':'run','baseline':baseline};store(root/'run-scope.json',scope)
  state=root/'dispatch-fence';state.mkdir(mode=0o700);f=RunFence(state,'run',baseline,create=True)
  args={'files':{'hello.py':'hello data','test_hello.py':'test data'}}
  call=f.begin_inference(0,b'initial');f.record_tool(call,b'stream','tool',args);f.begin_tool('tool',args)
  st=candidate.stat();intent={'executor_kind':'writer','candidate':{'path':str(candidate),'dev':st.st_dev,'inode':st.st_ino,'readonly':False}}
  return root,candidate,f,args,intent
 def assert_quarantined(self,root,candidate,f,args,intent):
  with self.assertRaises(Denied):RunFence(f.root,f.run,f.task).begin_tool('tool',args)
  with mock.patch('nuc_int_loop_evaluator.Batch') as cls:
   cls.return_value.read.return_value=intent
   with self.assertRaisesRegex(RuntimeError,'quarantined'):freeze(root,candidate,root/'manifest')
  self.assertEqual(list(root.glob('evaluation-*')),[])
  self.assertFalse((root/'holdout-result.json').exists())
 def test_crash_before_effect_after_first_link_and_lost_ack(self):
  infrastructure=pathlib.Path(__file__).resolve().parent
  for phase in ('before','first_link','lost_ack'):
   with self.subTest(phase=phase),tempfile.TemporaryDirectory() as parent:
    root,candidate,f,args,intent=self.setup_task(parent)
    code='''import json,os,sys
import nuc_factory_write_files as writer
phase=sys.argv[1]
if phase=='before':os._exit(90)
original=writer.os.link
def link(*args,**kwargs):
 original(*args,**kwargs)
 if phase=='first_link':os._exit(91)
writer.os.link=link
result=writer.execute(json.loads(sys.stdin.buffer.read()),sys.argv[2])
if result['status']!='executed':os._exit(89)
os._exit(92)
'''
    result=subprocess.run([sys.executable,'-B','-c',code,phase,str(candidate)],cwd=infrastructure,input=canonical_arguments(args),capture_output=True,timeout=5)
    self.assertEqual(result.returncode,{'before':90,'first_link':91,'lost_ack':92}[phase])
    self.assertEqual((candidate/'hello.py').exists(),phase!='before')
    self.assertEqual((candidate/'test_hello.py').exists(),phase=='lost_ack')
    self.assert_quarantined(root,candidate,f,args,intent);os.close(f.dirfd)
 def test_unlink_or_directory_sync_failure_cannot_release_success(self):
  for failure in ('unlink','directory_sync'):
   with self.subTest(failure=failure),tempfile.TemporaryDirectory() as parent:
    root,candidate,f,args,intent=self.setup_task(parent)
    if failure=='unlink':
     with mock.patch('nuc_factory_write_files.os.unlink',side_effect=OSError('injected')):result=execute(args,str(candidate))
     self.assertTrue(list(candidate.glob('.factory-*')))
    else:
     original=os.fsync
     def sync(fd):
      import stat
      if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('injected')
      return original(fd)
     with mock.patch('nuc_factory_write_files.os.fsync',side_effect=sync):result=execute(args,str(candidate))
    self.assertEqual(result['status'],'refused')
    self.assert_quarantined(root,candidate,f,args,intent);os.close(f.dirfd)
 def test_cleanup_failure_blocks_snapshot_even_after_complete_fence(self):
  with tempfile.TemporaryDirectory() as parent:
   root,candidate,f,args,intent=self.setup_task(parent)
   response=execute(args,str(candidate));self.assertEqual(response['status'],'executed')
   f.record_tool_result('tool',json.dumps(response,separators=(',',':')).encode());call=f.begin_inference(1,b'final');f.record_final(call,b'done')
   with mock.patch('nuc_int_loop_evaluator.Batch') as cls:
    cls.return_value.stop.side_effect=RuntimeError('cleanup unresolved')
    with self.assertRaisesRegex(RuntimeError,'cleanup unresolved'):freeze(root,candidate,root/'manifest')
   self.assertEqual(list(root.glob('evaluation-*')),[]);os.close(f.dirfd)

if __name__=='__main__':unittest.main()
