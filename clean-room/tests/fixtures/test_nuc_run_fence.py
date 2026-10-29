import os,tempfile,unittest
from nuc_run_fence import RunFence,Denied
class FenceTests(unittest.TestCase):
 def test_restart_unknown_tool_and_dispatch_are_never_reissued(self):
  with tempfile.TemporaryDirectory() as d:
   f=RunFence(d,'run','task',create=True);call=f.begin_inference(0,b'first')
   with self.assertRaises(Denied):RunFence(d,'run','task').begin_inference(0,b'first')
   f.record_tool(call,b'stream','id',{'command':'pwd'})
   with self.assertRaises(Denied):f.begin_tool('id',{'command':'other'})
   f.begin_tool('id',{'command':'pwd'})
   with self.assertRaises(Denied):RunFence(d,'run','task').begin_tool('id',{'command':'pwd'})
   f.record_tool_result('id',b'safe');second=f.begin_inference(1,b'second')
   with self.assertRaises(Denied):RunFence(d,'run','task').begin_inference(1,b'second')
   f.record_final(second,b'final')
   with self.assertRaises(Denied):RunFence(d,'run','task').begin_inference(0,b'first')
 def test_scope_and_file_permissions(self):
  with tempfile.TemporaryDirectory() as d:
   RunFence(d,'run','task',create=True)
   with self.assertRaises(Denied):RunFence(d,'different','task')
   os.unlink(os.path.join(d,'state'))
   with self.assertRaises(Denied):RunFence(d,'run','task',create=True)
 def test_permissions(self):
  with tempfile.TemporaryDirectory() as d:
   RunFence(d,'run','task',create=True)
   os.chmod(os.path.join(d,'state'),0o644)
   with self.assertRaises(Denied):RunFence(d,'run','task')
if __name__=='__main__':unittest.main()
