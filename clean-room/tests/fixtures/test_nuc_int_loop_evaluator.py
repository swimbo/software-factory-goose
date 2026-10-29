import pathlib,tempfile,unittest,json,os
from nuc_run_fence import RunFence
from nuc_int_loop_evaluator import store
from unittest import mock
from nuc_int_loop_evaluator import freeze

class SnapshotControls(unittest.TestCase):
 def fixture(self,parent):
  task=pathlib.Path(parent).resolve()/'task';task.mkdir(mode=0o700);repo=task/'repo';repo.mkdir();(repo/'README.md').write_text('baseline')
  source=task/'candidate';source.mkdir();(source/'README.md').write_text('baseline')
  for name in ('hello.py','test_hello.py'):(source/name).write_text('data')
  store(task/'task.json',{'baseline':'baseline'});store(task/'run-scope.json',{'run':'run','baseline':'baseline'})
  fence_root=task/'dispatch-fence';fence_root.mkdir(mode=0o700)
  fence=RunFence(fence_root,'run','baseline',create=True);arguments={'files':{'hello.py':'data','test_hello.py':'data'}}
  call=fence.begin_inference(0,b'first');fence.record_tool(call,b'stream','tool',arguments);fence.begin_tool('tool',arguments)
  fence.record_tool_result('tool',b'{"status":"executed","exit_code":0,"stdout":"Both task files written.","stderr":""}')
  call=fence.begin_inference(1,b'second');fence.record_final(call,b'final');os.close(fence.dirfd)
  st=source.stat();binding={'executor_kind':'writer','candidate':{'path':str(source),'dev':st.st_dev,'inode':st.st_ino,'readonly':False}}
  return task,source,binding
 def test_exact_files_and_baseline_are_required(self):
  for variant in ('extra','baseline','hardlink'):
   with self.subTest(variant=variant),tempfile.TemporaryDirectory() as parent:
    task,source,binding=self.fixture(parent)
    if variant=='extra':(source/'.factory-remnant').write_text('partial')
    elif variant=='baseline':(source/'README.md').write_text('changed')
    else:(source/'hello.py').unlink();(source/'hello.py').hardlink_to(source/'test_hello.py')
    with mock.patch('nuc_int_loop_evaluator.Batch') as cls:
     cls.return_value.read.return_value=binding
     with self.assertRaises(RuntimeError):freeze(task,source,task/'manifest')
     cls.return_value.stop.assert_called_once()
 def test_source_must_match_generation_and_snapshot_is_hash_bound(self):
  with tempfile.TemporaryDirectory() as parent:
   task,source,binding=self.fixture(parent)
   with mock.patch('nuc_int_loop_evaluator.Batch') as cls:
    cls.return_value.read.return_value=binding
    root=freeze(task,source,task/'manifest')
    self.assertEqual((root/'snapshot'/'hello.py').read_text(),'data')
    self.assertEqual((root/'snapshot').stat().st_mode & 0o777,0o555)
    binding['candidate']['inode']+=1
    with self.assertRaisesRegex(RuntimeError,'binding'):freeze(task,source,task/'manifest')
 def test_complete_looking_unknown_generation_is_quarantined(self):
  with tempfile.TemporaryDirectory() as parent:
   task,source,binding=self.fixture(parent)
   state=task/'dispatch-fence'/'state';value=json.loads(state.read_text());value['stage']='tool_unknown';state.write_text(json.dumps(value))
   with mock.patch('nuc_int_loop_evaluator.Batch') as cls:
    cls.return_value.read.return_value=binding
    with self.assertRaisesRegex(RuntimeError,'quarantined'):freeze(task,source,task/'manifest')
   self.assertEqual(list(task.glob('evaluation-*')),[])
 def test_modified_provider_bound_bytes_are_not_snapshotted(self):
  with tempfile.TemporaryDirectory() as parent:
   task,source,binding=self.fixture(parent);(source/'hello.py').write_text('different')
   with mock.patch('nuc_int_loop_evaluator.Batch') as cls:
    cls.return_value.read.return_value=binding
    with self.assertRaisesRegex(RuntimeError,'provider-bound'):freeze(task,source,task/'manifest')
   self.assertFalse(any(root.joinpath('snapshot.json').exists() for root in task.glob('evaluation-*')))

if __name__=='__main__':unittest.main()
