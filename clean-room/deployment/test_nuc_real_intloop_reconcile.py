import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
import nuc_real_intloop_reconcile as r
class ReconcileTests(unittest.TestCase):
 def test_missing_terminal_proof_still_stops_kernel_but_never_cleans(self):
  plan={'generation':r.G};h=Mock();h.rooted=Mock();p=Mock(returncode=0)
  with patch.object(r,'make_plan',return_value=plan),patch.object(r,'store_intent') as intent,patch.object(r.subprocess,'run',return_value=p) as run,patch.object(r,'frozen_empty'),patch.object(r,'helper',return_value=h),patch.object(r,'read_root',return_value=b'cat'),patch.object(r,'CAT_SHA',hashlib.sha256(b'cat').hexdigest()),patch.object(r,'records',side_effect=RuntimeError('missing launch receipt')),patch.object(r,'stop_units') as units,patch.object(r,'remove_exact') as remove:
   with self.assertRaises(RuntimeError):r.apply(r.Host('source'),plan)
   intent.assert_called_once();self.assertEqual(run.call_args.args[0],[str(r.STOP),r.G]);units.assert_not_called();remove.assert_not_called()
 def test_active_deadline_service_refuses_cleanup(self):
  timer='sfactorydeadline'+r.LOW+'.timer';service='sfactorydeadline'+r.LOW+'.service'
  def prop(unit,key):
   values={'LoadState':'not-found','ActiveState':'inactive','Job':'','Names':unit,'FragmentPath':'','DropInPaths':''}
   if unit==service:values.update({'LoadState':'loaded','ActiveState':'active','Transient':'yes','FragmentPath':'/run/systemd/transient/'+service,'ExecStart':'{ path='+str(r.STOP)+' ; argv[]='+str(r.STOP)+' '+r.G+' ; ignore_errors=no ; }'})
   return values[key]
  h=Mock();h.property_value.side_effect=prop
  with self.assertRaises(RuntimeError):r.stop_deadline_units(h)
  h.fixed_run.assert_not_called()
 def test_incomplete_candidate_refuses_snapshot_before_copy(self):
  h=Mock()
  with patch.object(r.os,'listdir',side_effect=[['hello.py'],['result.json']]),patch.object(r.os,'mkdir') as mkdir:
   with self.assertRaises(RuntimeError):r.snapshot(h,'a'*64)
   mkdir.assert_not_called()
 def test_complete_snapshot_requires_matching_writer_and_relay_receipts(self):
  files={'hello.py':b'print(1)\n','test_hello.py':b'assert True\n'}
  digests={k:hashlib.sha256(v).hexdigest() for k,v in files.items()};binding='b'*64
  writer=json.dumps({'status':'executed','digests':digests}).encode()
  done=json.dumps({'schema':1,'generation':r.G,'binding_sha256':binding,'phase':'done','observations':[{},{}]}).encode()
  def read(path,*_):return writer if path.name=='result.json' else done if path.name.endswith('.done.json') else files[path.name]
  h=Mock();h.canonical.side_effect=lambda x:json.dumps(x,sort_keys=True,separators=(',',':')).encode()
  with tempfile.TemporaryDirectory() as temp,patch.object(r,'STATE',Path(temp)),patch.object(r,'SNAP',Path(temp)/'snap'),patch.object(r.os,'listdir',side_effect=[['hello.py','test_hello.py'],['result.json']]),patch.object(r,'read_owned',side_effect=read):
   self.assertEqual(r.snapshot(h,binding),digests)
   self.assertEqual([c.args[0].name for c in h.store.call_args_list],['hello.py','test_hello.py','writer-result.json','relay-done.json','manifest.json'])
if __name__=='__main__':unittest.main()
