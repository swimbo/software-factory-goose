import contextlib,unittest
from unittest.mock import patch
import nuc_registry_v5_launch_prepare as prepare
import nuc_registry_v5_intloop_driver as driver
import nuc_registry_v5_admission as admission
class AdmissionGate(unittest.TestCase):
 def test_both_paths_deny_without_producer_before_effect(self):
  for module in (prepare,driver):
   with self.subTest(module=module.__name__),patch.object(module.registry_gate,'admission',return_value=contextlib.nullcontext()),patch.object(admission,'PRODUCER_SHA256',None),patch.object(module.old,'store',side_effect=AssertionError('effect reached')):
    with self.assertRaisesRegex(RuntimeError,'admission producer unavailable'):module.plan()
 def test_scope_is_distinct(self):
  self.assertEqual((prepare.G,prepare.TASK),(driver.G,driver.TASK));self.assertEqual(driver.INTENT,'01M66XF6HPWC3NXMAFDHKHDSP7')
  self.assertIn('registry-v5-grant-prepare',driver.BINARIES);self.assertIn('root-launch-v5',driver.BINARIES)

class AdapterBehavior(unittest.TestCase):
 def test_current_receipt_and_retirement_are_required(self):
  import json,stat
  from types import SimpleNamespace
  from test_nuc_sdk5_admission_receipt import AdmissionReceiptTests
  f=AdmissionReceiptTests();f.setUp();f.bind['transition_id']=admission.retirement.T;f.value['transition_id']=admission.retirement.T
  raw=admission.contract.canonical(f.value)
  head={'transition_id':admission.retirement.T,'boot_id':f.bind['boot_id'],'manifest_sha256':f.bind['registry_sha256'],'attestation_sha256':f.bind['process_manifest_sha256']}
  start={'units':{u:{} for u in admission.retirement.UNITS}}
  end={'transition_id':head['transition_id'],'units':{u:{} for u in admission.retirement.UNITS},'plan_sha256':admission.sha(admission.retirement.canonical(start))}
  profile={'profile':'sdk5','attestation':'attest','probe':'probe','probe_sha256':'9'*64}
  def read(path,*args,**kwargs):
   if path==admission.retirement.START:return json.dumps(start).encode()
   if path==admission.retirement.DONE:return json.dumps(end).encode()
   if path==admission.RECEIPT:return raw
   if str(path)=='attest':return json.dumps({'netns_dev':1,'netns_ino':2}).encode()
   return b'fixed'
  response=SimpleNamespace(returncode=0,stdout=b'{"service_attested":true,"grant_requested":false}',stderr=b'')
  patches=[patch.object(admission,'PRODUCER_SHA256','1'*64),patch.object(admission.old,'read',side_effect=read),patch.object(admission.gate,'verify_head',return_value=head),patch.object(admission.gate,'_protected_read',return_value=b'{"deployment_id":"dp_Test1"}'),patch.object(admission.profiles,'select_for_registry',return_value=profile),patch.object(admission.retirement,'properties',side_effect=lambda u:{'DropInPaths':str(admission.retirement.paths(u)[1])}),patch.object(admission.retirement,'terminal'),patch.object(admission.old,'directory'),patch.object(admission.os,'getxattr',side_effect=OSError(admission.errno.ENODATA,'absent'),create=True),patch.object(admission.os,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFSOCK|0o700,st_uid=2004,st_gid=2004,st_nlink=1,st_dev=5,st_ino=6)),patch.object(admission.subprocess,'run',side_effect=lambda argv,**kw: SimpleNamespace(returncode=0,stdout=(json.dumps({'schema':1,'admission_sha256':admission.sha(raw),'boot_id':head['boot_id'],'transition_id':head['transition_id'],'registry_sha256':head['manifest_sha256'],'private_namespace_dev':1,'private_namespace_ino':2,'old_listeners_absent':True,'old_established_absent':True,'admin_unix_only':True,'no_overlapping_work':True,'overlap_scope':'retired-sdk-targets-excluding-sdk5','retirement_conditions_effective':True}).encode() if str(argv[0])==str(admission.PRODUCER) else response.stdout),stderr=b''))]
  import contextlib
  with contextlib.ExitStack() as stack:
   for p in patches:stack.enter_context(p)
   self.assertEqual(admission.verify()['deployment_id'],'dp_Test1')
   with patch.object(admission.retirement,'terminal',side_effect=RuntimeError('old still active')),self.assertRaisesRegex(RuntimeError,'old still active'):admission.verify()
   with patch.object(admission.os,'getxattr',side_effect=OSError(admission.errno.EOPNOTSUPP,'unsupported'),create=True),self.assertRaisesRegex(RuntimeError,'ACL unavailable'):admission.verify()
   f.value['sdk5']['generation']='01ARZ3NDEKTSV4RRFFQ69G5FAM';raw=admission.contract.canonical(f.value)
   with self.assertRaises(ValueError):admission.verify()
