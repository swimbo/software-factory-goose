import unittest
from nuc_grant_sidecar_resume import verify_metadata, EXPECTED,DID

def receipt():
 return {'deployment':DID,'metadata':{'id_matches':True,'uri_matches':True,'response_sha256':'a'*64,'service_entries':[{'name':k,'deployment_matches':True,'revision':2,'handler_names':v} for k,v in EXPECTED.items()]}}
class ResumeChecks(unittest.TestCase):
 def test_matching_deployment(self): self.assertEqual(verify_metadata(receipt()),'a'*64)
 def test_changed_identity_revision_and_handlers_refused(self):
  for change in ('identity','revision','handler','duplicate'):
   r=receipt();entries=r['metadata']['service_entries']
   if change=='identity':r['metadata']['uri_matches']=False
   elif change=='revision':entries[0]['revision']=1
   elif change=='handler':entries[0]['handler_names']=[]
   else:entries[1]=entries[0].copy()
   with self.assertRaises(RuntimeError):verify_metadata(r)
if __name__=='__main__':unittest.main()

class ResumeFailureTests(unittest.TestCase):
 def test_failure_closes_only_new_ingress_and_removes_own_marker(self):
  import pathlib,tempfile
  from unittest import mock
  import nuc_grant_sidecar_resume as m
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp); marker=root/'marker';start=root/'start'; calls=[]
   approved={'old':{'pid':1},'registration':{'deployment_id':DID}}
   def store(path,data,mode=0o644): path.write_bytes(data)
   def ctl(action,name): calls.append((action,name))
   with mock.patch.object(m,'ETC',root), mock.patch.object(m,'START',start), mock.patch.object(m,'MARKER',marker), mock.patch.object(m,'plan',return_value=approved), mock.patch.object(m.install,'store',side_effect=store), mock.patch.object(m.install,'syncdir'), mock.patch.object(m.install,'ctl',side_effect=ctl), mock.patch.object(m.install,'sidecar_running',return_value={'pid':2}), mock.patch.object(m.install,'old_snapshot',return_value=approved['old']), mock.patch.object(m.admin,'make_plan',return_value={}), mock.patch.object(m.admin,'apply',return_value=receipt()), mock.patch.object(m,'old_inspect'), mock.patch.object(m,'new_intake_empty',side_effect=RuntimeError('failed readiness')), mock.patch.object(m.time,'sleep'):
    with self.assertRaises(RuntimeError):m.apply(approved)
   self.assertFalse(marker.exists());self.assertTrue(start.exists())
   self.assertEqual([name for action,name in calls if action=='stop'],[m.NAME+x for x in ('intake.socket','worker.socket','launch.socket','runtime.service')])
