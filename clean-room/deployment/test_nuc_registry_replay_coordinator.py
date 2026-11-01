import json,unittest
from unittest.mock import patch
import nuc_registry_replay_coordinator as c
class Coordinator(unittest.TestCase):
 def fixture(self):
  configs={};entries=[]
  for i in range(4):
   name=f'config-{i}.json';raw=c.canonical({'task_id':'01ARZ3NDEKTSV4RRFFQ69G5FA'+str(i),'intent_id':'01ARZ3NDEKTSV4RRFFQ69G5FB'+str(i),'queue_id':'queue-'+str(i)});configs[name]=raw
   entries.append({'config':name,'evidence':f'evidence-{i}.json','config_sha256':c.sha(raw),'evidence_sha256':'a'*64,'catalog_sha256':'b'*64})
  return c.canonical({'schema':1,'active_intent':'01ARZ3NDEKTSV4RRFFQ69G5FB0','entries':entries}),configs
 def test_fixed_manifest_derives_all_prior_objects(self):
  manifest,configs=self.fixture();targets=c.derive_targets(manifest,lambda name:configs[name]);self.assertEqual(len(targets),12)
 def test_config_replacement_and_unsafe_paths_refused(self):
  manifest,configs=self.fixture()
  with self.assertRaisesRegex(RuntimeError,'config changed'):c.derive_targets(manifest,lambda name:b'{}')
  obj=json.loads(manifest);obj['entries'][0]['config']='../escape.json'
  with self.assertRaisesRegex(RuntimeError,'path unavailable'):c.derive_targets(c.canonical(obj),lambda name:configs[name])
 def test_missing_restart_authority_refuses_before_read(self):
  with patch.object(c,'RUNTIME_RECEIPT_PRODUCER_SHA',None),patch.object(c.gate,'_protected_read') as read:
   with self.assertRaisesRegex(RuntimeError,'receipt producer unavailable'):c.capture_after({'transition_id':'x'})
   read.assert_not_called()

class ProfiledAttestorTests(unittest.TestCase):
 def test_selected_probe_is_pinned_and_sdk4_bytes_cannot_satisfy_sdk5(self):
  import hashlib,pathlib
  from unittest.mock import patch,Mock
  raw=b'sdk5-probe';profile={'probe':pathlib.Path('/fixed/v5-probe'),'probe_sha256':hashlib.sha256(raw).hexdigest(),'port':9085}
  with patch.object(c.gate,'registry_profile',return_value=profile),patch.object(c.gate,'_protected_read',return_value=raw) as read,patch.object(c.subprocess,'run',return_value=Mock(returncode=0,stdout=b'{"service_attested":true,"grant_requested":false}',stderr=b'')) as run:
   self.assertEqual(c.assert_attestor(b'manifest'),profile);self.assertEqual(read.call_args.args[0],profile['probe']);self.assertEqual(run.call_args.args[0],[str(profile['probe'])])
  with patch.object(c.gate,'registry_profile',return_value=profile),patch.object(c.gate,'_protected_read',return_value=b'sdk4-probe'),patch.object(c.subprocess,'run') as run:
   with self.assertRaisesRegex(RuntimeError,'attestor executable changed'):c.assert_attestor(b'manifest')
   run.assert_not_called()

if __name__=='__main__':unittest.main()
