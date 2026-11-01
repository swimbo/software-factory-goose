import json,unittest
from unittest.mock import patch
import nuc_registry_v5_install as m
class V5Install(unittest.TestCase):
 def test_units_and_registration_keep_sdk4_distinct(self):
  units=m.units();self.assertEqual(len(units),5)
  self.assertTrue(all('registry-v5-' in n for n in units))
  service=units[m.NAME+'runtime.service'].decode()
  self.assertIn('private-registry-v5-sidecar',service)
  self.assertNotIn('private-registry-sidecar\n',service)
  self.assertIn(b"'uri':'http://127.0.0.1:9085','force':False",m.REGISTER_SOURCE)
  self.assertNotIn(b'9084',m.REGISTER_SOURCE)
 def test_proposal_changes_only_selected_scope(self):
  original={'sdk_port':9084,'worker_id':'old','queue_id':'old','intent_id':'old','task_id':'old','principal':'operator','request':{'schema_version':1,'repository':'r','target_ref':'refs/heads/main','base_revision':'a'*40,'intent':'task','acceptance_criteria':['ok']},'facts':{'spec_clarity':1.0,'blast_radius':0.0,'novelty':0.0,'reversibility':0.0,'has_codified_knowledge':True,'fatal':False},'evidence_sha256':'b'*64,'launch_scope':{}}
  with patch.object(m.old,'read',return_value=json.dumps(original).encode()):cfg,data,fp=m.proposed_config()
  self.assertEqual(cfg['sdk_port'],9085);self.assertEqual(cfg['intent_id'],m.INTENT);self.assertEqual(cfg['task_id'],m.TASK);self.assertEqual(cfg['launch_scope']['generation'],m.GEN);self.assertEqual(cfg['launch_scope']['catalog_sha256'],fp);self.assertEqual(cfg['request'],original['request']);self.assertEqual(cfg['facts'],original['facts']);self.assertEqual(json.loads(data),cfg)
if __name__=='__main__':unittest.main()
