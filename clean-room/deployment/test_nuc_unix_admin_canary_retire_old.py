import unittest
from unittest.mock import patch
import nuc_unix_admin_canary_retire_old as m
class Retirement(unittest.TestCase):
 def test_positive_receipt_requires_v2_and_both_reused_connections(self):
  p={'schema':1,'epoch_sha256':'a'*64,'probe_source_sha256':m.probe_v2.SHA,'unit':'sfactory-unix-admin-canary-ingress-probe.service','pid':7,'invocation_id':'b'*32,'start_monotonic_us':4,'stdout_sha256':'c'*64,'stage':'before_retirement','positive_old_count':1,'direct_discovery':True,'direct_reused':True,'ingress_reused':True,'hold':'inv_hold','queued':'inv_queue','probe_active':True,'no_job':True}
  m.validate_positive(p,'a'*64)
  for field,value in (('probe_source_sha256','0'*64),('direct_reused',False),('ingress_reused',False)):
   changed=dict(p);changed[field]=value
   with self.assertRaises(RuntimeError):m.validate_positive(changed,'a'*64)
 def test_failed_stop_preserves_fence_without_stopped_marker(self):
  calls=[];approved={'unit':m.pkg.OLD}
  with patch.object(m,'plan',return_value=approved),patch.object(m.old,'store',side_effect=lambda *x:calls.append('intent')),patch.object(m,'marker',side_effect=lambda p,*x:calls.append(p.name)),patch.object(m.active,'properties',side_effect=RuntimeError('stop unknown')):
   with self.assertRaisesRegex(RuntimeError,'stop unknown'):m.apply(approved)
  self.assertEqual(calls,['intent','old.retired'])
if __name__=='__main__':unittest.main()
