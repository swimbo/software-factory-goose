import unittest
from unittest import mock
import nuc_grant_journal_canary as c
class CanaryTests(unittest.TestCase):
 def test_claim_failure_preserves_reservation_boundary(self):
  events=[]; approved={'scope':c.SCOPE}
  def client(role,mode,body):
   events.append(mode)
   if mode=='pull':raise RuntimeError('unknown claim')
   return {'intent_id':c.install.INTAKE}
  with mock.patch.object(c,'plan',return_value=approved),mock.patch.object(c,'store',side_effect=lambda name,obj:events.append(name)),mock.patch.object(c,'client',side_effect=client),mock.patch.object(c,'grant') as grant:
   with self.assertRaises(RuntimeError):c.apply(approved)
   grant.assert_not_called()
  self.assertIn('grant-journal-pull-started.json',events)
  self.assertNotIn('grant-journal-reserve-started.json',events)
if __name__=='__main__':unittest.main()
