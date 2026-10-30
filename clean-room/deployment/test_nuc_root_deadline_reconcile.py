import unittest
from unittest.mock import patch
import nuc_root_deadline_reconcile as d
class ReconcileTests(unittest.TestCase):
 def test_changed_review_is_refused_before_receipt_creation(self):
  with patch.object(d,'make_plan',return_value={'state':'changed'}),patch.object(d.os,'open') as opened:
   with self.assertRaises(RuntimeError):d.apply(d.Host('source'),{'state':'reviewed'})
   opened.assert_not_called()
 def test_duplicate_manager_property_is_refused(self):
  class R:returncode=0;stdout='LoadState=loaded\nLoadState=not-found\n'
  with patch.object(d.subprocess,'run',return_value=R()):
   with self.assertRaises(RuntimeError):d.unit(d.TIMER)
if __name__=='__main__':unittest.main()
