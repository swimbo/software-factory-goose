import unittest
from unittest.mock import patch
import nuc_eval_sequence4_reconcile as m
class Reconcile(unittest.TestCase):
 def test_stale_plan_never_stops_or_removes(self):
  with patch.object(m,'plan',return_value={'x':1}),patch.object(m.old,'store') as store,patch.object(m.old,'ctl') as ctl:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called();ctl.assert_not_called()
if __name__=='__main__':unittest.main()
