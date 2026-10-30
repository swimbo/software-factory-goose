import unittest
from unittest import mock
import nuc_real_process_attestation as m
class AttestationTests(unittest.TestCase):
 def test_changed_plan_cannot_write(self):
  with mock.patch.object(m,'plan',return_value={'pid':1}),mock.patch.object(m.old,'store') as store:
   with self.assertRaises(RuntimeError):m.apply({'pid':2})
   store.assert_not_called()
if __name__=='__main__':unittest.main()
