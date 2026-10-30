import unittest
from unittest import mock
import nuc_real_preclaim_readiness as m
class Readiness(unittest.TestCase):
 def test_nonroot_refuses_before_reading_or_running(self):
  with mock.patch.object(m.os,'geteuid',return_value=1000),mock.patch.object(m.old,'read') as read,mock.patch.object(m.subprocess,'run') as run:
   with self.assertRaises(RuntimeError):m.make_plan(m.Host('test'))
   read.assert_not_called();run.assert_not_called()
if __name__=='__main__':unittest.main()
