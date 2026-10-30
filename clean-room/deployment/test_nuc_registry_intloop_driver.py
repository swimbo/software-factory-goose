import unittest
from unittest import mock
import nuc_registry_intloop_driver as d
class DriverTests(unittest.TestCase):
 def test_submit_failure_still_stops_without_grant_or_launch(self):
  events=[];approved={'x':1}
  def record(stage,value):events.append(stage)
  with mock.patch.object(d,'plan',return_value=approved),mock.patch.object(d.old,'store'),mock.patch.object(d.old,'read',return_value=b'{"request":{}}'),mock.patch.object(d,'record',side_effect=record),mock.patch.object(d,'client',side_effect=RuntimeError('unknown')),mock.patch.object(d,'native') as native,mock.patch.object(d,'stop_generation') as stop:
   with self.assertRaises(RuntimeError):d.apply(approved)
   stop.assert_called_once();native.assert_not_called();self.assertEqual(events,['submit-started'])
 def test_changed_plan_has_no_effect(self):
  with mock.patch.object(d,'plan',return_value={'x':1}),mock.patch.object(d.old,'store') as store,mock.patch.object(d,'stop_generation') as stop:
   with self.assertRaises(RuntimeError):d.apply({'x':2})
   store.assert_not_called();stop.assert_not_called()
if __name__=='__main__':unittest.main()

class SafeFailureMetadata(unittest.TestCase):
 def test_categories_are_allowlisted_not_raw_stderr(self):
  result=d.error_categories(b'permission denied secret-raw-body and helper failed')
  self.assertEqual(result,['permission denied','helper']);self.assertNotIn('secret-raw-body',str(result))
