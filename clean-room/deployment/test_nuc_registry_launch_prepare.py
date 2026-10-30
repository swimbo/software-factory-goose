import unittest
from unittest import mock
import nuc_registry_launch_prepare as m
class PrepareTests(unittest.TestCase):
 def test_changed_plan_stops_before_write(self):
  with mock.patch.object(m,'plan',return_value={'scope':'current'}),mock.patch.object(m.old,'store') as store:
   with self.assertRaises(RuntimeError):m.apply({'scope':'stale'})
   store.assert_not_called()
 def test_wrong_catalog_or_generation_denied_before_artifacts(self):
  scope={'generation':m.G,'task_id':m.TASK,'catalog_sha256':'0'*64}
  with mock.patch.object(m,'gold') as gold:
   with self.assertRaises(RuntimeError):m.artifacts({'launch_scope':scope},{},{})
   gold.assert_not_called()
  scope['catalog_sha256']='c43c7cc9ab3ec48629692a089de7e315845036ab951973920f18c5f8393d26df';scope['generation']='other'
  with self.assertRaises(RuntimeError):m.artifacts({'launch_scope':scope},{},{})
if __name__=='__main__':unittest.main()
