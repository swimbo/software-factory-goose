import unittest
from unittest import mock
import nuc_registry_sidecar_activate as m

class RegistryActivationTests(unittest.TestCase):
 def test_changed_plan_refuses_any_effect(self):
  with mock.patch.object(m,'plan',return_value={'x':1}),mock.patch.object(m.old,'store') as store,mock.patch.object(m.old,'ctl') as ctl:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called();ctl.assert_not_called()
 def test_metadata_requires_all_handlers_on_revision_four(self):
  entries=[{'name':name,'deployment_matches':True,'revision':4,'handler_names':handlers} for name,handlers in m.resume.EXPECTED.items()]
  value={'deployment':'dp_test','metadata':{'id_matches':True,'uri_matches':True,'service_entries':entries,'response_sha256':'a'*64}}
  with mock.patch.object(m.admin,'make_plan',return_value={}),mock.patch.object(m.admin,'apply',return_value=value):
   self.assertEqual(m.metadata('dp_test'),'a'*64)
   entries[0]['revision']=3
   with self.assertRaises(RuntimeError):m.metadata('dp_test')
   entries[0]['revision']=4;entries.pop()
   with self.assertRaises(RuntimeError):m.metadata('dp_test')
if __name__=='__main__':unittest.main()
