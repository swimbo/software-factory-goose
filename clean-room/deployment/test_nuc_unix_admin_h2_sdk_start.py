import unittest
import nuc_unix_admin_h2_sdk_start as x
class Scope(unittest.TestCase):
 def tearDown(self):x.ROLE=None
 def test_only_two_fixed_roles(self):
  with self.assertRaises(RuntimeError):x.paths()
  x.ROLE='old';old=x.paths();self.assertEqual(old[0],x.pkg.OLD);self.assertEqual(old[4],9081)
  x.ROLE='new';new=x.paths();self.assertEqual(new[0],x.pkg.NEW);self.assertEqual(new[4],9082);self.assertNotEqual(old[1],new[1])
  x.ROLE='other'
  with self.assertRaises(RuntimeError):x.paths()

class Epoch(unittest.TestCase):
 def test_exact_process_and_socket_binding(self):
  from unittest.mock import patch
  from types import SimpleNamespace
  e={'schema':1,'fixture_retained_active':True,'production_data_used':False,'boot_id':'boot','identities':{x.base.NET:{'pid':1},x.base.SERVER:{'pid':2}},'journal':{'socket_dev':3,'socket_ino':4}}
  original=x.pathlib.Path.read_text
  def read(path,*a,**k):
   if str(path)=='/proc/sys/kernel/random/boot_id':return 'boot\n'
   return original(path,*a,**k)
  with patch.object(x.pathlib.Path,'read_text',read),patch.object(x.active,'identity',side_effect=lambda name:e['identities'][name]),patch.object(x.os,'lstat',return_value=SimpleNamespace(st_dev=3,st_ino=4)):
   x.verify_epoch(e,allow_registered=True)
   changed={**e,'journal':{'socket_dev':3,'socket_ino':5}}
   with self.assertRaises(RuntimeError):x.verify_epoch(changed,allow_registered=True)
   changed={**e,'identities':{**e['identities'],x.base.NET:{'pid':999}}}
   with self.assertRaises(RuntimeError):x.verify_epoch(changed,allow_registered=True)
   changed={**e,'production_data_used':True}
   with self.assertRaises(RuntimeError):x.verify_epoch(changed,allow_registered=True)

class PlanRegression(unittest.TestCase):
 def test_plan_reaches_epoch_read_without_shadowing_paths(self):
  from unittest.mock import patch
  class ReachedEpoch(Exception):pass
  with patch.object(x,'ROLE','old'),patch.object(x.os,'geteuid',return_value=0),patch.object(x.os.path,'lexists',return_value=False),patch.object(x.old,'read',side_effect=ReachedEpoch):
   with self.assertRaises(ReachedEpoch):x.plan()
