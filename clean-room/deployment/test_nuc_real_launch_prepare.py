import copy,unittest
from unittest import mock
import nuc_real_launch_prepare as m
class PreparationTests(unittest.TestCase):
 def cfg(self):
  return {'launch_scope':{'generation':m.G,'task_id':m.TASK,'catalog_sha256':'cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7'},'request':{'intent':'build exact'}}
 def images(self):return {'worker':{'image_id':'sha256:'+'a'*64,'program_sha256':'b'*64},'writer':{'image_id':'sha256:'+'c'*64,'program_sha256':'d'*64}}
 def test_artifacts_bind_prompt_and_provider(self):
  golden={'model':'gpt-4o-mini','messages':[{'role':'system','content':'x'},{'role':'user','content':'y'}]}
  with mock.patch.object(m,'gold',side_effect=lambda:copy.deepcopy(golden)):
   a=m.artifacts(self.cfg(),{'identity':'x'},self.images());b=m.artifacts(self.cfg(),{'identity':'y'},self.images())
  self.assertNotEqual(a[4]['provider_binding_sha256'],b[4]['provider_binding_sha256']);self.assertIn(b'factory__write_files',a[0]);self.assertEqual(a[4]['relay_scope_template_sha256'],m.digest(a[2]))
 def test_changed_plan_never_writes(self):
  with mock.patch.object(m,'plan',return_value={'x':1}),mock.patch.object(m.old,'store') as store:
   with self.assertRaises(RuntimeError):m.apply({'x':2})
   store.assert_not_called()
 def test_units_separate_broker_and_relay_and_never_start_workers(self):
  units=m.units();self.assertEqual(len(units),5);values=[x.decode() for x in units.values()]
  writer=next(v for k,v in units.items() if k.startswith('sfactorywriter') and k.endswith('.service')).decode();relay=next(v for k,v in units.items() if k.startswith('sfactoryrelay') and k.endswith('.service')).decode()
  self.assertIn('Slice=system.slice',writer);self.assertIn('Slice=sfactory'+m.LOW+'.slice',relay);self.assertIn('LimitCORE=0',relay);self.assertIn('NetworkNamespacePath='+m.NET,relay);self.assertNotIn('docker start',''.join(values))
if __name__=='__main__':unittest.main()
