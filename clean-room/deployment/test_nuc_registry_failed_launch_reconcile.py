import contextlib,hashlib,unittest
from unittest.mock import Mock,patch
import nuc_registry_failed_launch_reconcile as r
class Reconcile(unittest.TestCase):
 def test_live_launch_job_refuses_before_cleanup(self):
  binding='b'*64;h=Mock();records=[{'generation':r.G,'binding_sha256':binding},{'stage':'launch','exit_status':1,'output_bound_exceeded':False}]
  def props(unit,key):
   d={'LoadState':'loaded','Names':r.DRIVER,'Transient':'yes','FragmentPath':'/run/systemd/transient/'+r.DRIVER,'DropInPaths':'','Job':'waiting'}
   return d[key]
  h.property_value.side_effect=props
  with patch.object(r,'load_root',side_effect=records),patch.object(r.os.path,'lexists',return_value=False):
   with self.assertRaisesRegex(RuntimeError,'producer not terminal'):r.driver_terminal(h,binding,'c'*64)
 def test_unknown_removal_preserves_callback(self):
  plan={'generation':r.G};h=Mock();h.callback_lifecycle.return_value=contextlib.nullcontext();events=[]
  def units(h,callback_only=False):events.append('callback' if callback_only else 'other-units')
  def remove(h,role,ident):
   events.append(role)
   if role=='goose':raise RuntimeError('Docker outcome unknown')
  with patch.object(r,'make_plan',return_value=plan),patch.object(r,'store_intent'),patch.object(r.subprocess,'run',return_value=Mock(returncode=0)),patch.object(r,'frozen_empty'),patch.object(r,'helper',return_value=h),patch.object(r,'read_root',return_value=b'cat'),patch.object(r,'CAT_SHA',hashlib.sha256(b'cat').hexdigest()),patch.object(r,'records',return_value=('binding','writer','goose')),patch.object(r,'stop_units',side_effect=units),patch.object(r,'remove_exact',side_effect=remove):
   with self.assertRaisesRegex(RuntimeError,'unknown'):r.apply(r.Host('source'),plan)
  self.assertEqual(events,['other-units','writer','goose'])
 def test_callback_stops_only_after_terminal_engine_and_both_ids(self):
  plan={'generation':r.G};h=Mock();h.callback_lifecycle.return_value=contextlib.nullcontext();events=[]
  h.engine_guard.side_effect=lambda:events.append('engine')
  def units(h,callback_only=False):events.append('callback' if callback_only else 'other-units')
  with patch.object(r,'make_plan',return_value=plan),patch.object(r,'store_intent'),patch.object(r.subprocess,'run',return_value=Mock(returncode=0)),patch.object(r,'frozen_empty'),patch.object(r,'helper',return_value=h),patch.object(r,'read_root',return_value=b'cat'),patch.object(r,'CAT_SHA',hashlib.sha256(b'cat').hexdigest()),patch.object(r,'records',return_value=('binding','writer','goose')),patch.object(r,'stop_units',side_effect=units),patch.object(r,'remove_exact',side_effect=lambda h,role,i:events.append(role)),patch.object(r,'driver_terminal',side_effect=lambda *a:events.append('terminal')),patch.object(r,'stop_deadline_units'):
   r.apply(r.Host('source'),plan)
  self.assertEqual(events,['other-units','writer','goose','terminal','engine','callback'])
if __name__=='__main__':unittest.main()
