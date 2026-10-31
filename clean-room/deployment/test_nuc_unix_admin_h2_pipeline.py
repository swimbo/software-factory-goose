import pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tests'/'fixtures'))
import nuc_unix_admin_h2_retire_old as retirement
import nuc_unix_admin_h2_probe_start as probe
import nuc_unix_admin_h2_probe_install as install
import nuc_unix_admin_h2_sdk_install as sdk
import nuc_unix_admin_h2_registration as registration
import nuc_unix_admin_h2_register_lost as lost
import nuc_unix_admin_h2_snapshot_supervisor as snapshots
class FixedProfile(unittest.TestCase):
 def test_stage_bindings_and_scope(self):
  self.assertEqual(probe.PROBE,install.DEST);self.assertEqual(probe.PROBE_SHA,install.SHA)
  self.assertEqual(registration.UNITS['new'],lost.UNIT)
  self.assertEqual(sdk.HANDSHAKE,retirement.FENCE.parent)
  self.assertEqual(snapshots.ACTIONS['prezero-old'],'old-uri-matches');self.assertEqual(snapshots.ACTIONS['reconcile'],'new-uri-matches')
  self.assertNotIn('unix-admin-canary/',str(sdk.ROOT))
 def test_retirement_requires_live_pinned_positive(self):
  pos={'schema':1,'epoch_sha256':'a'*64,'probe_source_sha256':install.SHA,'unit':probe.UNIT,'pid':123,'invocation_id':'a'*32,'start_monotonic_us':123,'stdout_sha256':'b'*64,'stage':'before_retirement','positive_old_count':1,'direct_discovery':True,'direct_reused':True,'ingress_reused':True,'hold':'inv_a','queued':'inv_b','probe_active':True,'no_job':True}
  retirement.validate_positive(pos,'a'*64)
  for key in ('direct_reused','ingress_reused','probe_active','no_job'):
   with self.subTest(key=key),self.assertRaises(RuntimeError):retirement.validate_positive(dict(pos,**{key:False}),'a'*64)
  with self.assertRaises(RuntimeError):retirement.validate_positive(dict(pos,queued=pos['hold']),'a'*64)
 def test_probe_install_denies_missing_native_control(self):
  from unittest.mock import patch
  with patch.object(install.os,'geteuid',return_value=0),patch.object(install.os.path,'lexists',return_value=False),patch.object(install.old,'directory'),patch.object(install.old,'read',return_value=b'{}'),patch.object(install.base,'sha',return_value=install.SHA),patch.object(install,'SOURCE',b'fixture'):
   with self.assertRaises(RuntimeError):install.plan()
 def test_exact_history_responses_bound_to_both_snapshots(self):
  import nuc_unix_admin_h2_classify_after_restart as final
  base={'schema':1,'role':'baseline','epoch_sha256':'e','snapshot_sha256':'s','invocation_sha256':'i','output_sha256':'a'*64,'expected_response':True,'read_only':True}
  after=dict(base,role='afterrestart',epoch_sha256='f',snapshot_sha256='t')
  final.verify_history_outputs(base,after,'i','e','f','s','t')
  for change in ({'output_sha256':'b'*64},{'invocation_sha256':'wrong'},{'expected_response':False},{'snapshot_sha256':'wrong'}):
   with self.subTest(change=change),self.assertRaises(RuntimeError):final.verify_history_outputs(base,dict(after,**change),'i','e','f','s','t')
 def test_probe_terminal_retains_success_and_original_identity(self):
  from unittest.mock import patch
  import nuc_unix_admin_h2_probe_after as after
  fields={'ActiveState':'active','SubState':'exited','MainPID':'0','Job':'','Result':'success','ExecMainCode':'1','ExecMainStatus':'0','ExecMainStartTimestampMonotonic':'42'}
  def show(*args):return fields[args[3]]
  with patch.object(after.old,'ctl',side_effect=show):
   after.terminal(42)
   for key,value in [('ActiveState','inactive'),('ExecMainCode','0'),('ExecMainStartTimestampMonotonic','0'),('Result','failed')]:
    old=fields[key];fields[key]=value
    with self.subTest(key=key),self.assertRaises(RuntimeError):after.terminal(42)
    fields[key]=old
