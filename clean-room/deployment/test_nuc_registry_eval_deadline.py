import types,unittest
from unittest.mock import Mock,patch
import nuc_registry_eval_deadline as m
G='01M65RMR3F04YB1B016EBBSXGH'
class DeadlineTests(unittest.TestCase):
 def test_changed_boot_denied_before_any_timer_or_cgroup_effect(self):
  d=Mock();d.pinned_json.return_value=({'schema':1,'target_id':G,'task_id':'task','generation':G,'boot_id':'other','cgroup_dev':29,'cgroup_ino':42},'a'*64)
  e={'target':G,'task_id':'task','cgroup_dev':29,'cgroup_ino':42};instance=m.Deadline(d,{'challenges':[e],'boot_id':'current'})
  with patch.object(m.sys,'platform','linux'),patch.object(m.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')),patch.object(m.pathlib.Path,'read_text',return_value='current\n'),patch.object(m.os,'open') as opened:
   with self.assertRaises(m.Unavailable):instance.plan(G)
   opened.assert_not_called();d.run.assert_not_called()
if __name__=='__main__':unittest.main()
