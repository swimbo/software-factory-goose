import pathlib,tempfile,unittest
from unittest.mock import patch
import nuc_registry_native_readiness_canary as m
class Canary(unittest.TestCase):
 def test_failure_is_retained_and_no_success_record(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)
   def store(path,data,mode):
    with open(path,'xb') as f:f.write(data)
   with patch.multiple(m,START=p/'start',DONE=p/'done',OLD_SOURCE='x=1',READINESS_SOURCE='x=2'),patch.object(m.os,'geteuid',return_value=0),patch.object(m.old,'ctl',return_value='not-found'),patch.object(m.old,'store',side_effect=store),patch.object(m.subprocess,'run',side_effect=TimeoutError('unknown')):
    approved=m.plan()
    with self.assertRaises(TimeoutError):m.apply(approved)
    self.assertTrue((p/'start').exists());self.assertFalse((p/'done').exists())
    with self.assertRaisesRegex(RuntimeError,'already attempted'):m.plan()
if __name__=='__main__':unittest.main()
