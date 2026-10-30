#!/usr/bin/env python3
import pathlib,runpy,unittest
m=runpy.run_path(str(pathlib.Path(__file__).with_name('nuc_root_stop_canary.py')))
class Tests(unittest.TestCase):
 def test_systemd_preflight_machine_values(self):
  f=m['preflight_succeeded'];prefix='{ path=/usr/bin/python3 ; argv[]=fixed ; pid=12 ; '
  self.assertTrue(f(prefix+'code=exited ; status=0 }'))
  self.assertTrue(f(prefix+'code=exited ; status=0/SUCCESS }'))
  for suffix in ('code=exited ; status=1 }','code=exited ; status=01 }','code=killed ; status=0 }','code=exited ; status=0'):
   self.assertFalse(f(prefix+suffix))
  self.assertFalse(f(prefix+'code=exited ; status=0 } '+prefix+'code=exited ; status=0 }'))
  self.assertFalse(f('{ path=/tmp/other ; code=exited ; status=0 }'))
if __name__=='__main__':unittest.main()
