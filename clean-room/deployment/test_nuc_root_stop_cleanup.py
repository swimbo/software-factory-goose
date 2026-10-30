#!/usr/bin/env python3
import pathlib,runpy,unittest
m=runpy.run_path(str(pathlib.Path(__file__).with_name('nuc_root_stop_cleanup.py')))
class Tests(unittest.TestCase):
 def test_manager_exec_matches_actual_show_format_without_pid_path_substitution(self):
  f=m['manager_exec_matches'];p='/usr/local/libexec/software-factory-goose/sfactory_root_stop'
  actual='{ path='+p+' ; argv[]='+p+' ; ignore_errors=no ; start_time=[Thu 2026-10-29 22:47:14 EDT] ; stop_time=[n/a] ; pid=292951 ; code=(null) ; status=0/0 }'
  self.assertTrue(f(actual,292951))
  self.assertFalse(f(actual,292952));self.assertFalse(f(actual,0))
  self.assertFalse(f(actual.replace('argv[]='+p,'argv[]='+p+' --other'),292951))
  self.assertFalse(f(actual.replace('path='+p,'path=/tmp/other'),292951))
  self.assertFalse(f(actual.replace('code=(null)','code=exited'),292951))
  self.assertFalse(f(actual+' '+actual,292951))
if __name__=='__main__':unittest.main()
