import unittest
import nuc_registry_restore_history_probe_v2 as probe
class HistoryProbeTests(unittest.TestCase):
 def test_fixed_targets_and_sql_metacharacter_rejection(self):
  valid=[{'service':'ClaimLeaseJournal','key':'01M65RMR3FE6FQTFRBHERRHXRG'},{'service':'IntakeJournal','key':'01M65RMR3FE6FQTFRBHERRHXRG'},{'service':'WorkerQueueJournal','key':'queue_1'}]
  self.assertEqual(len(probe.targets(valid)),3)
  for bad in ([{'service':'WorkerQueueJournal','key':"x' OR 1=1"}],valid+valid,[{'service':'Other','key':'a'}],list(reversed(valid))):
   with self.subTest(bad=bad),self.assertRaises(RuntimeError):probe.targets(bad)
 def test_duplicate_json_refused(self):
  with self.assertRaises(RuntimeError):probe.parse(b'{"a":1,"a":2}')
if __name__=='__main__':unittest.main()
