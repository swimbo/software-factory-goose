import unittest
import nuc_registry_admission_journal_probe as probe
class AdmissionProbeTests(unittest.TestCase):
 def test_id_only_safe_bounded_deployment_identifier(self):
  self.assertEqual(probe.validated_id('dp_Ab12'),'dp_Ab12')
  for value in ('',"dp_a' OR TRUE",'not_a_deployment','dp_','dp_'+('a'*81)):
   with self.subTest(value=value),self.assertRaises(RuntimeError):probe.validated_id(value)
 def test_duplicate_json_fails_closed(self):
  with self.assertRaises(RuntimeError):probe.parse(b'{"schema":1,"schema":2}')
if __name__=='__main__':unittest.main()
