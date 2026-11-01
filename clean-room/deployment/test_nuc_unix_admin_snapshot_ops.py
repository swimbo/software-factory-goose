import ast,pathlib,unittest
class Snapshot(unittest.TestCase):
 def test_only_fixed_operations_and_queries(self):
  p=pathlib.Path(__file__).with_name('nuc_unix_admin_canary_snapshot_ops.py');tree=ast.parse(p.read_text());strings=[n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str)]
  self.assertTrue(any("target_service_name = 'FenceFixture'" in s and 'LIMIT 101' in s for s in strings));self.assertTrue(any('127.0.0.1:9082' in s for s in strings));self.assertFalse(any(s=='register-old' or s=='register-new' for s in strings))
if __name__=='__main__':unittest.main()
