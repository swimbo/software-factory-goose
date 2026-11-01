import ast,pathlib,unittest
class Epoch(unittest.TestCase):
 def test_namespace_probe_compiles_and_has_explicit_guards(self):
  tree=ast.parse(pathlib.Path(__file__).with_name('nuc_unix_admin_canary_epoch_restart.py').read_text())
  fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='apply')
  assignment=next(n for n in fn.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='code' for t in n.targets))
  source=ast.literal_eval(assignment.value);probe=ast.parse(source)
  self.assertFalse(any(isinstance(n,ast.Assert) for n in ast.walk(probe)))
  self.assertIn('NoNewPrivs',source);self.assertIn('/proc/self/ns/net',source)
 def test_transient_inventory_avoids_multiline_execstart(self):
  source=pathlib.Path(__file__).with_name('nuc_unix_admin_canary_epoch_restart.py').read_text();self.assertIn('--property=LoadState,ActiveState,MainPID,Job,ControlGroup',source)
if __name__=='__main__':unittest.main()
