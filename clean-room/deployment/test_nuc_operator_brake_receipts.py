import importlib.util, json, os, pathlib, tempfile, unittest
from unittest.mock import patch
p = pathlib.Path(__file__).with_name('nuc_operator_brake_receipts.py')
s = importlib.util.spec_from_file_location('inventory', p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
class InventoryTests(unittest.TestCase):
 def test_linked_records_and_mismatch(self):
  # The metadata ownership validator is exercised using the current fixture owner.
  with tempfile.TemporaryDirectory() as tmp:
   root = pathlib.Path(tmp); state = root/'state'; cat = root/'tasks'; state.mkdir(); cat.mkdir()
   target = '01ARZ3NDEKTSV4RRFFQ69G5FAV'
   def put(path, data):
    path.write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode()); path.chmod(0o600)
   put(state/(target+'.canary-receipt.json'), {'target_id':target,'operator_frontend_verified':True,'kernel_stop_verified':True,'engine_reconciled':False,'slice_removed':True})
   put(state/(target+'.canary-intent.json'), {'target_id':target,'operation':'operator-frontend-sleeper-stop'})
   put(cat/(target+'.json'), {'target_id':target})
   put(state/(target+'.closed'), (target+'\n').encode())
   original = m.os.fstat
   def fake(fd):
    st = original(fd)
    values = list(st); values[4] = values[5] = 0
    return os.stat_result(values)
   with patch.object(m,'STATE',state), patch.object(m,'ROOT',cat), patch.object(m.os,'fstat',side_effect=fake):
    self.assertEqual(len(m.make_plan(m.Host())['receipts']), 1)
    put(state/(target+'.closed'), b'wrong\n')
    with self.assertRaises(RuntimeError): m.make_plan(m.Host())
if __name__ == '__main__': unittest.main()
