import unittest
from unittest.mock import patch
import nuc_writer_cap0_diagnostic as m
class Diagnostic(unittest.TestCase):
 def test_stale_plan_has_no_effect(self):
  with patch.object(m,'plan',return_value={'v':1}),patch.object(m.old,'store') as store,patch.object(m.subprocess,'run') as run:
   with self.assertRaises(RuntimeError):m.apply({'v':2})
   store.assert_not_called();run.assert_not_called()
 def test_program_does_not_use_authority_or_key(self):
  compile(m.CODE,'<diagnostic>','exec');self.assertNotIn('check_stop(',m.CODE);self.assertNotIn('authority.verify(',m.CODE);self.assertNotIn('credential',m.CODE);self.assertNotIn('serve_listener',m.CODE)
if __name__=='__main__':unittest.main()
