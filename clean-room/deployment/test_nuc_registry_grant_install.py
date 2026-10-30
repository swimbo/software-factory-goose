import json,pathlib,tempfile,unittest
from unittest.mock import patch
import nuc_registry_grant_install as m

class Install(unittest.TestCase):
 def test_create_only_and_partial_failure_retains_intent(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td); src=p/'src';dst=p/'dst';etc=p/'etc'
   for d in (src,dst,etc):d.mkdir()
   (p/'boot').write_text('fixture-boot')
   files={'first':'a'*64,'second':'b'*64}; items={name:{'sha256':v} for name,v in files.items()}
   def checked(name,digest,out=None):
    if out is not None:
     if name=='second':raise RuntimeError('candidate changed')
     m.os.write(out,b'first')
    return items[name]
   def store(path,data,mode):
    with open(path,'xb') as f:f.write(data)
   with patch.multiple(m,SOURCE=src,DEST=dst,BOOT=p/'boot',START=etc/'started',DONE=etc/'done',FILES=files),patch.object(m.os,'geteuid',return_value=0),patch.object(m.old,'directory'),patch.object(m.old,'syncdir'),patch.object(m.old,'read'),patch.object(m.old,'store',side_effect=store),patch.object(m,'checked_source',side_effect=checked):
    plan=m.plan()
    with self.assertRaisesRegex(RuntimeError,'candidate changed'):m.apply(plan)
    self.assertTrue((etc/'started').is_file());self.assertFalse((etc/'done').exists())
    self.assertEqual((dst/'first').read_bytes(),b'first')
    with self.assertRaisesRegex(RuntimeError,'already attempted'):m.plan()
 def test_occupied_destination_denied_before_intent(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td);(p/'first').touch()
   with patch.multiple(m,SOURCE=p,DEST=p,START=p/'started',DONE=p/'done',FILES={'first':'a'*64}),patch.object(m.os,'geteuid',return_value=0),patch.object(m.old,'directory'):
    with self.assertRaisesRegex(RuntimeError,'destination occupied'):m.plan()
    self.assertFalse((p/'started').exists())
if __name__=='__main__':unittest.main()
