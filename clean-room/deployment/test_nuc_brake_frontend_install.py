import contextlib, importlib.util, io, os, pathlib, tempfile, unittest
from unittest import mock
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('brake_install',pathlib.Path(__file__).with_name('nuc_brake_frontend_install.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class InstallTests(unittest.TestCase):
 def test_apply_keeps_synthetic_secret_out_of_records(self):
  writes={}; key=bytes([19])*32
  def write(path,data,mode,uid=0,gid=0):
   self.assertNotIn(str(path),writes);writes[str(path)]=(bytes(data),mode,uid,gid)
  out=io.StringIO()
  with mock.patch.object(m,'write_new',side_effect=write),mock.patch.object(m.os,'getrandom',create=True,return_value=key),contextlib.redirect_stdout(out):
   m.apply({'test':'fixture'},b'fixed-binary',b'fixed-sfctl')
  self.assertEqual(writes[str(m.SERVER_KEY)],(key,0o440,0,2003))
  self.assertEqual(writes[str(m.HUMAN_KEY)],(key,0o600,1000,1000))
  for path,(data,_,_,_) in writes.items():
   if path not in (str(m.SERVER_KEY),str(m.HUMAN_KEY)):self.assertNotIn(key,data)
  self.assertNotIn(key.hex(),out.getvalue())
  self.assertIn(str(m.RECEIPT),writes)
 def test_partial_key_copy_failure_retains_intent_without_receipt(self):
  writes={}
  def write(path,data,mode,uid=0,gid=0):
   if path==m.HUMAN_KEY:raise OSError('injected failure')
   writes[str(path)]=bytes(data)
  with mock.patch.object(m,'write_new',side_effect=write),mock.patch.object(m.os,'getrandom',create=True,return_value=bytes([19])*32):
   with self.assertRaises(OSError):m.apply({'test':'fixture'},b'fixed-binary',b'fixed-sfctl')
  self.assertIn(str(m.INTENT),writes);self.assertIn(str(m.SERVER_KEY),writes);self.assertNotIn(str(m.RECEIPT),writes)
 def test_existing_key_collision_refuses_before_random_or_write(self):
  bo=SimpleNamespace(pw_uid=1000,pw_gid=1000);brake=SimpleNamespace(pw_uid=2003,pw_gid=2003)
  def user(name):return bo if name=='bo' else brake
  def exists(path):return path==m.SERVER_KEY
  with mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(m,'trusted_dir',return_value={'uid':0}),mock.patch.object(m.pwd,'getpwnam',side_effect=user),mock.patch.object(m.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=2003)),mock.patch.object(pathlib.Path,'exists',exists),mock.patch.object(pathlib.Path,'is_symlink',return_value=False),mock.patch.object(m,'write_new') as write,mock.patch.object(m.os,'getrandom',create=True) as random:
   with self.assertRaises(m.Refused):m.plan(pathlib.Path('/tmp/sfactory-test/binary'),'a'*64,pathlib.Path('/tmp/sfactory-test/sfctl'),'b'*64)
   write.assert_not_called();random.assert_not_called()

 def test_mode_is_set_before_owner_change(self):
  with tempfile.TemporaryDirectory() as d:
   path=pathlib.Path(d)/'fixture'; calls=[];real_chmod=os.fchmod;real_chown=os.fchown
   def chmod(fd,mode):calls.append('chmod');return real_chmod(fd,mode)
   def chown(fd,uid,gid):calls.append('chown');return real_chown(fd,uid,gid)
   with mock.patch.object(m.os,'fchmod',side_effect=chmod),mock.patch.object(m.os,'fchown',side_effect=chown):
    m.write_new(path,b'test',0o600,os.getuid(),os.getgid())
   self.assertEqual(calls,['chmod','chown']);self.assertEqual(path.read_bytes(),b'test')

 def test_empty_random_fails_before_creating_key_files(self):
  writes={}
  def write(path,data,mode,uid=0,gid=0):writes[str(path)]=bytes(data)
  with mock.patch.object(m,'write_new',side_effect=write),mock.patch.object(m.os,'getrandom',create=True,return_value=bytes(32)):
   with self.assertRaises(m.Refused):m.apply({'test':'fixture'},b'fixed-binary',b'fixed-sfctl')
  self.assertNotIn(str(m.SERVER_KEY),writes);self.assertNotIn(str(m.HUMAN_KEY),writes);self.assertNotIn(str(m.RECEIPT),writes)

if __name__=='__main__':unittest.main()
