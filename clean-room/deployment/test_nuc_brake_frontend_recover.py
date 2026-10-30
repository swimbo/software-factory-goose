import contextlib,hashlib,importlib.util,io,json,os,pathlib,tempfile,unittest
from unittest import mock
from types import SimpleNamespace
spec=importlib.util.spec_from_file_location('brake_recovery',pathlib.Path(__file__).with_name('nuc_brake_frontend_recover.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RecoveryTests(unittest.TestCase):
 def with_file(self,body):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'human';fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
   try:body(fd,p)
   finally:os.close(fd)
 def test_empty_pinned_file_gets_synthetic_key_and_no_output(self):
  def check(fd,p):
   meta=m.identity(os.fstat(fd));secret=bytearray([21]*32);out=io.StringIO()
   with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):m.fill_empty(fd,secret,meta)
   self.assertEqual(p.read_bytes(),bytes(secret));self.assertEqual(out.getvalue(),'')
  self.with_file(check)
 def test_nonempty_or_replaced_identity_is_never_overwritten(self):
  def check(fd,p):
   meta=m.identity(os.fstat(fd));os.write(fd,b'old')
   with self.assertRaises(m.Refused):m.fill_empty(fd,bytearray([21]*32),meta)
   self.assertEqual(p.read_bytes(),b'old')
  self.with_file(check)
 def test_interrupted_partial_write_remains_quarantined(self):
  def check(fd,p):
   meta=m.identity(os.fstat(fd));real_write=os.write;calls=0
   def partial(out,data):
    nonlocal calls
    calls+=1
    if calls==1:return real_write(out,data[:8])
    raise OSError('injected write fault')
   with mock.patch.object(m.os,'write',side_effect=partial):
    with self.assertRaises(OSError):m.fill_empty(fd,bytearray([21]*32),meta)
   self.assertEqual(len(p.read_bytes()),8)
   with self.assertRaises(m.Refused):m.fill_empty(fd,bytearray([21]*32),meta)
  self.with_file(check)
 def test_matching_32_byte_copy_is_readonly_and_not_applied(self):
  with tempfile.TemporaryDirectory() as d:
   server=pathlib.Path(d)/'server';human=pathlib.Path(d)/'human';secret=bytes([21])*32
   server.write_bytes(secret);human.write_bytes(secret)
   binary=b'fixture-binary';sha=hashlib.sha256(binary).hexdigest()
   expected={'/fixture/frontend':sha,'/usr/local/libexec/software-factory-goose/sfctl':sha}
   old={'candidate':{'sha256':sha},'sfctl_candidate':{'sha256':sha},'unit_sha256':{}}
   intent={'plan_sha256':m.EXPECTED_PLAN,'plan':old}
   def public(path,mode,limit):
    return (json.dumps(intent).encode(),{'fixture':1}) if path==m.ORIGINAL_INTENT else (binary,{'fixture':2})
   def checked(path,*args,**kwargs):
    p=server if path==m.SERVER else human
    fd=os.open(p,os.O_RDONLY);return fd,m.identity(os.fstat(fd))
   with mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(m,'trusted_dir',return_value={}),mock.patch.object(m,'no_path'),mock.patch.object(m,'bounded_public',side_effect=public),mock.patch.object(m,'open_checked',side_effect=checked),mock.patch.object(m,'digest',return_value=m.EXPECTED_PLAN),mock.patch.object(m,'EXPECTED_BINARIES',expected),mock.patch.object(m,'EXPECTED_UNITS',{}),mock.patch.object(pathlib.Path,'read_text',return_value='fixture-boot'),mock.patch.object(m,'write_record') as write:
    plan=m.plan();self.assertEqual(plan['human_state'],'matching_readonly')
    self.assertNotIn(secret.hex(),json.dumps(plan))
    with self.assertRaises(m.Refused):m.apply(plan)
    write.assert_not_called()
   self.assertEqual(human.read_bytes(),secret)

 def test_unit_state_accepts_unloaded_or_exact_loaded_only(self):
  name='software-factory-goose-brake.service'
  def query(values):
   def run(args,**kwargs):return SimpleNamespace(returncode=0,stdout=values[args[4]]+'\n')
   return run
  base={'LoadState':'not-found','ActiveState':'inactive','FragmentPath':'','DropInPaths':'','Names':name,'MainPID':'0'}
  with mock.patch.object(m.subprocess,'run',side_effect=query(base)):
   self.assertEqual(m.inactive(name)['LoadState'],'not-found')
  loaded={**base,'LoadState':'loaded','FragmentPath':str(m.SYSTEM/name)}
  with mock.patch.object(m.subprocess,'run',side_effect=query(loaded)):
   self.assertEqual(m.inactive(name)['LoadState'],'loaded')
  for changed in ({'DropInPaths':'/tmp/foreign.conf'},{'Names':name+' alias.service'},{'MainPID':'42'},{'ActiveState':'active'},{'FragmentPath':'/tmp/foreign'}):
   with mock.patch.object(m.subprocess,'run',side_effect=query({**loaded,**changed})):
    with self.assertRaises(m.Refused):m.inactive(name)

 def test_expected_original_plan_is_fixed(self):
  self.assertEqual(m.EXPECTED_PLAN,'d339e3893031d84dfbf5744bc24facdeaaf8e0c54f3276819874498b247f22e2')

if __name__=='__main__':unittest.main()
