import importlib.util
import hashlib
import tempfile
import pathlib
import unittest
from unittest import mock
p=pathlib.Path(__file__).with_name('nuc_private_runtime_install.py')
spec=importlib.util.spec_from_file_location('private_install',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PrivateBootstrapTests(unittest.TestCase):
 def test_embedded_helpers_match_reviewed_source(self):
  for name,data,digest in [('nuc_netns_anchor.py',m.ANCHOR_BYTES,m.ANCHOR_SHA256),('nuc_private_register.py',m.REGISTER_BYTES,m.REGISTER_SHA256)]:
   self.assertEqual(pathlib.Path(__file__).with_name(name).read_bytes(),data)
   self.assertEqual(hashlib.sha256(data).hexdigest(),digest)
 def test_all_private_services_are_bound_to_anchor_and_namespace(self):
  units=m.units()
  for suffix in ('initdb.service','postgres.service','createdb.service','genesis.service','restate.service','runtime.service','register.service'):
   text=units[m.NAME+suffix].decode()
   for required in ('BindsTo='+m.NAME+'net.service','After='+m.NAME+'net.service','JoinsNamespaceOf='+m.NAME+'net.service','PrivateNetwork=yes','CapabilityBoundingSet=','NoNewPrivileges=yes','Restart=no'):
    self.assertIn(required,text,(suffix,required))
  for suffix in ('intake.socket','worker.socket'):
   self.assertIn('BindsTo='+m.NAME+'net.service',units[m.NAME+suffix].decode())
 def test_socket_names_and_peer_separation(self):
  units=m.units()
  intake=units[m.NAME+'intake.socket'].decode(); worker=units[m.NAME+'worker.socket'].decode()
  self.assertIn('FileDescriptorName=intake',intake);self.assertIn('SocketGroup=1000',intake)
  self.assertIn('FileDescriptorName=worker',worker);self.assertIn('SocketGroup=sfgoose-worker',worker)
  for text in (intake,worker):self.assertIn('SocketUser=root',text);self.assertIn('SocketMode=0660',text)
 def test_admin_database_never_listens_host_namespace(self):
  units=m.units(); pg=units[m.NAME+'postgres.service'].decode()
  self.assertIn('User=sfgoose-journal',pg);self.assertIn('-h 127.0.0.1 -p 55432',pg)
  self.assertIn('PrivateNetwork=yes',pg);self.assertNotIn('0.0.0.0',pg)
 def test_registration_is_fixed_and_single_attempt(self):
  unit=m.units()[m.NAME+'register.service'].decode()
  self.assertIn('/usr/bin/python3 -I -B '+m.PREFIX+'/private-register.py',unit)
  self.assertIn('Restart=no',unit)
 def test_streaming_pin_and_collision(self):
  with tempfile.TemporaryDirectory() as d:
   src=pathlib.Path(d)/'source'; dst=pathlib.Path(d)/'dest';src.write_bytes(b'known')
   digest=hashlib.sha256(b'known').hexdigest()
   m.stream_pinned(src,digest,dst)
   self.assertEqual(dst.read_bytes(),b'known')
   with self.assertRaises(FileExistsError): m.stream_pinned(src,digest,dst)
   src.write_bytes(b'other')
   with self.assertRaisesRegex(RuntimeError,'digest mismatch'):m.stream_pinned(src,digest)
 def test_streaming_refuses_hardlink_and_oversize(self):
  with tempfile.TemporaryDirectory() as d:
   src=pathlib.Path(d)/'source';src.write_bytes(b'known')
   digest=hashlib.sha256(b'known').hexdigest()
   with self.assertRaisesRegex(RuntimeError,'unsafe staged source'):m.stream_pinned(src,digest,max_bytes=4)
   import os
   os.link(src,pathlib.Path(d)/'other')
   with self.assertRaisesRegex(RuntimeError,'unsafe staged source'):m.stream_pinned(src,digest)
 def test_nonroot_refuses_before_effects(self):
  with mock.patch.object(m.os,'geteuid',return_value=1000):
   with self.assertRaisesRegex(RuntimeError,'root required'):m.preflight()
 def test_changed_plan_refuses_before_effects(self):
  with mock.patch.object(m,'preflight',return_value={'version':1}), mock.patch.object(m,'create') as create:
   with self.assertRaisesRegex(RuntimeError,'plan changed'):m.apply({'version':2})
   create.assert_not_called()

if __name__=='__main__':unittest.main()
