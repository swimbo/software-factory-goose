import json,stat,types,unittest
from unittest import mock
import nuc_registry_external_preservation as inventory
class ExternalPreservationTests(unittest.TestCase):
 def test_changing_container_set_is_refused(self):
  cid='a'*64;image='sha256:'+'b'*64
  def st(path):return types.SimpleNamespace(st_mode=(stat.S_IFSOCK|0o660) if path==inventory.SOCKET else (stat.S_IFREG|0o755),st_uid=0,st_dev=1,st_ino=2)
  responses=iter(['daemon-1',cid,json.dumps([cid,image,'running',123,'2026-10-30T00:00:00Z']),''])
  with mock.patch.object(inventory.os,'lstat',side_effect=st),mock.patch.object(inventory,'call',side_effect=lambda _:next(responses)),mock.patch.object(inventory,'current_transport',return_value={'id':cid}):
   with self.assertRaisesRegex(RuntimeError,'set changed'):inventory.collect()
 def test_only_exact_current_transport_is_excluded(self):
  own='a'*64;other='b'*64;image='sha256:'+'c'*64
  def st(path):return types.SimpleNamespace(st_mode=(stat.S_IFSOCK|0o660) if path==inventory.SOCKET else (stat.S_IFREG|0o755),st_uid=0,st_dev=1,st_ino=2)
  rows=[ [own,image,'running',123,'2026-10-30T00:00:00Z'],[other,image,'running',124,'2026-10-30T00:00:00Z'] ];ids=own+'\n'+other;inspect='\n'.join(json.dumps(row) for row in rows);responses=iter(['daemon-1',ids,inspect,ids,inspect])
  def ctl(*args):
   unit=args[1];return 'Names='+unit+'\nLoadState=loaded\nActiveState=active\nMainPID=55\nInvocationID='+('f'*32)+'\nJob=\nFragmentPath=/etc/systemd/system/'+unit
  with mock.patch.object(inventory.os,'lstat',side_effect=st),mock.patch.object(inventory,'call',side_effect=lambda _:next(responses)),mock.patch.object(inventory,'current_transport',return_value={'id':own}),mock.patch.object(inventory.old,'ctl',side_effect=ctl):
   shared,transport=inventory.collect_with_transport()
  self.assertEqual(transport['id'],own);self.assertEqual([x[0] for x in shared['containers']],[other])

 def test_spoofed_bridge_pid_is_not_excluded(self):
  cid='a'*64;token='b'*32;payload=[cid,inventory.BRIDGE_IMAGE,999,'running','/sfactory-identity-admin-'+token,token]
  with mock.patch.object(inventory.pathlib.Path,'read_text',return_value='0::/system.slice/docker-'+cid+'.scope\n'),mock.patch.object(inventory,'call',return_value=json.dumps(payload)),mock.patch.object(inventory.os,'getpid',return_value=123):
   with self.assertRaisesRegex(RuntimeError,'bridge identity unavailable'):inventory.current_transport(['docker'])

 def test_digest_is_deterministic(self):
  self.assertEqual(inventory.digest({'a':1,'b':2}),inventory.digest({'b':2,'a':1}))
if __name__=='__main__':unittest.main()
