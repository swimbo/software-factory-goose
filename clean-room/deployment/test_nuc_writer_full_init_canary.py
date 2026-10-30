import pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).parent/"relay"))
import nuc_root_writer_service as actual
import nuc_writer_full_init_canary as m
import nuc_root_grant_deadline as production
class SyntheticRecords(unittest.TestCase):
 def fixture(self):
  p={'schema':1,'container_id':'a'*64,'image_id':'sha256:'+'b'*64,'pid':12,'network_device':4,'network_inode':6,'sandbox_key':'/run/docker/netns/'+'a'*12,'port':8080};w={'id':'c'*64,'image':'d'*64,'program':'e'*64};d={k:{'path':'/var/lib/software-factory-goose/handoff/'+m.G+'/'+k.removesuffix('_dir'),'dev':1,'ino':2} for k in ('input_dir','output_dir','candidate_dir')};return p,w,d
 def test_scope_hashes_and_synthetic_identity_bind(self):
  p,w,d=self.fixture();r=m.build(p,w,d,'12345678-1234-1234-1234-123456789abc',29,10,100,200);self.assertEqual(r['scope']['catalog_sha256'],m.sha(m.canonical(r['catalog'])));self.assertEqual(r['scope']['provider_binding_sha256'],m.sha(m.canonical(p)));self.assertEqual(r['armed']['verified_grant_sha256'],m.sha(m.canonical(r['grant'])));self.assertEqual(r['writer']['generation'],m.G)
 def test_actual_writer_deadline_accepts_fixture_and_denies_expiry_or_changed_binding(self):
  p,w,d=self.fixture();r=m.build(p,w,d,'12345678-1234-1234-1234-123456789abc',29,10,100,200)
  args=(m.G,r['scope'],r['task'],m.canonical(r['armed']),m.canonical(r['grant']))
  actual.verify_deadline_records(*args,99,199)
  with self.assertRaises(actual.Denied):actual.verify_deadline_records(*args,100,199)
  r['scope']['grant_sha256']='f'*64
  with self.assertRaises(actual.Denied):actual.verify_deadline_records(m.G,r['scope'],r['task'],m.canonical(r['armed']),m.canonical(r['grant']),99,199)
 def test_actual_scope_parser_rejects_changed_catalog(self):
  import nuc_relay_authority as authority
  p,w,d=self.fixture();r=m.build(p,w,d,'12345678-1234-1234-1234-123456789abc',29,10,100,200);raw={1:m.canonical(r['scope']),2:r['consumed'],3:m.canonical(r['catalog']),4:m.canonical(r['provider'])}
  with patch.object(authority,'_root_bytes',side_effect=lambda fd,limit:raw[fd]):
   scope,_=authority.load_root_scope(1,2,3,4);self.assertEqual(scope['generation'],m.G)
   raw[3]=b'{}'
   with self.assertRaises(authority.Denied):authority.load_root_scope(1,2,3,4)
 def test_synthetic_catalog_is_not_production_grant(self):
  p,w,d=self.fixture();r=m.build(p,w,d,'12345678-1234-1234-1234-123456789abc',29,10,100,200)
  with self.assertRaises(RuntimeError):production.matches(r['catalog'],{},r['grant'],r['task'],r['task']['boot_id'],m.G,50)
 def test_rejects_unbound_directory_and_writer(self):
  p,w,d=self.fixture();d['input_dir']['path']='/tmp/other'
  with self.assertRaises(ValueError):m.build(p,w,d,'12345678-1234-1234-1234-123456789abc',29,10,100,200)
  p,w,d=self.fixture();w['id']='bad'
  with self.assertRaises(ValueError):m.build(p,w,d,'12345678-1234-1234-1234-123456789abc',29,10,100,200)
if __name__=='__main__':unittest.main()
