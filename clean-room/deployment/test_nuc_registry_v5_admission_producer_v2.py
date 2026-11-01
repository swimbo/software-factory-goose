import contextlib,unittest
from unittest import mock
import nuc_registry_v5_admission_producer_v2 as producer
class PendingAdmissionTests(unittest.TestCase):
 def setUp(self):
  self.binding={'head':{'boot_id':'12345678-1234-1234-1234-123456789abc','manifest_sha256':'1'*64,'transition_id':'5DEX7YKFGSEJN362KKSRNWP262','attestation_sha256':'2'*64},'attestation':{'netns_dev':10,'netns_ino':20},'deployment':'dp_Test123','admin_dev':30,'admin_ino':40,'retirement_sha256':'3'*64,'h2_sha256':'4'*64,'producer_sha256':'5'*64,'guard_binary_sha256':'6'*64}
  self.proof={'journal':{'counts':{'invocations':0,'queue_entries':0,'queues':0},'admin_dev':30,'admin_ino':40,'schema':1,'old_listeners_and_established_absent':True,'tcp_admin_absent':True},'deny':{'schema':1,'admin_access_denied':True},'h2_sha256':'4'*64}
 def test_publication_retains_marker_and_records_intent_first(self):
  events=[]
  @contextlib.contextmanager
  def lock():events.append('lock');yield
  def store(path,*args):events.append(path)
  with mock.patch.object(producer.backup,'locked',lock),mock.patch.object(producer.os.path,'lexists',return_value=False),mock.patch.object(producer,'snapshot',return_value=self.binding),mock.patch.object(producer,'evidence',return_value=self.proof),mock.patch.object(producer.old,'store',side_effect=store),mock.patch.object(producer.old,'read',return_value=b'retired\n'):
   result=producer.apply({'schema':1,'binding':self.binding,'scope':'publish exact prospective SDK5 admission while transition remains closed'})
  self.assertTrue(result['transition_still_closed']);self.assertEqual(events,['lock',producer.START,producer.RECEIPT]);self.assertNotIn(producer.gate.ROOT/producer.gate.MARKER,events)
 def test_pending_recheck_refuses_changed_observation(self):
  with mock.patch.object(producer.old,'read',return_value=b'retired\n'):raw=producer.build_receipt(self.binding,self.proof)
  changed={**self.proof,'journal':{**self.proof['journal'],'counts':{'invocations':1,'queue_entries':0,'queues':0}}}
  with mock.patch.object(producer,'snapshot',return_value=self.binding),mock.patch.object(producer.old,'read',side_effect=lambda path,*a,**k: producer.canonical({'schema':1,'head':self.binding['head'],'producer_sha256':self.binding['producer_sha256']}) if path==producer.START else raw),mock.patch.object(producer,'evidence',return_value=changed):
   with self.assertRaisesRegex(RuntimeError,'pending evidence changed'):producer.verify_pending()
if __name__=='__main__':unittest.main()
