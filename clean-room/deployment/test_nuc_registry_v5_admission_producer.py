import unittest
from unittest import mock
import nuc_registry_v5_admission_producer as producer
import nuc_sdk5_admission_receipt as contract
class ProducerTests(unittest.TestCase):
 def setUp(self):
  self.binding={'head':{'boot_id':'12345678-1234-1234-1234-123456789abc','manifest_sha256':'1'*64,'transition_id':'5DEX7YKFGSEJN362KKSRNWP262','attestation_sha256':'2'*64},'attestation':{'netns_dev':10,'netns_ino':20},'deployment':'dp_Test123','admin_dev':30,'admin_ino':40,'retirement_sha256':'3'*64,'h2_sha256':'4'*64,'producer_sha256':'5'*64,'guard_binary_sha256':'6'*64}
  self.proof={'journal':{'counts':{'invocations':0,'queue_entries':0,'queues':0},'admin_dev':30,'admin_ino':40,'schema':1,'old_listeners_and_established_absent':True,'tcp_admin_absent':True},'deny':{'schema':1,'admin_access_denied':True},'h2_sha256':'4'*64}
 def test_receipt_binds_exact_head_and_evidence(self):
  with mock.patch.object(producer.old,'read',return_value=b'retired\n'):raw=producer.build_receipt(self.binding,self.proof)
  self.assertEqual(contract.validate(raw,producer.expected(self.binding))['sdk5']['deployment_id'],'dp_Test123')
  bad=dict(self.binding);bad['deployment']='dp_Other'
  with self.assertRaises(ValueError):contract.validate(raw,producer.expected(bad))
 def test_only_final_9086_evidence_accepts_retained_unknown(self):
  final=b'final';stop_raw=b'quiesce';stop={'schema':1,'sdk_listeners_closed':True,'admin_socket_absent':True,'owned_units_terminal':True,'fixture_data_retained':True,'old_work_retained':True,'production_changed':False}
  result={'schema':1,'synthetic_sequence_completed':True,'fixture_quiesced':True,'9082_outcome':'unknown','original_failed_intent_retained':True,'production_accepted':False,'candidate_promoted':False,'final_receipt_sha256':producer.sha(final),'quiesce_receipt_sha256':producer.sha(stop_raw)}
  def read(path,*args):
   if path==producer.H2:return b'final-continuation',result
   if path==producer.H2_FINAL:return final,{}
   if path==producer.H2_STOP:return stop_raw,stop
   if path==producer.old.ETC/'unix-admin-h2-canary-9086-final-continuation-started.json':return b'continuation',{'schema':1,'original_sha256':producer.sha(b'original'),'classification':{},'stages':['classify_afterrestart','quiesce']}
   if path==producer.old.ETC/'unix-admin-h2-canary-9086-orchestration-started.json':return b'original',{}
   raise AssertionError(path)
  with mock.patch.object(producer,'rootjson',side_effect=read),mock.patch.object(producer.old,'read',return_value=b'started'),mock.patch.object(producer.os.path,'lexists',return_value=False):
   self.assertEqual(producer.h2_evidence(),producer.sha(b'final-continuation'))
   with mock.patch.object(producer,'rootjson',side_effect=lambda path,*a: (b'changed',{}) if path==producer.H2_FINAL else read(path,*a)):
    with self.assertRaisesRegex(RuntimeError,'H2 proof unavailable'):producer.h2_evidence()
   result['9082_outcome']='success'
   with self.assertRaisesRegex(RuntimeError,'H2 proof unavailable'):producer.h2_evidence()

 def test_canary_and_guarded_binary_provenance_are_mandatory(self):
  native={'schema':1,'positive':True,'extra_connected_fd_denied':True,'positive_invocation_id':'a'*32,'negative_invocation_id':'b'*32,'fixture_stopped':True,'registration':False,'original_attempt_retained':True};native_raw=b'public canary receipt';started={'binary':{'sha256':producer.CANARY_SHA}}
  guarded={'schema':1,'binary_path':str(producer.v5.BIN),'prior_binary_sha256':producer.v5.SOURCE_SHA,'binary_sha256':producer.GUARDED_BINARY_SHA,'guard_source_sha256':producer.GUARD_SHA,'entrypoint_sha256':producer.ENTRY_SHA,'build_source_commit':producer.SOURCE_COMMIT,'production_features':['registry-v5'],'canary_feature_enabled':False,'native_guard_receipt_sha256':producer.sha(native_raw),'native_guard_binary_sha256':producer.CANARY_SHA,'backup_path':str(producer.old.PREFIX/'private-registry-v5-sidecar.pre-guard'),'installed_inactive':True,'executed':False}
  def read(path,*args):
   if path==producer.NATIVE:return native_raw,native
   if path==producer.NATIVE_START:return b'started',started
   if path==producer.GUARDED:return b'guarded',guarded
   raise AssertionError(path)
  with mock.patch.object(producer,'rootjson',side_effect=read),mock.patch.object(producer.old,'read',return_value=b''):
   self.assertEqual(producer.guarded_binary({'binary_sha256':producer.GUARDED_BINARY_SHA}),guarded)
   guarded['canary_feature_enabled']=True
   with self.assertRaisesRegex(RuntimeError,'provenance unavailable'):producer.guarded_binary({'binary_sha256':producer.GUARDED_BINARY_SHA})

 def test_live_changed_counts_refuse(self):
  with mock.patch.object(producer.old,'read',return_value=b'retired\n'):raw=producer.build_receipt(self.binding,self.proof)
  changed={**self.proof,'journal':{**self.proof['journal'],'counts':{'invocations':1,'queue_entries':0,'queues':0}}}
  with mock.patch.object(producer,'snapshot',return_value=self.binding),mock.patch.object(producer.old,'read',return_value=raw),mock.patch.object(producer,'evidence',return_value=changed):
   with self.assertRaisesRegex(RuntimeError,'evidence changed'):producer.verify_live()
if __name__=='__main__':unittest.main()
