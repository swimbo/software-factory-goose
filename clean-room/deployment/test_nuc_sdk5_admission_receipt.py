import copy,json,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_sdk5_admission_receipt as receipt

class AdmissionReceiptTests(unittest.TestCase):
    def setUp(self):
        self.bind={'producer_sha256':'1'*64,'boot_id':'98b86bb5-c04c-46f5-951d-22e497102f29','private_namespace_dev':1,'private_namespace_ino':2,'registry_sha256':'2'*64,'transition_id':'01ARZ3NDEKTSV4RRFFQ69G5FAM','deployment_id':'dp_Test1','process_manifest_sha256':'3'*64,'admin_socket_dev':5,'admin_socket_ino':6}
        self.value={k:v for k,v in self.bind.items() if k in ('producer_sha256','boot_id','private_namespace_dev','private_namespace_ino','registry_sha256','transition_id')}
        self.value.update(schema=1,sdk5={'intent_id':receipt.SDK5_INTENT,'task_id':receipt.SDK5_TASK,'generation':receipt.SDK5_GENERATION,'deployment_id':'dp_Test1','uri':'http://127.0.0.1:9085','process_manifest_sha256':'3'*64},admin={'socket_dev':5,'socket_ino':6,'unix_only':True,'sdk_uid_denied':True,'trusted_journal_uid_allowed':True,'no_inherited_admin_fd':True},ingress={'port':8080,'old_forwarding_denied':True,'unresolved_overlap_count':0,'inventory_sha256':'6'*64,'observation_sha256':'7'*64},retired=[{'unit':u,'port':p,'fence_sha256':'4'*64,'stop_receipt_sha256':'5'*64,'no_job':True,'cgroup_empty':True,'listener_closed':True,'serving_fds_closed':True,'restart_denied':True} for u,p in receipt.OLD_ENDPOINTS])
    def test_exact_scope_accepted_by_pure_validator(self):
        self.assertEqual(receipt.validate(receipt.canonical(self.value),self.bind),self.value)
    def test_independent_binding_substitution_denied(self):
        for field in self.bind:
            changed=copy.deepcopy(self.bind);changed[field]='different'
            with self.subTest(field=field),self.assertRaises(ValueError):receipt.validate(receipt.canonical(self.value),changed)
    def test_incomplete_or_forged_retirement_denied(self):
        for change in ('missing','wrong_unit','stale_listener','failed_restart','substituted_sdk','admin_tcp','old_forwarding','pending_work'):
            v=copy.deepcopy(self.value)
            if change=='missing':v['retired'].pop()
            if change=='wrong_unit':v['retired'][0]['unit']=v['retired'][1]['unit']
            if change=='stale_listener':v['retired'][2]['listener_closed']=False
            if change=='failed_restart':v['retired'][3]['restart_denied']=False
            if change=='substituted_sdk':v['sdk5']['generation']='01ARZ3NDEKTSV4RRFFQ69G5FAM'
            if change=='admin_tcp':v['admin']['unix_only']=False
            if change=='old_forwarding':v['ingress']['old_forwarding_denied']=False
            if change=='pending_work':v['ingress']['unresolved_overlap_count']=1
            with self.subTest(change=change),self.assertRaises(ValueError):receipt.validate(receipt.canonical(v),self.bind)
    def test_ambiguous_json_and_unknown_fields_denied(self):
        with self.assertRaises(ValueError):receipt.parse(b'{"schema":1,"schema":1}\n')
        with self.assertRaises(ValueError):receipt.parse(json.dumps(self.value).encode())
        value=copy.deepcopy(self.value);value['untrusted']=True
        with self.assertRaises(ValueError):receipt.validate(receipt.canonical(value),self.bind)
if __name__=='__main__':unittest.main()
