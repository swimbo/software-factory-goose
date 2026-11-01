import copy,pathlib,sys,unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import nuc_registry_transition_delta as delta

class TransitionDeltaTests(unittest.TestCase):
    def setUp(self):
        stable={'boot_id':'98b86bb5-c04c-46f5-951d-22e497102f29','host_namespace_dev':1,'host_namespace_ino':2,'private_namespace_dev':1,'private_namespace_ino':3,'anchor_pid':12,'anchor_invocation':'a'*32,'postgres_pid':13,'postgres_invocation':'b'*32,'postgres_system_identifier':'123','postgres_data_dev':2,'postgres_data_ino':8,'other_services_sha256':'c'*64}
        restate={'unit':'software-factory-goose-private-restate.service','pid':14,'invocation':'d'*32,'binary_sha256':'e'*64,'data_dev':2,'data_ino':9,'node':'sfgoose-private','config_sha256':'f'*64}
        old=[{'unit':u,'port':p,'identity_sha256':'1'*64} for u,p in delta.OLD_ENDPOINTS]
        self.before={'schema':1,'stable':stable,'restate':restate,'old_sdks':old};self.after=copy.deepcopy(self.before);self.after['restate'].update(pid=15,invocation='2'*32,config_sha256='3'*64)
        for entry in self.after['old_sdks']:entry.update(retired=True,retirement_receipt_sha256='4'*64)
    def test_exact_authorized_delta(self):self.assertTrue(delta.validate(self.before,self.after,'3'*64))
    def test_pg_namespace_and_unrelated_changes_denied(self):
        for field in self.before['stable']:
            after=copy.deepcopy(self.after);after['stable'][field]='changed'
            with self.subTest(field=field),self.assertRaises(ValueError):delta.validate(self.before,after,'3'*64)
    def test_wrong_restate_or_incomplete_retirement_denied(self):
        for case in ('same_pid','binary','config','missing','unretired','substitution'):
            after=copy.deepcopy(self.after)
            if case=='same_pid':after['restate']['pid']=self.before['restate']['pid']
            if case=='binary':after['restate']['binary_sha256']='5'*64
            if case=='config':after['restate']['config_sha256']='5'*64
            if case=='missing':after['old_sdks'].pop()
            if case=='unretired':after['old_sdks'][2]['retired']=False
            if case=='substitution':after['old_sdks'][0]['unit']=after['old_sdks'][1]['unit']
            with self.subTest(case=case),self.assertRaises(ValueError):delta.validate(self.before,after,'3'*64)
if __name__=='__main__':unittest.main()
