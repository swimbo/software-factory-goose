import json,unittest
from nuc_grant_failed_inventory import registration_record,NAME

class RegistrationEvidenceTests(unittest.TestCase):
    def entry(self, **updates):
        d={'_SYSTEMD_UNIT':NAME+'register.service','_SYSTEMD_INVOCATION_ID':'a'*32,'MESSAGE':'GRANT_REGISTRATION '+json.dumps({'id':'dp_123','service_count':4})}; d.update(updates); return json.dumps(d).encode()
    def test_unique_persisted_id(self):
        self.assertEqual(registration_record(self.entry())['invocation_id'],'a'*32)
    def test_missing_or_duplicated_receipts_refused(self):
        for data in (b'',self.entry()+b'\n'+self.entry()):
            with self.assertRaises(ValueError): registration_record(data)
    def test_wrong_unit_or_bad_payload_refused(self):
        for data in (self.entry(_SYSTEMD_UNIT='other.service'),self.entry(_SYSTEMD_INVOCATION_ID=''),self.entry(MESSAGE='GRANT_REGISTRATION {"id":"x","service_count":true}')):
            with self.assertRaises(ValueError): registration_record(data)
    def test_bounded(self):
        with self.assertRaises(ValueError): registration_record(b' '*65537)
if __name__=='__main__': unittest.main()
