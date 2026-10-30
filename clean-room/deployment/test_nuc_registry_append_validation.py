import copy,json,unittest
import nuc_registry_append_validation as a

def ident(n):return '01J000000000000000000000'+f'{n:02d}'
def entry(n):return {'config':f'config-{n}.json','evidence':f'evidence-{n}.json','config_sha256':f'{n:064x}','evidence_sha256':f'{n+32:064x}','catalog_sha256':f'{n+64:064x}'}
def scope(n):return {'intent_id':ident(n),'task_id':ident(n+20),'generation':None if n<3 else ident(n+40),'catalog_sha256':f'{n+64:064x}'}
def raw(x):return json.dumps(x,separators=(',',':')).encode()
class Append(unittest.TestCase):
 def setUp(self):
  self.old={'schema':1,'active_intent':ident(3),'entries':[entry(i) for i in range(4)]};self.new={'schema':1,'active_intent':ident(4),'entries':[*self.old['entries'],entry(4)]};self.prev=[scope(i) for i in range(4)];self.next=scope(4)
 def test_only_append_returns_no_authority(self):
  result=a.validate_append(raw(self.old),raw(self.new),self.prev,self.next);self.assertEqual(result['new_count'],5);self.assertFalse(result['admission_authorized'])
 def test_changed_deleted_or_reordered_history_refused(self):
  for mode in range(3):
   bad=copy.deepcopy(self.new)
   if mode==0:bad['entries'][1]['evidence_sha256']='a'*64
   elif mode==1:bad['entries'].pop(1)
   else:bad['entries'][0],bad['entries'][1]=bad['entries'][1],bad['entries'][0]
   with self.assertRaises(ValueError):a.validate_append(raw(self.old),raw(bad),self.prev,self.next)
 def test_reused_scope_duplicate_fields_and_capacity_refused(self):
  bad=copy.deepcopy(self.next);bad['generation']=self.prev[3]['generation']
  with self.assertRaises(ValueError):a.validate_append(raw(self.old),raw(self.new),self.prev,bad)
  with self.assertRaises(ValueError):a.decode(b'{"schema":1,"schema":1}')
  full=copy.deepcopy(self.old);full['entries']=[entry(i) for i in range(16)];out=copy.deepcopy(full);out['entries'].append(entry(16))
  with self.assertRaises(ValueError):a.validate_append(raw(full),raw(out),[scope(i) for i in range(16)],scope(16))
if __name__=='__main__':unittest.main()
