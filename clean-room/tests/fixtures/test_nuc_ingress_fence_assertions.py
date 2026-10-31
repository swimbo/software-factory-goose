import nuc_ingress_fence_assertions as check

import unittest
from nuc_ingress_fence_assertions import classify
class DurableRows(unittest.TestCase):
 def test_positive_and_invalid_deployment(self):
  hold={'id':'i1','target_service_name':'FenceFixture','target_service_key':'blocked','target_handler_name':'hold','status':'suspended','pinned_deployment_id':'dp_old'}
  queue={'id':'i2','target_service_name':'FenceFixture','target_service_key':'blocked','target_handler_name':'increment','status':'inboxed','pinned_deployment_id':None}
  delay={'id':'i3','target_service_name':'FenceFixture','target_service_key':'delayed','target_handler_name':'increment','status':'scheduled','pinned_deployment_id':None}
  self.assertFalse(classify([hold,queue,delay],'i1','i2','dp_old')['all_drained'])
  self.assertEqual(classify([{**hold,'status':'invoked'},queue,delay],'i1','i2','dp_old')['hold'],'old-pinned-nonterminal')
  with self.assertRaises(RuntimeError):classify([{**hold,'status':'unrecognized'},queue,delay],'i1','i2','dp_old')
  with self.assertRaises(RuntimeError):classify([{**hold,'pinned_deployment_id':'dp_other'},queue,delay],'i1','i2','dp_old')
  with self.assertRaises(RuntimeError):classify([hold,queue,{**delay,'status':'completed'}],'i1','i2','dp_old')
  with self.assertRaises(RuntimeError):classify([hold,hold,queue,delay],'i1','i2','dp_old')
 def test_after_restart_allows_only_proven_new_effect(self):
  from nuc_ingress_fence_assertions import classify_after_restart
  h={'id':'i1','target_service_name':'FenceFixture','target_service_key':'blocked','target_handler_name':'hold','status':'suspended','pinned_deployment_id':'dp_old'}
  q={'id':'i2','target_service_name':'FenceFixture','target_service_key':'blocked','target_handler_name':'increment','status':'inboxed','pinned_deployment_id':None}
  d={'id':'i3','target_service_name':'FenceFixture','target_service_key':'delayed','target_handler_name':'increment','status':'scheduled','pinned_deployment_id':None}
  f={'id':'i4','target_service_name':'FenceFixture','target_service_key':'after','target_handler_name':'increment','status':'completed','pinned_deployment_id':'dp_new','completion_result':{'version':'new','count':1}}
  state=[{'service_key':'history','key':'count','value_utf8':'1'},{'service_key':'after','key':'count','value_utf8':'1'}]
  self.assertEqual(classify_after_restart([h,q,d,f],state,'i1','i2','i4','dp_old','dp_new',[h,q,d])['forwarded'],'completed-on-new')
  self.assertEqual(classify_after_restart([h,q,{**d,'status':'invoked'},f],state,'i1','i2','i4','dp_old','dp_new',[h,q,d])['old_work']['delayed'],'retained-nonterminal-matured')
  for bad in ({'id':'different'},{'status':'completed'},{'pinned_deployment_id':'dp_other'}):
   with self.subTest(bad=bad),self.assertRaises(RuntimeError):classify_after_restart([h,q,{**d,**bad},f],state,'i1','i2','i4','dp_old','dp_new',[h,q,d])
  with self.assertRaises(RuntimeError):classify_after_restart([h,q,d,{**f,'pinned_deployment_id':'dp_old'}],state,'i1','i2','i4','dp_old','dp_new',[h,q,d])
  with self.assertRaises(RuntimeError):classify_after_restart([h,q,d,{**f,'completion_result':{'version':'old','count':1}}],state,'i1','i2','i4','dp_old','dp_new',[h,q,d])

class CompletedHistory(unittest.TestCase):
 def test_same_id_and_result_required(self):
  row={'id':'inv-history','target_service_name':'FenceFixture','target_service_key':'history','target_handler_name':'increment','status':'completed','pinned_deployment_id':'dp_old','completion_result':'success'}
  self.assertEqual(check.compare_completed_history([row],[dict(row)],'dp_old'),'same-completed-invocation-and-success-status')
  for change in ({'id':'different'},{'completion_result':'failure'},{'completion_result':None},{'pinned_deployment_id':'dp_new'}):
   with self.subTest(change=change), self.assertRaises((RuntimeError, ValueError, TypeError)):
    check.compare_completed_history([row],[dict(row,**change)],'dp_old')
