import unittest
import nuc_registry_fd_graph as graph
class PeerGraphTests(unittest.TestCase):
 def test_detects_inherited_client_with_different_inode(self):
  unix={1:{'type':1,'state':1,'peer':2,'name':None},2:{'type':1,'state':1,'peer':1,'name':graph.ADMIN}}
  with self.assertRaisesRegex(ValueError,'connected admin'):graph.classify({1},unix,set())
 def test_unknown_socket_and_missing_peer_fail_closed(self):
  unix={2:{'type':1,'state':10,'peer':None,'name':graph.ADMIN},3:{'type':1,'state':1,'peer':None,'name':None}}
  for fds in ({4},{3}):
   with self.subTest(fds=fds),self.assertRaises(ValueError):graph.classify(fds,unix,set())
 def test_other_classified_socket_is_allowed(self):
  unix={2:{'type':1,'state':10,'peer':None,'name':graph.ADMIN}}
  self.assertEqual(graph.classify({4},unix,{4}),{'all_socket_fds_classified':True,'admin_socket_absent':True})
if __name__=='__main__':unittest.main()
