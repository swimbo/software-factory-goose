import unittest
from unittest.mock import patch
import nuc_relay_server as server
from nuc_relay_authority import Denied
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'

class FailClosedStartup(unittest.TestCase):
    def test_missing_root_guard_stops_before_provider_construction(self):
        descriptors={'scope':3,'catalog':4,'consumed':5,'provider':6,'callback':7,'provider-binding':8}
        class Guard:
            def __init__(self,scope,binding):pass
            def check(self,scope):raise Denied('not installed')
        with patch.object(server.os,'getuid',return_value=2000), patch.object(server.os,'geteuid',return_value=2000), patch.object(server.os,'getgid',return_value=2000), patch.object(server.os,'getegid',return_value=2000), patch.object(server.os,'getgroups',return_value=[2000]), patch.object(server.sys,'argv',['server']), patch.object(server,'protect_memory'), patch.object(server,'named_descriptors',return_value=descriptors), patch.object(server,'load_root_scope',return_value=({'generation':G},{})), patch.object(server,'in_generation_slice'), patch.object(server,'validate_listener'), patch.object(server,'validate_provider_descriptor'), patch.object(server,'RootGuard',Guard), patch.object(server,'LoopbackProvider') as provider, patch.object(server,'fence_directory') as fence:
            with self.assertRaises(Denied):server.main()
            provider.assert_not_called();fence.assert_not_called()

if __name__=='__main__':unittest.main()
