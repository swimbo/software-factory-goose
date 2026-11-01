import contextlib
import hashlib
import pathlib
import unittest
from unittest import mock

import nuc_registry_retirement_coordinator as retirement


class RetirementPlanTests(unittest.TestCase):
    def test_fences_cover_exact_old_units(self):
        self.assertEqual(len(retirement.UNITS), 19)
        self.assertEqual(len(set(retirement.UNITS)), 19)
        for unit in retirement.UNITS:
            marker, dropin = retirement.paths(unit)
            self.assertIn(retirement.T, marker.name)
            self.assertEqual(dropin.parent.name, unit + '.d')
            self.assertEqual(retirement.expected_dropin(unit),
                             ('[Unit]\nConditionPathExists=!' + str(marker) + '\n').encode())

    def test_snapshot_binds_dropin_contents(self):
        unit = retirement.SERVICES[0]
        path = str(retirement.old.UNIT / (unit + '.d') / 'existing.conf')
        props = {'LoadState':'loaded', 'Names':unit,
                 'FragmentPath':str(retirement.old.UNIT / unit), 'Job':'',
                 'DropInPaths':path}
        def read(p, mode):
            return b'unit' if p == retirement.old.UNIT / unit else b'dropin'
        with mock.patch.object(retirement, 'properties', return_value=props), mock.patch.object(retirement.old, 'read', side_effect=read):
            snapshot = retirement.observe(unit)
        self.assertEqual(snapshot['dropin_sha256'][path], hashlib.sha256(b'dropin').hexdigest())

    def test_socket_without_mainpid_is_terminal_but_service_is_not(self):
        socket=retirement.UNITS[0];service=retirement.SERVICES[0]
        def props(unit):return {'LoadState':'loaded','Names':unit,'FragmentPath':str(retirement.old.UNIT/unit),'ActiveState':'inactive','Job':''}
        with mock.patch.object(retirement,'properties',side_effect=props):
            self.assertEqual(retirement.terminal(socket,{}),props(socket))
            with self.assertRaisesRegex(RuntimeError,'terminal state'):retirement.terminal(service,{})

    def test_later_condition_reset_and_changed_dropin_are_refused(self):
        unit=retirement.SERVICES[0];marker,fence=retirement.paths(unit)
        later=str(retirement.old.UNIT/(unit+'.d')/'99-later.conf');before={'dropin_sha256':{later:hashlib.sha256(b'unchanged').hexdigest()}}
        expected={**before['dropin_sha256'],str(fence):hashlib.sha256(retirement.expected_dropin(unit)).hexdigest()}
        with mock.patch.object(retirement,'observe',return_value={'dropin_sha256':expected}),mock.patch.object(retirement.old,'read',return_value=b'[Unit]\nConditionPathExists=\n'):
            with self.assertRaisesRegex(RuntimeError,'later condition override'):retirement.verify_loaded_fence(unit,before)
        with mock.patch.object(retirement,'observe',return_value={'dropin_sha256':{}}):
            with self.assertRaisesRegex(RuntimeError,'drop-ins changed'):retirement.verify_loaded_fence(unit,before)

    def test_rejects_outside_or_duplicate_dropins(self):
        unit = retirement.SERVICES[0]
        props = {'LoadState':'loaded', 'Names':unit,
                 'FragmentPath':str(retirement.old.UNIT / unit), 'Job':''}
        for paths in ('/tmp/foreign.conf', str(retirement.old.UNIT / 'same') + ' ' + str(retirement.old.UNIT / 'same')):
            with self.subTest(paths=paths), mock.patch.object(retirement, 'properties', return_value={**props, 'DropInPaths':paths}), mock.patch.object(retirement.old, 'read', return_value=b'x'):
                with self.assertRaises(RuntimeError):
                    retirement.observe(unit)

class RetirementApplyTests(unittest.TestCase):
    def test_stop_failure_keeps_transition_and_does_not_publish_success(self):
        events=[]
        @contextlib.contextmanager
        def gate(*args):
            events.append('lock');yield 12
        @contextlib.contextmanager
        def transition(fd,intent):
            events.append('durable-transition');yield fd
        reviewed={'old_manifest_sha256':'a'*64,'new_manifest_sha256':'b'*64,
                  'units':{u:{} for u in retirement.UNITS},'preservation':{'external':{}}}
        def store(path,data,mode): events.append(('store',path))
        def ctl(*args):
            events.append(('ctl',args))
            if args[0]=='stop':raise RuntimeError('uncertain stop')
        with mock.patch.object(retirement.gate,'_trusted_ancestors'), mock.patch.object(retirement.gate,'_gate',gate), mock.patch.object(retirement.gate,'_transition_already_locked',transition), mock.patch.object(retirement,'plan_locked',return_value=reviewed), mock.patch.object(retirement.old,'store',side_effect=store), mock.patch.object(retirement.old,'directory'), mock.patch.object(retirement.old,'read'), mock.patch.object(retirement.old,'ctl',side_effect=ctl), mock.patch.object(retirement.os.path,'lexists',return_value=True), mock.patch.object(retirement,'assert_original'), mock.patch.object(retirement,'verify_loaded_fence'), mock.patch.object(retirement.external,'collect_with_transport',return_value=({}, {'id':'fixture'})):
            with self.assertRaisesRegex(RuntimeError,'uncertain stop'):retirement.apply(reviewed)
        self.assertLess(events.index('durable-transition'),events.index(('store',retirement.START)))
        self.assertFalse(any(e==('store',retirement.DONE) for e in events))
        self.assertEqual(sum(isinstance(e,tuple) and e[0]=='ctl' and e[1][0]=='stop' for e in events),1)

if __name__ == '__main__':
    unittest.main()
