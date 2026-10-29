import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from nuc_factory_write_files import execute
from nuc_structured_file_relay import FileRelay
from nuc_file_contract import valid, canonical_arguments
from trusted_tool_relay import Refused


def request(first='a', second='b'):
    return {'files': {'hello.py': first, 'test_hello.py': second}}


class WriterAuthorityTests(unittest.TestCase):
    def test_file_byte_limits_and_aggregate_limit(self):
        self.assertTrue(valid(request('é' * 4096)))
        self.assertFalse(valid(request('é' * 4096 + 'x')))
        self.assertFalse(valid(request('a' * 8193)))
        self.assertFalse(valid(request('a' * 8192, 'b' * 8192)))
        baseline = len(canonical_arguments(request('a', 'b')))
        exact = request('a' * 8192, 'b' * (12288 - baseline - 8190))
        self.assertEqual(len(canonical_arguments(exact)), 12288)
        self.assertTrue(valid(exact))
        self.assertFalse(valid(request(exact['files']['hello.py'], exact['files']['test_hello.py'] + 'b')))
        # JSON escape expansion can overflow even when raw UTF-8 file bytes fit.
        self.assertFalse(valid(request('"' * 6140, 'b')))

    def test_invalid_names_unicode_and_shape_refused_before_effects(self):
        bad = [
            {'files': {'../hello.py': 'a', 'test_hello.py': 'b'}},
            {'files': {'hello.py': 'a', 'test_hello.py': 'b', 'extra': 'c'}},
            {'files': {'hello.py': '', 'test_hello.py': 'b'}},
            request('\x00', 'b'), request('\ud800', 'b'),
            {'files': {'hello.py': ['a'], 'test_hello.py': 'b'}},
        ]
        for item in bad:
            with self.subTest(item=ascii(item)), tempfile.TemporaryDirectory() as d:
                self.assertFalse(valid(item))
                self.assertEqual(execute(item, d)['status'], 'refused')
                self.assertEqual(os.listdir(d), [])

    def test_file_targets_cannot_replace_existing_or_follow_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            outside = root / 'outside'
            outside.write_text('unchanged')
            (root / 'hello.py').symlink_to(outside)
            self.assertEqual(execute(request(), d)['status'], 'refused')
            self.assertEqual(outside.read_text(), 'unchanged')
            self.assertFalse((root / 'test_hello.py').exists())

    def test_relay_binding_refuses_substitution_and_replay(self):
        calls = []
        relay = FileRelay(lambda args: calls.append(args) or {
            'status': 'executed', 'exit_code': 0, 'stdout': 'ok', 'stderr': ''})
        args = request('actual', 'test')
        relay.record_provider_call('provider-1', args)
        for call_id, values in [('provider-2', args), ('provider-1', request('changed', 'test'))]:
            with self.assertRaises(Refused):
                relay.call(call_id, values)
        relay.call('provider-1', args)
        with self.assertRaises(Refused):
            relay.call('provider-1', args)
        self.assertEqual(calls, [args])

    def test_failed_execution_is_not_replayed(self):
        calls = []
        def failed(args):
            calls.append(args)
            raise OSError('ambiguous effect')
        relay = FileRelay(failed)
        args = request()
        relay.record_provider_call('provider-1', args)
        with self.assertRaises(Refused):
            relay.call('provider-1', args)
        with self.assertRaises(Refused):
            relay.call('provider-1', args)
        self.assertEqual(len(calls), 1)

    def test_executor_stdin_rejects_duplicate_keys_and_frame_overflow(self):
        # Stub the side effect: observing 'invoked' proves parsing admitted input.
        script = ("import sys; import nuc_factory_write_files as w; "
                  "w.execute=lambda x:{'status':'invoked'}; "
                  "sys.argv=['writer','--tool-request']; raise SystemExit(w.main())")
        def invoke(raw):
            process = subprocess.run([sys.executable, '-c', script], input=raw,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     cwd=pathlib.Path(__file__).parent, check=True)
            return json.loads(process.stdout)
        good = b'{"files":{"hello.py":"a","test_hello.py":"b"}}'
        self.assertEqual(invoke(good)['status'], 'invoked')
        duplicate = b'{"files":{"hello.py":"a","hello.py":"b","test_hello.py":"c"}}'
        self.assertEqual(invoke(duplicate)['status'], 'refused')
        self.assertEqual(invoke(good + b' ' * 65536)['status'], 'refused')


if __name__ == '__main__':
    unittest.main()
