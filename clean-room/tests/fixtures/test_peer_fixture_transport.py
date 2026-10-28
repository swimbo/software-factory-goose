#!/usr/bin/env python3
"""Narrow test controls for early close on rejected Unix peers."""
import os
import threading
import types
import unittest
from unittest.mock import patch

import peer_catalog_gate_fixture as fixture


class WrongPeerTransportTests(unittest.TestCase):
    def server(self, observed=True):
        event=threading.Event()
        if observed:event.set()
        return types.SimpleNamespace(expected_uid=os.geteuid()+1,denied_uid=os.geteuid(),peer_denied=event)

    def test_early_disconnect_requires_observed_kernel_uid_mismatch(self):
        for error in (BrokenPipeError(),ConnectionResetError()):
            with patch.object(fixture,'invoke',side_effect=error):
                fixture.assert_wrong_peer_denied('/fixture',{},self.server())
        server=self.server()
        server.denied_uid=server.expected_uid
        with patch.object(fixture,'invoke',side_effect=BrokenPipeError()):
            with self.assertRaises(AssertionError):fixture.assert_wrong_peer_denied('/fixture',{},server)

    def test_success_or_unrelated_transport_errors_are_not_hidden(self):
        with patch.object(fixture,'invoke',return_value=(200,{})):
            with self.assertRaises(AssertionError):fixture.assert_wrong_peer_denied('/fixture',{},self.server())
        with patch.object(fixture,'invoke',side_effect=TimeoutError()):
            with self.assertRaises(TimeoutError):fixture.assert_wrong_peer_denied('/fixture',{},self.server())


if __name__=='__main__':unittest.main()
