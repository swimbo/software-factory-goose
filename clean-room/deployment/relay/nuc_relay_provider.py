"""Unregistered loopback provider transport candidate for a pinned network namespace.

The root launch adapter must attest the Docker and namespace identity and bind the
scope. This module never starts a service or selects any caller-provided endpoint.
"""
import http.client
import json
import os
from nuc_relay_authority import Denied
from nuc_relay_systemd import validate_provider_descriptor

MAX_REQUEST = 65536
MAX_RESPONSE = 8 * 1024 * 1024


def check_namespace(scope):
    try:
        st = os.stat('/proc/self/ns/net')
        if (type(scope['network_device']) is not int or type(scope['network_inode']) is not int
                or (st.st_dev, st.st_ino) != (scope['network_device'], scope['network_inode'])):
            raise Denied('network identity unavailable')
    except (OSError, KeyError, TypeError):
        raise Denied('network identity unavailable') from None


class LoopbackProvider:
    def __init__(self, scope, credential_fd):
        validate_provider_descriptor(credential_fd)
        check_namespace(scope)
        self.scope = scope
        self.credential_fd = os.dup(credential_fd)

    def send(self, body):
        if not isinstance(body, dict) or body.get('model') != 'auto':
            raise Denied('provider request unavailable')
        try:
            data = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
            if not 0 < len(data) <= MAX_REQUEST:
                raise Denied('provider request unavailable')
            check_namespace(self.scope)
            validate_provider_descriptor(self.credential_fd)
            credential = os.pread(self.credential_fd, 4097, 0).strip()
            if (not 0 < len(credential) <= 4096 or any(c < 33 or c > 126 for c in credential)
                    or credential in data):
                raise Denied('provider credential unavailable')
            # Direct connection in the root-pinned namespace: no proxy, redirects or caller URL.
            conn = http.client.HTTPConnection('127.0.0.1', 8080, timeout=65)
            try:
                conn.request('POST', '/v1/chat/completions', body=data,
                             headers={'Content-Type':'application/json', 'Accept':'text/event-stream',
                                      'Connection':'close', 'x-bf-vk':credential.decode('ascii')})
                response = conn.getresponse()
                lengths = response.headers.get_all('Content-Length', [])
                transfers = response.headers.get_all('Transfer-Encoding', [])
                encodings = response.headers.get_all('Content-Encoding', [])
                if (response.status != 200 or response.headers.get_content_type() != 'text/event-stream'
                        or len(lengths) > 1 or len(transfers) > 1 or len(encodings) > 1
                        or lengths and transfers or encodings and encodings[0].lower() != 'identity'):
                    raise Denied('provider response unavailable')
                if transfers:
                    if transfers[0].strip().lower() != 'chunked':
                        raise Denied('provider response unavailable')
                elif lengths:
                    if not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 10:
                        raise Denied('provider response unavailable')
                    if int(lengths[0]) > MAX_RESPONSE:
                        raise Denied('provider response unavailable')
                else:
                    raise Denied('provider framing unavailable')
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE or (lengths and len(raw) != int(lengths[0])) or credential in raw:
                    raise Denied('provider response unavailable')
            finally:
                conn.close()
            check_namespace(self.scope)
            return raw
        except Denied:
            raise
        except Exception:
            # Errors never contain URL, headers, credential, body or upstream response.
            raise Denied('provider outcome unknown') from None
