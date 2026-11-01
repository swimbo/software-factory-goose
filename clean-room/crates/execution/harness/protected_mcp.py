#!/usr/bin/env python3
"""Fixed loopback client for a protected attempt broker. No provider credentials."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
from factory_harness import canonical
from harness_mcp import serve


class Client:
    def __init__(self, port, declarations_sha256, token):
        if not 1024 <= port <= 65535 or len(token) != 64:
            raise ValueError("attempt transport unavailable")
        self.port, self.digest, self.token = port, declarations_sha256, token
        self.cancelled = threading.Event()

    def request(self, operation, value):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=35)
        try:
            body = canonical(value).encode()
            if len(body) > 65536:
                raise ValueError("attempt request overflow")
            connection.request(
                "POST",
                "/factory/" + operation,
                body=body,
                headers={
                    "Authorization": "Bearer " + self.token,
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            lengths = response.headers.get_all("Content-Length", [])
            if (
                response.status != 200
                or len(lengths) != 1
                or response.headers.get("Transfer-Encoding") is not None
                or response.headers.get("Content-Encoding") not in (None, "identity")
                or not lengths[0].isascii()
                or not lengths[0].isdecimal()
                or not 0 < int(lengths[0]) <= 65536
            ):
                raise ValueError("attempt response unavailable")
            raw = response.read(65537)
            if len(raw) != int(lengths[0]):
                raise ValueError("attempt response unavailable")
            return json.loads(raw)
        finally:
            connection.close()

    def declarations(self):
        value = self.request("list", {})
        if hashlib.sha256(canonical(value).encode()).hexdigest() != self.digest:
            raise ValueError("attempt declarations changed")
        return value

    def call(self, name, arguments):
        return self.request("call", {"name": name, "arguments": arguments})

    def cancel_remote(self):
        self.request("cancel", {})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker-port", type=int, required=True)
    parser.add_argument("--declarations-sha256", required=True)
    args = parser.parse_args()
    serve(
        Client(
            args.broker_port,
            args.declarations_sha256,
            os.environ.pop("FACTORY_BROKER_TOKEN", ""),
        )
    )
