#!/usr/bin/env python3
"""Unregistered synthetic tool relay. Provider and executor are trusted service-side inputs."""
import json
import threading

MAX_FRAME = 65536

class Refused(Exception):
    pass

class ToolRelay:
    def __init__(self, execute):
        self._execute = execute
        self._pending = None
        self._used = set()
        self._lock = threading.Lock()

    def record_provider_call(self, tool_id, arguments):
        if (not isinstance(tool_id, str) or not 1 <= len(tool_id) <= 128
            or not tool_id.isascii() or not all(c.isalnum() or c in '_-' for c in tool_id)
            or not isinstance(arguments, dict) or set(arguments) != {'command'}
            or not isinstance(arguments['command'], str)
            or len(arguments['command'].encode()) > 16384):
            raise Refused('invalid provider tool call')
        with self._lock:
            if self._pending is not None or tool_id in self._used or len(self._used) >= 64:
                raise Refused('call unavailable')
            self._pending = (tool_id, arguments.copy())

    def call(self, tool_id, arguments):
        with self._lock:
            if self._pending != (tool_id, arguments) or tool_id in self._used:
                raise Refused('call unavailable')
            # Consume before external work: failures and disconnects are ambiguous.
            self._used.add(tool_id)
            self._pending = None
        try:
            response = self._execute(arguments)
            raw = json.dumps(response, separators=(',', ':'), ensure_ascii=False).encode()
            if len(raw) > MAX_FRAME or not valid_response(response):
                raise Refused('invalid executor response')
            return {'role': 'tool', 'tool_call_id': tool_id, 'content': raw.decode()}
        except Exception as exc:
            raise Refused('executor unavailable') from exc

def valid_response(value):
    if not isinstance(value, dict): return False
    if value.get('status') == 'refused':
        return set(value) == {'status','reason'} and value['reason'] in {'invalid_request','configuration_unavailable','policy_denied','execution_unavailable','timed_out','output_withheld'}
    return (set(value) == {'status','exit_code','stdout','stderr'} and value['status'] == 'executed'
            and type(value['exit_code']) is int and 0 <= value['exit_code'] <= 255
            and isinstance(value['stdout'], str) and isinstance(value['stderr'], str))
