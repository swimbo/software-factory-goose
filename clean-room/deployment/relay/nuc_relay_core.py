"""Unregistered relay core; caller must provide root-verified liveness and transports.

This module is not an executable or socket server. No production adapter exists yet.
"""
import base64
import json
import threading
from nuc_relay_authority import Denied, load_root_scope, require_worker_peer, validate_writer_arguments, verify_request
from nuc_relay_stream import parse, no_duplicates


def _encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

class RelayCore:
    def __init__(self, scope_fd, consumed_fd, catalog_fd, binding_fd, fence, guard, transport, writer):
        self.scope, _ = load_root_scope(scope_fd, consumed_fd, catalog_fd, binding_fd)
        if not all(callable(fn) for fn in (guard, transport, writer)):
            raise Denied('runtime adapter unavailable')
        self.fence, self.guard, self.transport, self.writer = fence, guard, transport, writer
        self.phase = 'initial'
        self.observations = []
        self.lock = threading.Lock()

    def _check_open(self):
        if self.guard(self.scope) is not True:
            raise Denied('runtime authority unavailable')

    def call(self, conn, request):
        require_worker_peer(conn)
        with self.lock:
            try:
                if not isinstance(request, dict):
                    raise Denied('invalid request')
                if request.get('type') == 'inference' and set(request) == {'type', 'body'}:
                    return self._inference(request['body'])
                if request.get('type') == 'tool' and set(request) == {'type', 'arguments'}:
                    return self._tool(request['arguments'])
                raise Denied('invalid request')
            except Denied:
                raise
            except Exception:
                raise Denied('runtime unavailable') from None

    def _inference(self, body):
        if not isinstance(body, dict):
            raise Denied('invalid request')
        raw = _encode(body)
        if self.phase == 'initial':
            self.initial = verify_request(self.scope, raw)
            turn = 0
        elif self.phase == 'continuation':
            expected = dict(self.initial)
            expected['messages'] = self.initial['messages'] + [self.assistant, self.tool_response]
            candidate = json.loads(raw, object_pairs_hook=no_duplicates)
            try:
                argument_text = candidate['messages'][2]['tool_calls'][0]['function']['arguments']
                if json.loads(argument_text, object_pairs_hook=no_duplicates) != self.arguments:
                    raise Denied('continuation unavailable')
                candidate['messages'][2]['tool_calls'][0]['function']['arguments'] = self.assistant['tool_calls'][0]['function']['arguments']
            except (KeyError, IndexError, TypeError, ValueError):
                raise Denied('continuation unavailable') from None
            if json.dumps(candidate, sort_keys=True, separators=(',', ':')) != json.dumps(expected, sort_keys=True, separators=(',', ':')):
                raise Denied('continuation unavailable')
            turn = 1
        else:
            raise Denied('inference unavailable')
        routed = dict(body)
        routed['model'] = 'auto'
        self._check_open()
        import hashlib
        self.fence.begin(self.scope['generation'], 'inference' + str(turn), hashlib.sha256(_encode(routed)).hexdigest())
        self.phase = 'unknown'
        data = self.transport(routed)
        self._check_open()
        result = parse(data, frozenset(self.scope['allowed_models']))
        self.observations.append({'turn':turn,'model':result['model'],'response_sha256':hashlib.sha256(data).hexdigest(),'usage':result['usage']})
        if turn == 0:
            if result['kind'] != 'tool':
                raise Denied('writer unavailable')
            self.arguments = result['arguments']
            self.tool_id = result['id']
            self.assistant = {'role':'assistant','content':None,'tool_calls':[{'id':self.tool_id,'type':'function','function':{'name':'factory__write_files','arguments':result['arguments_text']}}]}
            if 'reasoning_content' in result:
                self.assistant['reasoning_content'] = result['reasoning_content']
            self.phase = 'tool'
        else:
            if result['kind'] != 'final':
                raise Denied('final unavailable')
            self.phase = 'done'
        return base64.b64encode(data).decode('ascii')

    def _tool(self, arguments):
        if self.phase != 'tool' or arguments != self.arguments:
            raise Denied('writer unavailable')
        raw = _encode(arguments)
        validate_writer_arguments(raw)
        self._check_open()
        import hashlib
        self.fence.begin(self.scope['generation'], 'writer', hashlib.sha256(raw).hexdigest())
        self.phase = 'unknown'
        result = self.writer(arguments)
        self._check_open()
        if _encode(result) != _encode({'status':'executed','exit_code':0,'stdout':'Both task files written.','stderr':''}):
            raise Denied('writer unavailable')
        self.tool_response = {'role':'tool','tool_call_id':self.tool_id,'content':_encode(result).decode('utf-8')}
        self.phase = 'continuation'
        return self.tool_response['content']
