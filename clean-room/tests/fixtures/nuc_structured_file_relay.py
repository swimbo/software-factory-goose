#!/usr/bin/env python3
"""Synthetic file tool binding; trusted in-process service records provider calls."""
import json,threading
from trusted_tool_relay import Refused,valid_response
from nuc_file_contract import valid,canonical_arguments,MAX_FILE_BYTES

WRITE_TOOL={'type':'function','function':{'name':'factory__write_files','description':'Write the two authorized task files without executing code.','parameters':{'type':'object','properties':{'files':{'type':'object','properties':{'hello.py':{'type':'string','maxLength':MAX_FILE_BYTES},'test_hello.py':{'type':'string','maxLength':MAX_FILE_BYTES}},'required':['hello.py','test_hello.py'],'additionalProperties':False}},'required':['files'],'additionalProperties':False}}}

class FileRelay:
 def __init__(self,execute):self.execute=execute;self.pending=None;self.used=set();self.lock=threading.Lock()
 def record_provider_call(self,tool_id,arguments):
  if not isinstance(tool_id,str) or not 1<=len(tool_id)<=128 or not tool_id.isascii() or not all(c.isalnum() or c in '_-' for c in tool_id) or not valid(arguments):raise Refused('invalid provider call')
  with self.lock:
   if self.pending is not None or tool_id in self.used or len(self.used)>=64:raise Refused('call unavailable')
   self.pending=(tool_id,json.loads(json.dumps(arguments)))
 def call(self,tool_id,arguments):
  with self.lock:
   if self.pending!=(tool_id,arguments) or tool_id in self.used:raise Refused('call unavailable')
   self.used.add(tool_id);self.pending=None
  try:
   canonical_arguments(arguments)
   result=self.execute(arguments)
   raw=json.dumps(result,separators=(',',':'),ensure_ascii=False).encode()
   if len(raw)>65536 or not valid_response(result):raise Refused('invalid result')
   return {'role':'tool','tool_call_id':tool_id,'content':raw.decode()}
  except Exception as error:raise Refused('executor unavailable') from error
