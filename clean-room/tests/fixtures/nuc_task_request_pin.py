#!/usr/bin/env python3
"""Pin a task request while validating Goose's volatile turn context."""
import datetime,json,re,time
from trusted_tool_relay import Refused

class TaskRequestPin:
 def __init__(self,snapshot,prompt):
  if not isinstance(prompt,str) or not prompt or not isinstance(snapshot,dict):raise Refused('scope unavailable')
  self.snapshot=json.loads(json.dumps(snapshot));self.prompt=prompt
  self.pattern=re.compile(re.escape(prompt)+r'\n<turn-context>\n<current-time>([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \+00:00)</current-time>\n<working-directory>(/work/goose-relay-[a-z0-9_]+/work)</working-directory>\n</turn-context>')
  self._stable(snapshot,verify_clock=False)
 def _stable(self,body,verify_clock):
  if not isinstance(body,dict) or not isinstance(body.get('messages'),list) or len(body['messages'])!=2:raise Refused('initial unavailable')
  user=body['messages'][1]
  if not isinstance(user,dict) or set(user)!={'role','content'} or user['role']!='user' or not isinstance(user['content'],str):raise Refused('initial unavailable')
  match=self.pattern.fullmatch(user['content'])
  if not match:raise Refused('initial unavailable')
  try:ts=datetime.datetime.strptime(match.group(1),'%Y-%m-%d %H:%M:%S %z').timestamp()
  except ValueError:raise Refused('initial unavailable') from None
  if verify_clock and abs(time.time()-ts)>120:raise Refused('initial unavailable')
  return {**body,'messages':[body['messages'][0],{'role':'user','content':self.prompt}]}
 def __call__(self,body):
  return self._stable(body,True)==self._stable(self.snapshot,False)
