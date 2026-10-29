#!/usr/bin/env python3
"""Strict bounded OpenAI SSE collector for a single service-owned tool call."""
import json
from trusted_tool_relay import Refused
from nuc_stream_contract import RAW_SSE_BYTES
LIMIT=RAW_SSE_BYTES

def no_duplicates(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise Refused('duplicate JSON key')
  result[key]=value
 return result

def parse(raw, allowed_models, tool_name="factory__shell"):
 if tool_name not in ("factory__shell","factory__write_files"):raise Refused("invalid tool scope")
 if not isinstance(raw,bytes) or not 0<len(raw)<=LIMIT:raise Refused('invalid stream')
 try:text=raw.decode('utf-8').replace('\r\n','\n')
 except UnicodeDecodeError:raise Refused('invalid stream') from None
 if not text.endswith('\n\n'):raise Refused('incomplete stream')
 events=text[:-2].split('\n\n');done=False;finish=None;tool=None;content='';response_id=None;model=None;reasoning_size=0;reasoning_fields=set();reasoning_content_parts=[];comment_bytes=0
 if not isinstance(allowed_models,(set,frozenset)) or not allowed_models:raise Refused('route unavailable')
 for event in events:
  data=None
  for line in event.split('\n'):
   if line.startswith(':'):
    size=len(line.encode('utf-8'));comment_bytes+=size
    if size>8192 or comment_bytes>65536:raise Refused('invalid event')
   elif line.startswith('data: ') and data is None:data=line[6:]
   else:raise Refused('invalid event')
  if data is None:
   if done:raise Refused('invalid completion')
   continue
  if data=='[DONE]':
   if done or event!=events[-1]:raise Refused('invalid completion')
   done=True;continue
  if done:raise Refused('invalid completion')
  try:v=json.loads(data,object_pairs_hook=no_duplicates)
  except (ValueError,TypeError):raise Refused('invalid event') from None
  if not isinstance(v,dict) or v.get('object')!='chat.completion.chunk':raise Refused('invalid event')
  choices=v.get('choices')
  if not isinstance(choices,list) or len(choices)>1:raise Refused('invalid choices')
  if not choices:continue
  response=v.get('id');served=v.get('model')
  if not isinstance(response,str) or not response or len(response)>256 or not isinstance(served,str) or served not in allowed_models:raise Refused('unreviewed response identity')
  if response_id is None:response_id=response;model=served
  if response_id!=response or model!=served:raise Refused('changed response identity')
  choice=choices[0]
  if not isinstance(choice,dict) or choice.get('index')!=0 or not isinstance(choice.get('delta'),dict):raise Refused('invalid choice')
  delta=choice['delta'];reason=choice.get('finish_reason')
  if finish is not None and (delta or reason is not None):raise Refused('event after finish')
  if reason is not None:
   if reason not in ('tool_calls','stop') or finish is not None:raise Refused('invalid finish')
   finish=reason
  if set(delta)-{'role','content','tool_calls','reasoning','reasoning_content','reasoning_details'}:raise Refused('unsupported delta')
  if delta.get('role','assistant') not in ('assistant',None):raise Refused('invalid role')
  for field in ('reasoning','reasoning_content'):
   if field in delta and delta[field] is not None:
    if not isinstance(delta[field],str):raise Refused('invalid reasoning')
    reasoning_fields.add(field);reasoning_size+=len(delta[field].encode())
    if reasoning_size>262144:raise Refused('reasoning too large')
  selected=delta.get('reasoning_content') or delta.get('reasoning')
  if isinstance(selected,str) and selected:reasoning_content_parts.append(selected)
  if 'reasoning_details' in delta:
   details=delta['reasoning_details']
   if not isinstance(details,list) or len(details)>1:raise Refused('invalid reasoning details')
   for item in details:
    if not isinstance(item,dict) or set(item)!={'index','type','text'} or type(item['index']) is not int or item['index']!=0 or item['type']!='reasoning.text' or not isinstance(item['text'],str):raise Refused('invalid reasoning details')
    try:reasoning_size+=len(item['text'].encode('utf-8'))
    except UnicodeError:raise Refused('invalid reasoning details') from None
    reasoning_fields.add('reasoning_details')
    if reasoning_size>262144:raise Refused('reasoning too large')
  if delta.get('content') is not None:
   if not isinstance(delta['content'],str):raise Refused('invalid content')
   content+=delta['content']
  if 'tool_calls' in delta:
   calls=delta['tool_calls']
   if calls is None or calls==[]:continue
   if not isinstance(calls,list) or len(calls)!=1 or not isinstance(calls[0],dict):raise Refused('unsupported tools')
   part=calls[0]
   if set(part)-{'index','id','type','function'} or part.get('index')!=0:raise Refused('invalid tool')
   if tool is None:tool={'id':None,'name':'','arguments':''}
   if part.get('id') is not None:
    if not isinstance(part['id'],str) or (tool['id'] is not None and tool['id']!=part['id']):raise Refused('invalid tool ID')
    tool['id']=part['id']
   if part.get('type') not in (None,'function'):raise Refused('invalid tool type')
   fn=part.get('function',{})
   if not isinstance(fn,dict) or set(fn)-{'name','arguments'}:raise Refused('invalid function')
   for field in ('name','arguments'):
    if field in fn:
     if not isinstance(fn[field],str):raise Refused('invalid function')
     if field!='name' or fn[field]!=tool[field]:tool[field]+=fn[field]
 if not done or finish is None:raise Refused('incomplete stream')
 if finish=='stop':
  if tool is not None:raise Refused('invalid finish')
  return {'kind':'final','content':content,'model':model,'reasoning_fields':sorted(reasoning_fields),'reasoning_bytes':reasoning_size}
 if content or tool is None or tool['name']!=tool_name or not isinstance(tool['id'],str):raise Refused('invalid tool call')
 try:args=json.loads(tool['arguments'],object_pairs_hook=no_duplicates)
 except (ValueError,TypeError):raise Refused('invalid arguments') from None
 if not isinstance(args,dict):raise Refused('invalid arguments')
 result={'kind':'tool','id':tool['id'],'arguments':args,'arguments_text':tool['arguments'],'model':model,'reasoning_fields':sorted(reasoning_fields),'reasoning_bytes':reasoning_size}
 if reasoning_content_parts:result['reasoning_content']=''.join(reasoning_content_parts)
 return result
