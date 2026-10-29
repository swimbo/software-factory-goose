"""Private bounded metadata-only trace for a single fixture transport."""
import json,os,stat

class TransportTrace:
 def __init__(self,root):
  fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:
   st=os.fstat(fd)
   if st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700:raise RuntimeError('trace root unavailable')
   self.fd=os.open('transport-trace.jsonl',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd);os.fsync(fd)
  finally:os.close(fd)
  self.count=0
 def __call__(self,value):
  if self.count>=8:raise RuntimeError('trace event limit')
  fields={'wire_bytes','framing_complete','version','status','content_type','content_length','transfer_encoding','event','child_exit'}
  allowed={'framing_complete_before_close','child_exit','parse_failed','parse_ok','failure_spawn','failure_setup','failure_write','failure_read','failure_deadline','failure_response_limit','failure_child_exit','failure_post_identity','failure_framing_invalid'}
  if not isinstance(value,dict) or set(value)!=fields or value['event'] not in allowed or value['version'] not in ('1.0','1.1','other','unavailable') or value['content_type'] not in ('text/event-stream','application/json','text/plain','other','unavailable') or value['transfer_encoding'] not in ('','chunked','other','unavailable') or not isinstance(value['wire_bytes'],int) or not 0<=value['wire_bytes']<=2**31 or type(value['framing_complete']) is not bool or (value['status'] is not None and (type(value['status']) is not int or not 100<=value['status']<=599)) or (value['content_length'] is not None and (type(value['content_length']) is not int or not 0<=value['content_length']<=9999999999)) or (value['child_exit'] is not None and (type(value['child_exit']) is not int or not -255<=value['child_exit']<=255)):raise RuntimeError('invalid trace event')
  raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();written=os.write(self.fd,raw)
  if written!=len(raw):raise RuntimeError('trace write incomplete')
  os.fsync(self.fd);self.count+=1
 def close(self):os.close(self.fd)
