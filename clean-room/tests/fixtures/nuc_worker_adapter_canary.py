#!/usr/bin/env python3
"""Offline socket peer for the exact production adapter image; no provider."""
import base64,importlib.util,json,pathlib,socket,subprocess,threading
spec=importlib.util.spec_from_file_location('offline','/canary.py');offline=importlib.util.module_from_spec(spec);spec.loader.exec_module(offline)

def main():
 listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind('/gate/relay.sock');listener.listen(4);listener.settimeout(170)
 seen=[];errors=[]
 def serve():
  try:
   for kind in ('inference','tool','inference'):
    conn,_=listener.accept()
    with conn:
     conn.settimeout(15);data=bytearray()
     while not data.endswith(b'\n') and len(data)<=65536:
      raw=conn.recv(4096)
      if not raw:break
      data.extend(raw)
     q=json.loads(data);assert q['type']==kind;seen.append(q)
     if len(seen)==1:
      call={'id':'offline-production-adapter','type':'function','function':{'name':'factory__write_files','arguments':json.dumps(offline.ARGS,separators=(',',':'))}}
      value=base64.b64encode(offline.sse({'role':'assistant','tool_calls':[{'index':0,**call}]},'tool_calls')).decode()
     elif len(seen)==2:
      assert q=={'type':'tool','arguments':offline.ARGS};value='{"status":"executed","exit_code":0,"stdout":"Both task files written.","stderr":""}'
     else:
      assert len(q['body']['messages'])==4
      value=base64.b64encode(offline.sse({'role':'assistant','content':'OFFLINE_FACTORY_DONE'},'stop')).decode()
     conn.sendall(json.dumps({'ok':True,'value':value}).encode())
  except Exception as exc:errors.append(type(exc).__name__)
 thread=threading.Thread(target=serve,daemon=True);thread.start()
 p=subprocess.run(['/usr/local/bin/python3','-I','-B','/factory/nuc_goose_worker.py'],capture_output=True,timeout=165)
 thread.join(timeout=3);listener.close()
 assert p.returncode==0 and not errors and not thread.is_alive() and len(seen)==3, 'adapter failed: '+p.stderr[-1000:].decode(errors='replace')
 assert json.loads(p.stdout)=={'goose_exit':0}
 print(json.dumps({'offline_only':True,'exact_adapter':True,'requests':seen,'inference_requests':2,'tool_calls':1},sort_keys=True))

if __name__=='__main__':main()
