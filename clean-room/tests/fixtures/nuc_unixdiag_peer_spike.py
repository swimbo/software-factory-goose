#!/usr/bin/python3
"""Synthetic same-UID Unix diagnostic peer proof; no external socket access."""
import ctypes,json,os,pathlib,re,socket,struct,sys,tempfile

def require(v,m):
 if not v:raise RuntimeError(m)
def dumpable(value):require(ctypes.CDLL(None,use_errno=True).prctl(4,value,0,0,0)==0,'dumpable change unavailable')
def diag():
 # linux/sock_diag.h and linux/unix_diag.h: AF_UNIX, dump all states, SHOW_PEER.
 seq=0x53464143;request=struct.pack('=IHHII',40,20,0x301,seq,0)+struct.pack('=BBHIIIII',socket.AF_UNIX,0,0,0xffffffff,0,5,0xffffffff,0xffffffff)
 result={};total=0
 with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,4) as s:
  s.settimeout(3);s.bind((0,0));s.send(request)
  while True:
   raw,_,flags,sender=s.recvmsg(65536);require(sender[0]==0,'non-kernel diagnostic sender');require(not flags&socket.MSG_TRUNC,'diagnostic truncation');total+=len(raw);require(total<=4*1024*1024,'diagnostic bound exceeded');pos=0
   while pos<len(raw):
    require(len(raw)-pos>=16,'netlink header unavailable');length,kind,flags,number,_=struct.unpack_from('=IHHII',raw,pos);require(length>=16 and pos+length<=len(raw) and number==seq and not flags&0x10,'netlink message invalid');payload=raw[pos+16:pos+length]
    if kind==3:return result
    require(kind!=2 and kind==20 and len(payload)>=16,'diagnostic failed')
    family,_,_,_,inode,_,_=struct.unpack_from('=BBBBIII',payload);require(family==socket.AF_UNIX and inode not in result,'diagnostic identity invalid');peer=None;name=None;offset=16
    while offset<len(payload):
     require(len(payload)-offset>=4,'attribute unavailable');alen,atype=struct.unpack_from('=HH',payload,offset);require(alen>=4 and offset+alen<=len(payload),'attribute invalid')
     if atype==0:
      require(name is None,'duplicate socket name');name=payload[offset+4:offset+alen].rstrip(b'\x00')
     if atype==2:
      require(alen==8 and peer is None,'peer unavailable');peer=struct.unpack_from('=I',payload,offset+4)[0]
     offset+=(alen+3)&~3
    require(offset==len(payload),'attribute padding invalid');result[inode]=(peer,name);pos+=(length+3)&~3
   require(pos==len(raw),'netlink padding invalid')
def main():
 require(len(sys.argv)==1 and (os.getuid(),os.geteuid(),os.getgid(),os.getegid())==(2000,)*4,'identity unavailable')
 status=dict(x.split(':',1) for x in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in x);require(status.get('NoNewPrivs','').strip()=='1' and all(status.get('Cap'+n,'').strip()=='0000000000000000' for n in ('Inh','Prm','Eff','Bnd','Amb')),'privileges unavailable');dumpable(0)
 with tempfile.TemporaryDirectory(prefix='sfactory-unixdiag-') as tmp:
  listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(tmp+'/sock');listener.listen(1);listener.settimeout(3)
  client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);client.connect(tmp+'/sock');accepted,_=listener.accept();r,w=os.pipe();pid=os.fork()
  if pid==0:
   try:
    os.close(r);listener.close();accepted.close();dumpable(1);os.write(w,str(client.fileno()).encode()+b'\n');os.close(w);client.recv(1);client.close();os._exit(0)
   except BaseException:os._exit(1)
  os.close(w);client.close()
  try:
   fdnum=os.read(r,32);require(re.fullmatch(rb'[0-9]+\n',fdnum),'child FD unavailable');link=os.readlink('/proc/'+str(pid)+'/fd/'+fdnum.decode().strip());m=re.fullmatch(r'socket:\[([0-9]+)\]',link);require(m is not None,'child socket unavailable');client_ino=int(m.group(1))
   link=os.readlink('/proc/self/fd/'+str(accepted.fileno()));m=re.fullmatch(r'socket:\[([0-9]+)\]',link);require(m is not None,'peer socket unavailable');peer_ino=int(m.group(1));mapping=diag();require(client_ino!=peer_ino and mapping.get(client_ino,(None,None))[0]==peer_ino and mapping.get(peer_ino,(None,None))==(client_ino,os.fsencode(tmp+'/sock')),'peer relation unavailable')
   print(json.dumps({'schema':1,'synthetic_inherited_connected_fd_detected':True,'bidirectional_peer_match':True,'raw_inodes_exposed':False},sort_keys=True,separators=(',',':')),flush=True)
  finally:
   os.close(r);accepted.close();listener.close();_,state=os.waitpid(pid,0);require(os.waitstatus_to_exitcode(state)==0,'child teardown unavailable')
if __name__=='__main__':
 try:main()
 except Exception:print('unixdiag peer spike unavailable',file=sys.stderr);raise SystemExit(1)
