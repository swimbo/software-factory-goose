#!/usr/bin/env python3
"""Explicitly invoked NUC task transport; no worker access or default activation."""
import errno,os,stat,sys

MAX_REQUEST=65536
from nuc_stream_contract import RAW_SSE_BYTES
MAX_RESPONSE=RAW_SSE_BYTES
CREDENTIAL='/home/bo/.hermes/bifrost/factory-secrets/software-factory-goose/credential'

class TransportRefused(Exception):pass

def _no_acl(fd, directory):
 if sys.platform!='linux':return  # Local fixture tests only; production candidate is Linux.
 for name in (('system.posix_acl_access','system.posix_acl_default') if directory else ('system.posix_acl_access',)):
  try:os.getxattr(fd,name)
  except OSError as e:
   if e.errno==errno.ENODATA:continue
   raise TransportRefused('credential unavailable') from None
  raise TransportRefused('credential unavailable')

def _open_anchored(path):
 if not os.path.isabs(path):raise TransportRefused('credential unavailable')
 parts=path.split('/')[1:]
 if not parts or any(p in ('','.','..') for p in parts):raise TransportRefused('credential unavailable')
 directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);private=False
 try:
  for i,part in enumerate(parts):
   is_dir=i<len(parts)-1
   flags=os.O_RDONLY|os.O_NOFOLLOW|(os.O_DIRECTORY if is_dir else os.O_NONBLOCK)
   child=os.open(part,flags,dir_fd=directory)
   try:
    st=os.fstat(child)
    if is_dir:
     if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,os.getuid()):raise TransportRefused('credential unavailable')
     _no_acl(child,True)
     if not private and st.st_mode & 0o022:raise TransportRefused('credential unavailable')
     if st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700:private=True
     os.close(directory);directory=child;child=-1
    else:
     if not private or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_nlink!=1:raise TransportRefused('credential unavailable')
     _no_acl(child,False)
     value=os.read(child,4097)
     if not 0<len(value)<=4096:raise TransportRefused('credential unavailable')
     value=value.strip()
     if not value or any(c<33 or c>126 for c in value):raise TransportRefused('credential unavailable')
     return value.decode('ascii')
   finally:
    if child>=0:os.close(child)
 finally:os.close(directory)
 raise TransportRefused('credential unavailable')

class BifrostTransport:
 def __init__(self,credential_path=CREDENTIAL):
  # Descriptor-anchored Linux read; the credential never enters worker state.
  try:self._credential=_open_anchored(credential_path)
  except OSError:raise TransportRefused('credential unavailable') from None
 def send(self,body):
  # Published host TCP port has no authenticated peer; use the separately reviewed pinned path.
  raise TransportRefused('unverified provider endpoint')
