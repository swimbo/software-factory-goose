"""Pure classifier for a complete independently observed Linux socket inventory.

 Caller must authenticate the process and namespace, collect bounded kernel-only
 observations, prevent races and prove the admin pathname belongs to the pinned
 server. This classifier alone confers no authority.
"""
ADMIN=b'/var/lib/software-factory-goose/journal/restate/sfgoose-private/admin.sock'
def require(v,m):
 if not v:raise ValueError(m)
def classify(fd_sockets,unix,other,admin=ADMIN):
 require(isinstance(fd_sockets,set) and len(fd_sockets)<=1024 and isinstance(unix,dict) and len(unix)<=65536 and isinstance(other,set) and len(other)<=65536 and isinstance(admin,bytes) and admin,'inventory unavailable')
 require(all(type(n) is int and n>0 for n in fd_sockets|other) and all(type(n) is int and n>0 for n in unix),'invalid inode')
 named=set()
 for inode,item in unix.items():
  require(isinstance(item,dict) and set(item)=={'type','state','peer','name'} and type(item['type']) is int and type(item['state']) is int and (item['peer'] is None or (type(item['peer']) is int and item['peer']>0)) and (item['name'] is None or isinstance(item['name'],bytes)),'Unix socket invalid')
  if item['name']==admin:named.add(inode)
 require(named,'admin socket mapping unavailable')
 require(not set(unix).intersection(other),'ambiguous socket inventory')
 for inode in fd_sockets:
  require(inode in unix or inode in other,'unclassified socket FD')
  if inode not in unix:continue
  item=unix[inode];peer=item['peer']
  require(inode not in named,'admin socket held')
  if item['type']==1 and item['state']==1:require(peer is not None,'connected Unix peer unavailable')
  if peer is not None:
   require(peer in unix and unix[peer]['peer']==inode,'Unix peer graph incomplete')
   require(peer not in named,'connected admin socket held')
 return {'all_socket_fds_classified':True,'admin_socket_absent':True}
