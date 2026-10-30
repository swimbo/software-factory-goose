"""Strict writer-seal record validation; launcher provenance is a separate gate."""
import json
import os
import re
import stat
from nuc_relay_authority import Denied, _no_acl, _root_bytes
from nuc_relay_stream import no_duplicates


def load_writer_binding(fd,scope,task,dirfds):
    try:
        record=json.loads(_root_bytes(fd,65536),object_pairs_hook=no_duplicates)
        fields={'schema','purpose','generation','task_id','binding_sha256','boot_id',
                'writer_container_id','writer_image_sha256','writer_program_sha256',
                'cgroup_dev','cgroup_ino','input_dir','output_dir','candidate_dir','mounts_sha256'}
        if not isinstance(record,dict) or set(record)!=fields or type(record['schema']) is not int or record['schema']!=1 or record['purpose']!='nuc-fixed-file-writer-v1':raise Denied('writer binding unavailable')
        if (record['generation']!=scope['generation'] or record['task_id']!=scope['task_id']
                or record['binding_sha256']!=scope['grant_sha256'] or record['boot_id']!=task['boot_id']
                or type(record['cgroup_dev']) is not int or type(record['cgroup_ino']) is not int
                or (record['cgroup_dev'],record['cgroup_ino'])!=(task['cgroup_dev'],task['cgroup_ino'])):
            raise Denied('writer binding unavailable')
        for key in ('binding_sha256','writer_container_id','writer_image_sha256','writer_program_sha256','mounts_sha256'):
            if not isinstance(record[key],str) or not re.fullmatch(r'[0-9a-f]{64}',record[key]):raise Denied('writer binding unavailable')
        for key,owner in (('input_dir',0),('output_dir',2001),('candidate_dir',2001)):
            item=record[key];suffix=key.removesuffix('_dir')
            expected='/var/lib/software-factory-goose/handoff/'+record['generation']+'/'+suffix
            if (not isinstance(item,dict) or set(item)!={'path','dev','ino'} or item['path']!=expected
                    or type(item['dev']) is not int or type(item['ino']) is not int or item['dev']<=0 or item['ino']<=0):
                raise Denied('writer binding unavailable')
            st=os.fstat(dirfds[key])
            if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=owner or st.st_gid!=owner
                    or stat.S_IMODE(st.st_mode)!=0o755 or (st.st_dev,st.st_ino)!=(item['dev'],item['ino'])):
                raise Denied('writer binding unavailable')
            _no_acl(dirfds[key],True)
        return record
    except Denied:raise
    except Exception:raise Denied('writer binding unavailable') from None
