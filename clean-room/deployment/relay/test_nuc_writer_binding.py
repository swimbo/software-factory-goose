import json
import os
import pathlib
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import nuc_writer_binding as wb
from nuc_relay_authority import Denied
G='01ARZ3NDEKTSV4RRFFQ69G5FAV'
class Binding(unittest.TestCase):
    def test_exact_seal_and_inodes_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            fds={}
            for key in ('input_dir','output_dir','candidate_dir'):
                p=pathlib.Path(tmp)/key;p.mkdir(mode=0o755);fds[key]=os.open(p,os.O_RDONLY|os.O_DIRECTORY)
            scope={'generation':G,'task_id':'task','grant_sha256':'a'*64};task={'boot_id':'boot','cgroup_dev':1,'cgroup_ino':2}
            record={'schema':1,'purpose':'nuc-fixed-file-writer-v1','generation':G,'task_id':'task','binding_sha256':'a'*64,'boot_id':'boot','writer_container_id':'b'*64,'writer_image_sha256':'c'*64,'writer_program_sha256':'d'*64,'cgroup_dev':1,'cgroup_ino':2,'mounts_sha256':'e'*64}
            original=os.fstat
            for key,fd in fds.items():
                s=original(fd);record[key]={'path':'/var/lib/software-factory-goose/handoff/'+G+'/'+key.removesuffix('_dir'),'dev':s.st_dev,'ino':s.st_ino}
            def fake(fd):
                s=original(fd);owner=0 if fd==fds['input_dir'] else 2001
                return SimpleNamespace(st_mode=s.st_mode,st_uid=owner,st_gid=owner,st_dev=s.st_dev,st_ino=s.st_ino)
            try:
                with patch.object(wb.os,'fstat',side_effect=fake),patch.object(wb,'_root_bytes',return_value=json.dumps(record).encode()):
                    self.assertEqual(wb.load_writer_binding(0,scope,task,fds),record)
                for bad in [{**record,'binding_sha256':'f'*64},{**record,'input_dir':{**record['input_dir'],'path':'/tmp/unsafe'}},{**record,'candidate_dir':{**record['candidate_dir'],'ino':record['candidate_dir']['ino']+1}}]:
                    with patch.object(wb.os,'fstat',side_effect=fake),patch.object(wb,'_root_bytes',return_value=json.dumps(bad).encode()):
                        with self.assertRaises(Denied):wb.load_writer_binding(0,scope,task,fds)
            finally:
                for fd in fds.values():os.close(fd)

if __name__=='__main__':unittest.main()
