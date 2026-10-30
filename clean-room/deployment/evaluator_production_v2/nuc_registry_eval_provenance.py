"""Validate root reconciliation data before provisioning a production evaluator.

Caller must read all records from protected root-owned, no-follow descriptors.
This pure validator grants no authority and never accepts fixture catalogs.
"""
import hashlib,re
ID=re.compile(r'[0-7][0-9A-HJKMNP-TV-Z]{25}\Z')
HEX=re.compile(r'[0-9a-f]{64}\Z')
FILES=('hello.py','test_hello.py')
class InvalidProvenance(ValueError):pass

def validate(generation,receipt,manifest,writer,relay,files):
 def need(value):
  if not value:raise InvalidProvenance('reconciled generation unavailable')
 need(isinstance(generation,str) and ID.fullmatch(generation) is not None)
 need(isinstance(receipt,dict) and set(receipt)=={'schema','generation','binding_sha256','writer_id','goose_id','candidate_sha256','kernel_closed_frozen_empty','exact_ids_removed','slice_retained_frozen','engine_reconciled_for_exact_ids'} and type(receipt.get('schema')) is int and receipt.get('schema')==1 and receipt.get('generation')==generation and all(receipt.get(k) is True for k in ('kernel_closed_frozen_empty','exact_ids_removed','slice_retained_frozen','engine_reconciled_for_exact_ids')))
 need(isinstance(manifest,dict) and set(manifest)=={'schema','generation','binding_sha256','candidate_sha256','writer_result_sha256','relay_done_sha256'} and type(manifest.get('schema')) is int and manifest.get('schema')==1 and manifest.get('generation')==generation)
 need(all(isinstance(receipt.get(k),str) and HEX.fullmatch(receipt[k]) is not None for k in ('writer_id','goose_id')) and receipt['writer_id']!=receipt['goose_id'])
 binding=receipt.get('binding_sha256');need(isinstance(binding,str) and HEX.fullmatch(binding) is not None and manifest.get('binding_sha256')==binding)
 need(isinstance(files,dict) and set(files)==set(FILES) and all(isinstance(files[n],bytes) and len(files[n])<=8192 for n in FILES))
 hashes={n:hashlib.sha256(files[n]).hexdigest() for n in FILES};need(receipt.get('candidate_sha256')==hashes and manifest.get('candidate_sha256')==hashes)
 need(isinstance(writer,bytes) and len(writer)<=2048 and isinstance(relay,bytes) and len(relay)<=16384)
 need(manifest.get('writer_result_sha256')==hashlib.sha256(writer).hexdigest() and manifest.get('relay_done_sha256')==hashlib.sha256(relay).hexdigest())
 return hashes
