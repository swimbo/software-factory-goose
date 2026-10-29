"""Task-specific byte contract; never a generic filesystem capability."""
import json

FILE_NAMES=('hello.py','test_hello.py')
MAX_FILE_BYTES=8192
MAX_ARGUMENT_BYTES=12288
MAX_FRAME_BYTES=65536

def canonical_arguments(value):
 if not isinstance(value,dict) or set(value)!={'files'} or not isinstance(value['files'],dict) or set(value['files'])!=set(FILE_NAMES):raise ValueError('invalid files')
 for text in value['files'].values():
  if not isinstance(text,str) or '\x00' in text or not 0<len(text.encode('utf-8'))<=MAX_FILE_BYTES:raise ValueError('invalid contents')
 raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
 if len(raw)>MAX_ARGUMENT_BYTES:raise ValueError('argument frame exceeded')
 return raw

def valid(value):
 try:canonical_arguments(value);return True
 except (ValueError,TypeError,RecursionError):return False

def _unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('duplicate key')
  result[key]=value
 return result

def strict_loads(raw):
 if not isinstance(raw,bytes) or not 0<len(raw)<=MAX_FRAME_BYTES:raise ValueError('frame exceeded')
 value=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('invalid number')))
 canonical_arguments(value)
 return value
