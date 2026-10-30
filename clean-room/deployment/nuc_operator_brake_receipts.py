"""Read-only inventory of retained operator-brake canary records."""
import json, os, pathlib, re, stat
STATE = pathlib.Path('/var/lib/software-factory-goose/stop')
ROOT = pathlib.Path('/etc/software-factory-goose/tasks')
class Host:
 def __init__(self, source_digest=None): self.source_digest = source_digest

def record(path, *, raw=False):
 fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
 try:
  s = os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_gid != 0 or s.st_nlink != 1 or stat.S_IMODE(s.st_mode) != 0o600 or s.st_size > 16384: raise RuntimeError('retained record identity mismatch')
  b = os.read(fd, 16385)
  if len(b) != s.st_size: raise RuntimeError('retained record length mismatch')
  return b if raw else json.loads(b)
 finally: os.close(fd)

def make_plan(host):
 results = []
 for path in sorted(STATE.glob('*.canary-receipt.json')):
  rec = record(path)
  if rec.get('operator_frontend_verified') is not True: continue
  target = rec.get('target_id', '')
  if not re.fullmatch('[0-7][0-9A-HJKMNP-TV-Z]{25}', target) or path.name != target + '.canary-receipt.json': raise RuntimeError('receipt target mismatch')
  intent_path = STATE / (target + '.canary-intent.json')
  catalogue = ROOT / (target + '.json')
  closed = STATE / (target + '.closed')
  intent, cat, closure = record(intent_path), record(catalogue), record(closed, raw=True)
  if intent.get('target_id') != target or intent.get('operation') != 'operator-frontend-sleeper-stop' or cat.get('target_id') != target or closure != (target + '\n').encode() or rec.get('kernel_stop_verified') is not True or rec.get('engine_reconciled') is not False or rec.get('slice_removed') is not True: raise RuntimeError('receipt linkage mismatch')
  results.append({'receipt': str(path), 'record': rec, 'intent': intent, 'catalogue': cat, 'closed': str(closed)})
 return {'component':'operator-brake-receipts', 'source_sha256':host.source_digest, 'receipts':results}
