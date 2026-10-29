import datetime,unittest
from nuc_task_request_pin import TaskRequestPin
from trusted_tool_relay import Refused
class Tests(unittest.TestCase):
 def test_only_generated_time_and_workdir_may_change(self):
  t=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S %z');t=t[:-2]+':'+t[-2:]
  def user(time,path):return {'role':'user','content':'task\n<turn-context>\n<current-time>'+time+'</current-time>\n<working-directory>'+path+'</working-directory>\n</turn-context>'}
  initial={'messages':[{'role':'system','content':'system'},user(t,'/work/goose-relay-abc/work')]}
  pin=TaskRequestPin(initial,'task')
  self.assertTrue(pin({'messages':[initial['messages'][0],user(t,'/work/goose-relay-xyz/work')]}))
  self.assertFalse(pin({'messages':[{'role':'system','content':'altered'},initial['messages'][1]]}))
  for bad in [user('2000-01-01 00:00:00 +00:00','/work/goose-relay-abc/work'),user(t,'/etc'),{'role':'user','content':'other'}]:
   with self.assertRaises(Refused):pin({'messages':[initial['messages'][0],bad]})
if __name__=='__main__':unittest.main()
