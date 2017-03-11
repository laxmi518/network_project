
import unittest
from pylib import disk

import re
import sys
sys.path.append(disk.get_sibling(__file__,'../../../opsec_fetcher/'))
import logging

log_pattern = re.compile(r'(?P<key>.*?)=(?P<value>.*?)\|')

def parse_log(line):
    #Apply log_pattern regex to the obtained line
    event = dict(log_pattern.findall(line))
    if event:
        #Means the line matches the pattern
        event["msg"] = line
        #Update loc to the latest log loc
        loc = event.get("loc")
        #Update time to the latest log recieved time
        time = event.get("time")
    else:
        #Means the line doesn't match the pattern
        logging.warn("%s didn't match the log pattern. So skipping" % line)
    return event, loc or None, time or None

class TestOpsecFetcher(unittest.TestCase):
    def test_parse_log(self):
        line = 'loc=0|time=2012-10-30 10:14:09|action=keyinst|orig=192.168.2.123|\
i/f_dir=inbound|i/f_name=daemon|has_accounting=0|uuid=<00000000,00000000,00000000,00000000>|\
product=VPN-1 & FireWall-1|Internal_CA:=started|'

        parsed = parse_log(line)
        expected = {'Internal_CA:': 'started',
                    'action': 'keyinst',
                    'has_accounting': '0',
                    'i/f_dir': 'inbound',
                    'i/f_name': 'daemon',
                    'loc': '0',
                    'orig': '192.168.2.123',
                    'product': 'VPN-1 & FireWall-1',
                    'time': '2012-10-30 10:14:09',
                    'uuid': '<00000000,00000000,00000000,00000000>',
                    'msg': line}
        self.assertEqual(expected, parsed[0])

def main():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestOpsecFetcher)
    unittest.TextTestRunner(verbosity=2).run(suite)

if __name__ == '__main__':
    main()

