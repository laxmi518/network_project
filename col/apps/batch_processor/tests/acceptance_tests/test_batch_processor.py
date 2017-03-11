
'''
Acceptance test to cover 'batch_processor.py'
'''

import time
import unittest
import subprocess

from pylib import wiring



class test_batch_processor(unittest.TestCase):
    def setUp(self):

        # input source
        self.batch_collector_out = wiring.Wire('batch_collector_out')

        # 'starting batch_processor'
        self.batch_processor = subprocess.Popen('python batch_processor.py', shell=True)

        # output sink
        self.normalizer = wiring.Wire('normalizer_in', use_gevent=True)

        # Allow syslog_collector to prepare for serving
        time.sleep(0.5)

    def tearDown(self):
        self.batch_processor.kill()

        self.batch_collector_out.close()
        self.normalizer.close()

        # allow sockets to prepare for close
        time.sleep(0.5)

    def send_event(self, file, sid=None, col_ts=None, parser=None):
        event = dict(
            file=file,
            sid = sid or '123',
            col_ts = col_ts or str(int(time.time())),
            parser = parser or 'SyslogParser')

        self.batch_collector_out.send(event)

    def test_normal_logfile(self):
        file = 'tests/data/20101215'
        self.send_event(file)

        event = self.normalizer.recv()
        assert event['pri'] == '57'
        assert event['msg'] == "<57> Dec 15 00:00:00 127.0.0.1 /usr/sbin/cron[93536]: (root) CMD (   /usr/sbin/newsyslog.pl)"

        # truncate normalizer receiver socket
        self.normalizer.recv()

    def test_gz_logfile(self):
        file = 'tests/data/20101215.gz'
        self.send_event(file)

        event = self.normalizer.recv()
        assert event['pri'] == '57'
        assert event['msg'] == "<57> Dec 15 00:00:00 127.0.0.1 /usr/sbin/cron[93536]: (root) CMD (   /usr/sbin/newsyslog.pl)"


if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)
