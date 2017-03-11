import os
import sys
import time
import unittest
from subprocess import Popen, PIPE

class TestFTPCollector(unittest.TestCase):
    def setUp(self):
        # ftp_fetcher forwards the received file info to batch_processor,
        # which then forwards to ZMQ

        self.base = os.path.abspath(os.path.dirname(__file__)) + '/'

        print >> sys.stderr, 'starting batch_processor'
        self.batch_processor = Popen('python %s' %
                                (self.base + '../../apps/batch_processor.py'),
                                shell=True)

        print >> sys.stderr, 'starting sink for collector out'
        self.collector_sinker = Popen('python %s storage_in' %
                                      (self.base + '../../../pylib/sink.py'),
                                      shell=True, stdout=PIPE, stderr=PIPE)

    def tearDown(self):
        self.batch_processor.kill()
        self.collector_sinker.kill()

    def test_fetch(self):
        self.ftp_fetcher = Popen('python %s %s %s --config=%s' %
                                (self.base + '../../apps/ftp_fetcher/ftp_fetcher.py',
                                 '123',
                                 'logs/IP/127.0.0.1/201012/20101215',
                                 self.base + '../data/ftp_fetcher.conf'),
                                shell=True)

        assert self.output_in_sink()

    def output_in_sink(self):
        # count no of msgs collected in sink in 2 sec
        count = 0
        count_time = 2
        start = time.time()
        while True:
            time.sleep(0.1)
            out = self.collector_sinker.stdout.readline()
            if out:
                count += 1
            if time.time() - start > count_time:
                print >> sys.stderr, 'test_ftp_collector.py',
                if count:
                    print >> sys.stderr, count, 'msgs were collected in sink in %d sec' % count_time
                    return True
                else:
                    print >> sys.stderr, 'no msgs were collected in sink in %d sec' % count_time
                    return False


if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)
