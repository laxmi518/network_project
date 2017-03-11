import time
import unittest
import subprocess
from ftplib import FTP

from nose.tools import eq_
import gevent
from pylib.wiring import gevent_zmq as zmq
from pylib import wiring


class TestFTPCollector(unittest.TestCase):
    zmq_context = zmq.Context()

    def setUp(self):
        self.ftp_server = subprocess.Popen(['python', 'ftp_collector.py',
                                 'tests/data/test-config.json'])

        self.batch_processor_in = wiring.Wire('batch_processor_in',
                                              use_gevent=True)
        # dont know why it fails when zmq_context reused
        #self.batch_processor_in = wiring.Wire('batch_processor_in',
        #                                      zmq_context=self.zmq_context)

        # Allow to prepare for serving
        time.sleep(0.5)

    def tearDown(self):
        self.ftp_server.kill()
        self.batch_processor_in.close()
        time.sleep(0.5)

    def login(self):
        ftp = FTP()
        ftp.connect('0.0.0.0', 2021)
        ftp.login('alpha', 'alpha')
        return ftp

    def test_login(self):
        self.login()

    def test_bad_authentication(self):
        ftp = FTP()
        ftp.connect('0.0.0.0', 2021)
        self.assertRaises(Exception, ftp.login, 'sujan', 'asdf')

    def test_normal_logfile(self):
        ftp = self.login()
        logfile = 'tests/data/1308216000'
        f = open(logfile)
        ftp.storbinary('STOR test_logfile_%s' % time.time(), f)

        event = gevent.with_timeout(5, self.batch_processor_in.recv,
                                    timeout_value=None)
        eq_(event['parser'], 'SyslogParser')
        eq_(event['sid'], 'ftpc|127.0.0.1-ubuntu')

    def test_gz_logfile(self):
        ftp = self.login()
        logfile = 'tests/data/1308216000.gz'
        f = open(logfile)
        ftp.storbinary('STOR test_logfile_%s.gz' % time.time(), f)

        event = gevent.with_timeout(5, self.batch_processor_in.recv,
                                    timeout_value=None)
        eq_(event['parser'], 'SyslogParser')
        eq_(event['sid'], 'ftpc|127.0.0.1-ubuntu')


if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)
