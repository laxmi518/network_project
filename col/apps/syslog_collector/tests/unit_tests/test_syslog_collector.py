import sys
from pylib.wiring import gevent_zmq as zmq

from nose.tools import eq_

from pylib import disk, wiring, conf, inet

sys.path.append("../../syslog_collector.py")

from syslog_collector import _get_profile_info
from syslog_collector import _get_sid_parser
from syslog_collector import _create_listener

import unittest


class test_syslog_collector(unittest.TestCase):
    zmq_context = zmq.Context()
    syslog_out = wiring.Wire('collector_out', zmq_context=zmq_context)
    
    def setUp(self):
        config_path = disk.get_sibling(__file__, "test-config.json")
        self.config = conf.load(config_path)
        self.port = self.config["port"]
        self.ssl_port = self.config["ssl_port"]
        self.collected_at = self.config["loginspect_name"]
        
    def tearDown(self):
        pass
    
    def test__create_listener(self):
        result = _create_listener(self.port)
        sock, sockaddr = inet.create_external_address(self.port)
        expected = sock
        eq_(type(result), type(expected))
    
    def test__get_profile_info(self):
        addr = '127.0.0.1', self.port
        ip = addr[0]
        sid = 'syslog|127.0.0.1'
        device_name = 'localhost'
        result = _get_profile_info(addr, self.config)
        result = list(result)
        parser = result.pop(2)
        expected = [ip, sid, device_name, self.collected_at]
        eq_(result, expected)
        
    def test__get_sid_parser(self):
        profile = self.config["client_map"]['127.0.0.1']
        sid, parser = _get_sid_parser(self.config, '127.0.0.1', profile)
        eq_(sid, 'syslog|127.0.0.1')

if __name__=='__main__':
    import nose
    nose.run(defaultTest=__name__)
