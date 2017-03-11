from subprocess import Popen
import unittest
import time
import re

import gevent
import socket
from pylib.wiring import gevent_zmq as zmq
from pylib import disk, conf, wiring, inet

from nose.tools import eq_
sample_data = """\x00\x00\x00\x05\x00\x00\x00\x01\xc0\xa8\x02(\x00\x01\x86\xa0\x00\x00\x00\x0c\x00\x03\xa9\x80\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\x8c\x00\x00\x00\x0c\x02\x00\x00\x01\x00\x00\x00\x06\x00\x00\x07\xd1\x00\x00\x00$\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x08\x00\'<D\xc8\x00\x00\x00\x00\x07\xd5\x00\x00\x004\x00\x00\x00\x01\xdd\x16\xcc\x00\x00\x00\x00\x01\x8f\x81\xe0\x00\x00\x00\x06f\x00\x00"\xc8\x00\x00\x00\x00\n\x89\x84\x00\x00\x104\xb0\x00\x00\x08\xa6\x00\x00\x00\x00\x00\xeb\x90\x00\x00\x00\x13\xdc\x00\x00\x07\xd4\x00\x00\x00H\x00\x00\x00\x00-\xf7\xd0\x00\x00\x00\x00\x00)t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe`\x00\x00\x00\x00\x00\x01\xc1 \x00\x00\x00\x00\x00\x18?\xe0\x00\x00\x00\x00\x00\x18?\xe0\x00\x00\x01\x0cD\x00\x00\x13\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd3\x00\x00\x00D\x00\x00\x00\x00<#\xd7\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00L\x00\x00\x00\x01\x00\x00\tf\x00\x00\x01M\x00\x00\x05\xa0\x00\x00\x00\x00\x00\x00\x12\x84\x00\x04\xde\x9a\x00\x00\x1e\x00\x00\x00\x00<\x00\x00\x00\x1e\x00\x002\xa2\x00\x00h\xea\x00\x00\x07\xd6\x00\x00\x00(\x00\x00\x00\x00\x00\x02Nx\x00\x00\x04\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x94\xa0\x00\x00\x00\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd0\x00\x00\x00D\x00\x00\x00\tritubuntu\x00\x00\x00\x1fB+\x1f\xd5)N\x8b\x88\xce\xe8\x0eMV[\xa0\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x152.6.32-28-generic-pae\x00\x00\x00"""

class test_sflow_collector(unittest.TestCase):
    zmq_context = zmq.Context()
    
    def setUp(self):
        # starting sflow collector
        config_path = disk.get_sibling(__file__, "test-config.json")
        config = conf.load(config_path)
        self.port = config["port"]
        self.sflow_out = wiring.Wire('norm_front_in', zmq_context=self.zmq_context)
        self.sflow_collector = Popen(['python', 'sflow_collector.py', config_path])
        time.sleep(0.5)

    def tearDown(self):
        self.sflow_collector.kill()
        self.sflow_out.close()
        time.sleep(0.5)
    
    def send_message(self, address=None, message=None):
        address = address or ('127.0.0.1', self.port)
        host, port = address
        
        data_file_path = disk.get_sibling(__file__, "sflow-data-v5.txt")
        message = message or open(data_file_path, "rb").read()
        
        client, sockaddr = inet.create_address(host, port, socket.SOCK_DGRAM)
        client.sendto(message, sockaddr)
        
        event = gevent.with_timeout(5, self.sflow_out.recv, timeout_value=None)
        
        mid = event.pop('mid')
        assert re.match(r'^LogInspect500\|sflow\|(127.0.0.1|::1)\|\d+\|1$', mid)
        
        device_name = event.pop('device_name')
        eq_(device_name, 'localhost')
        
        expected = dict(
                col_type='sflow',
                switch_uptime=240000L,
                _type_num='switch_uptime samples_count sample_source_id_index sub_agent_id sample_sequence_number sample_source_id_type version datagram_sequence_number version',
                samples_count=1L,
                sub_agent_id=100000L,
                device_ip=address[0],
                sample_type='COUNTER_SAMPLE',
                _p__raw_msg_b='AAAABQAAAAHAqAIoAAGGoAAAAAwAA6mAAAAAAQAAAAIAAAGMAAAADAIAAAEAAAAGAAAH0QAAACQAAAACAAAAAQAAAAEAAAAAAAAAAAAAAAIAAAABCAAnPETIAAAAAAfVAAAANAAAAAHdFswAAAAAAY+B4AAAAAZmAAAiyAAAAAAKiYQAABA0sAAACKYAAAAAAOuQAAAAE9wAAAfUAAAASAAAAAAt99AAAAAAACl0AAAAAAAAAAAAAAAAAAAA/mAAAAAAAAHBIAAAAAAAGD/gAAAAAAAYP+AAAAEMRAAAE6YAAAAAAAAAAAAAB9MAAABEAAAAADwj1woAAAAAAAAAAAAAAEwAAAABAAAJZgAAAU0AAAWgAAAAAAAAEoQABN6aAAAeAAAAADwAAAAeAAAyogAAaOoAAAfWAAAAKAAAAAAAAk54AAAECgAAAAAAAAAAAAAAAAAAlKAAAACMAAAAAAAAAAAAAAfQAAAARAAAAAlyaXR1YnVudHUAAAAfQisf1SlOi4jO6A5NVlugAAAAAgAAAAIAAAAVMi42LjMyLTI4LWdlbmVyaWMtcGFlAAAA\n',
                sample_sequence_number=12L,
                sample_source_id_index=1L,
                sample_source_id_type=2L,
                version=5L,
                address_type='IP_V4',
                datagram_sequence_number=12L,
                collected_at='LogInspect500',
                msg='',
                ip_address='192.168.2.40',
                _type_ip='ip_address device_ip',
                _type_str='sample_type address_type ip_address msg col_type device_name collected_at',
        )
        
        eq_(event, expected)
        
    def test_udp_flow(self):
       self.send_message(('127.0.0.1', self.port))
    
    def test_udp6_flow(self):
        self.send_message(('::1', self.port))
        
        

if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)