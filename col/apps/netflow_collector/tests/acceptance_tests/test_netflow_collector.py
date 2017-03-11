import os
import time
import unittest
import socket
from subprocess import Popen
import re

import gevent
from pylib.wiring import gevent_zmq as zmq
from nose.tools import eq_
from pylib import wiring, conf, disk, inet, cidr, homing

class test_netflow_collector(unittest.TestCase):
    zmq_context = zmq.Context()
    
    def setUp(self):
        # netflow collector forwards the received msg to normalizer_in
        # starting netflow collector
        config_path = disk.get_sibling(__file__, "test-config-netflow.json")
        config = conf.load(config_path)
        self.port = config['port']

        self.normalizer = wiring.Wire('norm_front_in',
                zmq_context=self.zmq_context)

        self.netflow_collector = Popen(['python', 'netflow_collector.py',
                                       config_path])
        # Allow to prepare for serving
        time.sleep(0.5)
        
    def tearDown(self):
        self.netflow_collector.kill()
        self.normalizer.close()
        time.sleep(0.5)

    def send_message(self, address=None, message=None, version=5):
        address = address or ('127.0.0.1', self.port )
        host, port = address

        client, sockaddr = inet.create_address(host, port,
                    socket.SOCK_DGRAM)
        
        if version == 5:
            file_path = disk.get_sibling(__file__, "v5-data.txt")
            msg = open(file_path, "rb").read()
            message  = message or msg

            client.sendto(message, sockaddr)
            
            event = gevent.with_timeout(5, self.normalizer.recv, timeout_value=None)
            
            mid = event.pop('mid')
            assert re.match(r'^LogInspect500\|netflow\|(127.0.0.1|::1)\|\d+\|1$', mid)
            #'mid': u'LogInspect500|netflow|192.168.2.0/24|1353399814|1',
            
            eq_(event, dict(
                #msg=message.rstrip('\n'),
                destination_address='10.0.0.3',
                protocol_name='UDP',
                _p__raw_msg_b='CgAAAgoAAAMAAAAAAAMABQAAAAEAAABAAbw5vQG9JB0QkgBQAAARAQACAAMgHwAA\n',
                version=5,
                msg='',
                source_address='10.0.0.2',
                current_unix_sec=1026403152,
                bytes_count=64,
                end_uptime_ms=29172765,
                types_of_service=1,
                destination_port=80,
                interface_index=3,
                start_uptime_ms=29112765,
                device_name='localhost',
                packet_count=1,
                col_type='netflow',
                source_port=4242,
                device_ip=address[0],
                collected_at='LogInspect500',
                _type_num='interface_index start_uptime_ms end_uptime_ms source_port destination_port packet_count bytes_count types_of_service version current_unix_sec',
                _type_str='protocol_name source_address destination_address msg col_type device_name collected_at',
                _type_ip='source_address destination_address device_ip',
                ))

        elif version == 9:
            file_path = disk.get_sibling(__file__, "v9-data.txt")
            msg = open(file_path, "rb").read()
            message = message or msg

            client.sendto(message, sockaddr)
            
            event = gevent.with_timeout(5, self.normalizer.recv, timeout_value=None)
            
            mid = event.pop('mid')
            assert re.match(r'^LogInspect500\|netflow\|(127.0.0.1|::1)\|\d+\|1$', mid)
            #'mid': u'LogInspect500|netflow|192.168.2.0/24|1353399814|1',
            
            expected = {'_type_str': 'packet_type msg col_type device_name collected_at', '_type_num': 'template_id', 'template_id': 300, 'device_ip': '127.0.0.1', 'device_name': u'localhost', 'packet_type': 'template', 'col_type': u'netflow', 'collected_at': u'LogInspect500', 'msg': '', '_p___raw_msg_b': 'ASwAEgAIAAQADAAEAA8ABAAKAAQADgAEAAIABAABAAQABwACAAsAAgAGAAEABAABAAUAAQARAAIAEAACAAkAAQANAAEAFQAEABYABA==\n', '_type_ip': 'device_ip'}
            eq_(event, expected)
            #eq_(event, dict(
            #    protocol=17, 
            #    first_switched=29074919, 
            #    unix_secs=0, 
            #    sys_uptime_ms=29134919, 
            #    package_sequence=111, 
            #    destination_address='10.0.0.3',
            #    protocol_name='UDP',
            #    _p__raw_msg_b='CgAAAgoAAAMAAAAAAAAAAwAAAAUAAAABAAAAQBCSAFAAEQEAAwACIB8BvJBHAbul5wAAAA==\n',
            #    version=9,
            #    msg='',
            #    source_address='10.0.0.2',
            #    bytes_count=64,
            #    destination_mask=31, 
            #    source_mask=32, 
            #    next_hop='0.0.0.0', 
            #    source_as=2, 
            #    output_interface_index=5, 
            #    source_id=0,
            #    last_switched=29134919, 
            #    tcp_flag=0,
            #    destination_as=3,
            #    types_of_service=1,
            #    destination_port=80,
            #    input_interface_index=3,
            #    device_name='localhost',
            #    packet_count=1,
            #    col_type='netflow',
            #    source_port=4242,
            #    device_ip=address[0],
            #    collected_at='LogInspect500',
            #    _type_num='bytes_count packet_count protocol types_of_service tcp_flag source_port source_mask input_interface_index destination_port destination_mask output_interface_index source_as destination_as last_switched first_switched version sys_uptime_ms unix_secs package_sequence source_id',
            #    _type_str='protocol_name source_address destination_address next_hop msg col_type device_name collected_at',
            #    _type_ip='source_address destination_address next_hop device_ip',
            #    ))    
        
        else:
            raise ValueError("Unknown netflow version type: %r" %version)
        
    def test_udp_version5(self):
        self.send_message(version=5)
        
    def test_udp_version9(self):
        self.send_message(version=9)
    
    def test_udp6_version5(self):
        self.send_message(address=('::1', self.port), version=5)
    

if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)
