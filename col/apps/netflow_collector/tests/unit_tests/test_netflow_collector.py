from pylib.wiring import gevent_zmq as zmq
from gevent import socket
import struct
import time

from pylib import inet, wiring
from dpkt import netflow

from nose.tools import eq_
from nose.tools import assert_is
from nose.tools import assert_equal
from nose.tools import assert_not_equal


import sys
sys.path.append("../../../netflow_collector")

from netflow_collector import start_udp_server
from netflow_collector import _get_sid
from netflow_collector import get_netflow_packet_version
from netflow_collector import parse_record
from netflow_collector import _handle_data
from netflow_collector import _netflow9
from netflow_collector import _New_Netflow_v9
from netflow_collector import msgfill_parsed_record_v9

import unittest

sample_v5 = '\x00\x05\x00\x01\x01\xbd$\x1dP\xab-=\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x03\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x01\xbc9\xbd\x01\xbd$\x1d\x10\x92\x00P\x00\x00\x11\x01\x00\x02\x00\x03 \x1f\x00\x00'
sample_v9 = '\x00\t\x00\x02\x01\xbc\x90G\x00\x00\x00\x00\x00\x00\x00o\x00\x00\x00\x00\x00\x00\x00P\x01,\x00\x12\x00\x08\x00\x04\x00\x0c\x00\x04\x00\x0f\x00\x04\x00\n\x00\x04\x00\x0e\x00\x04\x00\x02\x00\x04\x00\x01\x00\x04\x00\x07\x00\x02\x00\x0b\x00\x02\x00\x06\x00\x01\x00\x04\x00\x01\x00\x05\x00\x01\x00\x11\x00\x02\x00\x10\x00\x02\x00\t\x00\x01\x00\r\x00\x01\x00\x15\x00\x04\x00\x16\x00\x04\x01,\x008\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x10\x92\x00P\x00\x11\x01\x00\x03\x00\x02 \x1f\x01\xbc\x90G\x01\xbb\xa5\xe7\x00\x00\x00'

config = {"col_type": "netflow"}
collected_at = "Loginspect500"
col_type = "netflowc"

zmq_context = zmq.Context()
netflow_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)
ip = '127.0.0.1'
sid = "%s|%s" %(col_type, ip)
device_name = "device_name"


def test_test():
    eq_('test','test', msg="Checking test")

def test_start_udp_server():
    port = 9001
    sock = start_udp_server(port)
    sock_obj, sockaddr = inet.create_external_address(port, socket.SOCK_DGRAM, use_gevent=True)
    assert_is(type(sock_obj), type(sock), "test UDP server")

def test__get_sid():
    ip = "127.0.0.1"
    
    expected = '%s|%s' % (config['col_type'], ip)
    result = _get_sid(ip, config)
    eq_(result, expected, "test sid")

def test_get_netflow_packet_version_v5():
    expected = 5
    result = get_netflow_packet_version(sample_v5[0:2])
    eq_(result, expected, "test v5 version")

def test_get_netflow_packet_version_v9():
    expected = 9
    result = get_netflow_packet_version(sample_v9[0:2])
    eq_(result, expected, "test v9 version")

def test_get_netflow_packet_version_incorrect():
    result = get_netflow_packet_version('\x00\x12')
    assert_not_equal(result, 5, "test incorrect version")
    assert_not_equal(result, 9, "test incorrect version")

def test_header():
    version = get_netflow_packet_version(sample_v5[0:2])
    count = socket.ntohs(struct.unpack('H',sample_v5[2:4])[0])
    current_unix_sec = (struct.unpack('I',sample_v5[8:12])[0])
    eq_(version, 5, "test version")
    eq_(count, 1, "test count records")
    eq_(current_unix_sec, 1026403152, "test current unix sec")

def test_netflowdata_v5():    
    global record_v5
    netflow5 = netflow.Netflow5()
    netflow5.unpack(sample_v5)
    netflowdata = netflow5.data
    assert len(netflowdata) == 1
    for record in netflowdata:
        record_v5 = record
    netflowdata_str_result = str(netflowdata)
    netflowdata_str_expected = "[NetflowRecord(output_iface=5, src_addr=167772162, ip_proto=17, start_time=29112765, src_as=2, bytes_sent=64, src_mask=32, pkts_sent=1, dst_as=3, end_time=29172765, tos=1, input_iface=3, src_port=4242, dst_mask=31, dst_addr=167772163, dst_port=80)]"
    eq_(netflowdata_str_result, netflowdata_str_expected, "test netflowdata")
    
def test_parse_record():
    result = parse_record(record_v5)
    expected = dict(
            protocol_name='UDP',
            end_uptime_ms=29172765,
            start_uptime_ms=29112765,
            packet_count=1,
            destination_port=80,
            types_of_service=1,
            source_port=4242,
            destination_address='10.0.0.3',
            source_address='10.0.0.2',
            bytes_count=64,
            interface_index=3,
            _type_str='protocol_name source_address destination_address',
            _type_num='interface_index start_uptime_ms end_uptime_ms source_port destination_port packet_count bytes_count types_of_service',
            _type_ip='source_address destination_address',
            )
    print result, expected
    eq_(result, expected, "test parse record")

def test_msgfill_parsed_record_v9():
    d = {1: 64, 2: 1, 4: 17, 5: 1, 6: 0, 7: 4242, 8: 167772162, 9: 32, 10: 3, 11: 80, 12: 167772163, 13: 31, 14: 5, 15: 0, 16: 2, 17: 3, 21: 29572695, 22: 29512695}
    result = msgfill_parsed_record_v9(d)
    expected = dict(
        protocol=17,
        first_switched=29512695,
        _type_num='bytes_count packet_count protocol types_of_service tcp_flag source_port source_mask input_interface_index destination_port destination_mask output_interface_index source_as destination_as last_switched first_switched',
        destination_address='10.0.0.3',
        last_switched=29572695,
        _type_str='protocol_name source_address destination_address next_hop',
        protocol_name='UDP',
        destination_as=3,
        _type_ip='source_address destination_address next_hop',
        destination_mask=31,
        source_address='10.0.0.2',
        source_mask=32,
        bytes_count=64,
        input_interface_index=3,
        next_hop='0.0.0.0',
        types_of_service=1,
        source_as=2,
        destination_port=80,
        output_interface_index=5,
        packet_count=1,
        tcp_flag=0,
        source_port=4242,
    )
    eq_(result, expected, "test msg_fill")

def test__handle_data():
    assert True

def test_header_v9():
    version = get_netflow_packet_version(sample_v9[0:2])
    count = socket.ntohs(struct.unpack('H',sample_v9[2:4])[0])
    current_unix_sec = (struct.unpack('I',sample_v9[8:12])[0])
    #Other information in packet header v9
    sys_uptime_ms = (struct.unpack('!L',sample_v9[4:8])[0])
    unix_secs = (struct.unpack('!L',sample_v9[8:12])[0])
    package_sequence = (struct.unpack('!L',sample_v9[12:16])[0])
    source_id = (struct.unpack('!L',sample_v9[16:20])[0])
    
    eq_(version, 9, "test version")
    eq_(count, 2, "test count records")
    eq_(current_unix_sec, 0, "test current unix sec")
    eq_(sys_uptime_ms, 29134919, "test sys_uptime")
    eq_(unix_secs, 0, "test unix_secs")
    eq_(package_sequence, 111, "test package_sequene")
    eq_(source_id, 0, "test source_id")

def test__netflow9():
    data = sample_v9
    count = socket.ntohs(struct.unpack('H',sample_v9[2:4])[0])
    ip = '127.0.0.1'
    expire_time = 600
    sid = "netflow|127.0.0.1"
    
    result = _netflow9(data, count, expire_time, sid, netflow_out, device_name, col_type, ip, collected_at)
    data_dict = {300: {1: 64, 2: 1, 4: 17, 5: 1, 6: 0, 7: 4242, 8: 167772162, 9: 32, 10: 3, 11: 80, 12: 167772163, 13: 31, 14: 5, 15: 0, 16: 2, 17: 3, 21: 29134919, 22: 29074919}}
    data_data =  '\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x10\x92\x00P\x00\x11\x01\x00\x03\x00\x02 \x1f\x01\xbc\x90G\x01\xbb\xa5\xe7\x00\x00\x00'
    #_packet_type_b = 'ASwAEgAIAAQADAAEAA8ABAAKAAQADgAEAAIABAABAAQABwACAAsAAgAGAAEABAABAAUAAQARAAIAEAACAAkAAQANAAEAFQAEABYABA==\n'
    expected = [(data_dict, data_data)]
    print result, expected
    eq_(result, expected)

class TestNewNetflowv9(unittest.TestCase):
    sample = sample_v9
    count = socket.ntohs(struct.unpack('H',sample_v9[2:4])[0])
    def test_init(self):
        new_netflow = _New_Netflow_v9(self.sample, self.count)
        eq_(new_netflow.data, self.sample)
        eq_(new_netflow.count, self.count)
        eq_(new_netflow._raw_data, '')
        eq_(new_netflow.length, list())
        eq_(new_netflow.flowset_id, list())     #lsit of flowset id
        eq_(new_netflow.template_header_list, list())   #contains flowset_id and length
        eq_(new_netflow.flow_data_list, list())         #contains raw data
        eq_(new_netflow.template_template_list, list()) #contains template_id and field count
        eq_(new_netflow.data_header_list, list())       #contains template_id and length of the data
        eq_(new_netflow.template_data_dict, dict()) #contains templateflow data as template_id:data 
        eq_(new_netflow.data_data_dict, list()) #contains dataflow data as template_id:data
        eq_(new_netflow.unparsed_raw_data, list())
        eq_(new_netflow.now , int(time.time()))
        
        assert_not_equal(new_netflow.data, sample_v5)
        assert_not_equal(new_netflow.count, 1)
        assert_not_equal(new_netflow.unparsed_raw_data, sample_v9)
        assert_not_equal(new_netflow.now, int(time.time()) - 1)
    
    def test_get_flowset_id_length_data(self):
        new_netflow = _New_Netflow_v9(self.sample, self.count)
        eq_(new_netflow.get_flowset_id_length_data(self.sample, self.count), None, "test get flowset id")
        eq_(new_netflow.length, [[80,56]])
        eq_(new_netflow.flowset_id, [0, 300], "test get flowset id")
        eq_(new_netflow.template_header_list, [(0, 80), (300, 56)])   
        eq_(new_netflow.flow_data_list, ['\x00\x00\x00P\x01,\x00\x12\x00\x08\x00\x04\x00\x0c\x00\x04\x00\x0f\x00\x04\x00\n\x00\x04\x00\x0e\x00\x04\x00\x02\x00\x04\x00\x01\x00\x04\x00\x07\x00\x02\x00\x0b\x00\x02\x00\x06\x00\x01\x00\x04\x00\x01\x00\x05\x00\x01\x00\x11\x00\x02\x00\x10\x00\x02\x00\t\x00\x01\x00\r\x00\x01\x00\x15\x00\x04\x00\x16\x00\x04', '\x01,\x008\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x10\x92\x00P\x00\x11\x01\x00\x03\x00\x02 \x1f\x01\xbc\x90G\x01\xbb\xa5\xe7\x00\x00\x00'] )
        
        assert_not_equal(new_netflow.length, list())
        assert_not_equal(new_netflow.flowset_id, list())
    
    def test_get_raw_template_dict_raw_data_dict(self):
        new_netflow = _New_Netflow_v9(self.sample, self.count)
        eq_(new_netflow.get_flowset_id_length_data(self.sample, self.count), None, "test get flowset id")
        eq_(new_netflow.get_raw_template_dict_raw_data_dict(sid, netflow_out, device_name, col_type, ip, collected_at), None, "get_raw_data")
        eq_(new_netflow.template_template_list, [(300, 18)])
        
        expected_data_header_list = [(300, 56, '\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x10\x92\x00P\x00\x11\x01\x00\x03\x00\x02 \x1f\x01\xbc\x90G\x01\xbb\xa5\xe7\x00\x00\x00')]
        eq_(new_netflow.data_header_list, expected_data_header_list)
        
        assert_not_equal(new_netflow.template_template_list, dict())
        assert_not_equal(new_netflow.template_template_list, list())
        assert_not_equal(new_netflow.template_template_list, list((300, 0)))
        
    def test_update_template_data_list_dict(self):
        new_netflow = _New_Netflow_v9(self.sample, self.count)
        eq_(new_netflow.get_flowset_id_length_data(self.sample, self.count), None, "test get flowset id")
        eq_(new_netflow.update_template_data_list_dict(), None, "test update template data list")
        
        eq_(new_netflow.length, [[80, 56]])
        eq_(new_netflow.flowset_id, [0, 300])
        eq_(new_netflow.template_header_list, [(0, 80), (300, 56)])   
        eq_(new_netflow.flow_data_list, ['\x00\x00\x00P\x01,\x00\x12\x00\x08\x00\x04\x00\x0c\x00\x04\x00\x0f\x00\x04\x00\n\x00\x04\x00\x0e\x00\x04\x00\x02\x00\x04\x00\x01\x00\x04\x00\x07\x00\x02\x00\x0b\x00\x02\x00\x06\x00\x01\x00\x04\x00\x01\x00\x05\x00\x01\x00\x11\x00\x02\x00\x10\x00\x02\x00\t\x00\x01\x00\r\x00\x01\x00\x15\x00\x04\x00\x16\x00\x04', '\x01,\x008\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x10\x92\x00P\x00\x11\x01\x00\x03\x00\x02 \x1f\x01\xbc\x90G\x01\xbb\xa5\xe7\x00\x00\x00'] )
        
        assert_not_equal(new_netflow.length, list())
        assert_not_equal(new_netflow.flowset_id, list())
    
    def test_clean_unparsed_raw_data(self):
        new_netflow = _New_Netflow_v9(self.sample, self.count)
        eq_(new_netflow.get_flowset_id_length_data(self.sample, self.count), None, "test get flowset id")
        eq_(new_netflow.get_raw_template_dict_raw_data_dict(sid, netflow_out, device_name, col_type, ip, collected_at), None, "test update template data list")
        eq_(new_netflow.update_template_data_list_dict(), None, "test update template data list")
        
        eq_(new_netflow.unparsed_raw_data, list())
        
        assert_not_equal(new_netflow.flowset_id, list(self.sample))
        assert_not_equal(new_netflow.flowset_id, dict())
     
if __name__ == '__main__':
    import nose
    nose.run(defaultTest=__name__)
