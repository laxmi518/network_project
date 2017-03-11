
from gevent import socket
import struct
import time

from pylib import inet
from pylib.wiring import gevent_zmq as zmq

from nose.tools import eq_
from nose.tools import assert_is

import sys
sys.path.append("../../sflow_collector.py")

from sflow_collector import start_udp_server
from sflow_collector import _get_sid
from sflow_collector import _is_valid_ipv4
from sflow_collector import _is_valid_ipv6
from sflow_collector import _is_valid_num
from sflow_collector import _fill_msg_types
from sflow_collector import peek_data32
from sflow_collector import get_data32
from sflow_collector import peek_data128
from sflow_collector import get_data128
from sflow_collector import get_data64
from sflow_collector import get_data32_addr
from sflow_collector import get_data128_addr
from sflow_collector import skip_bytes
from sflow_collector import parse_sample
from sflow_collector import parse_flow_sample
from sflow_collector import parse_flow_record_header
from sflow_collector import parse_counter_sample
from sflow_collector import parse_counter_record_header
from sflow_collector import parse_counters_generic
from sflow_collector import parse_counters_ethernet
from sflow_collector import EVENT, EACH_EVENT

import sflow_collector

import unittest

sample_data = """\x00\x00\x00\x05\x00\x00\x00\x01\xc0\xa8\x02(\x00\x01\x86\xa0\x00\x00\x00\x0c\x00\x03\xa9\x80\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\x8c\x00\x00\x00\x0c\x02\x00\x00\x01\x00\x00\x00\x06\x00\x00\x07\xd1\x00\x00\x00$\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x08\x00\'<D\xc8\x00\x00\x00\x00\x07\xd5\x00\x00\x004\x00\x00\x00\x01\xdd\x16\xcc\x00\x00\x00\x00\x01\x8f\x81\xe0\x00\x00\x00\x06f\x00\x00"\xc8\x00\x00\x00\x00\n\x89\x84\x00\x00\x104\xb0\x00\x00\x08\xa6\x00\x00\x00\x00\x00\xeb\x90\x00\x00\x00\x13\xdc\x00\x00\x07\xd4\x00\x00\x00H\x00\x00\x00\x00-\xf7\xd0\x00\x00\x00\x00\x00)t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe`\x00\x00\x00\x00\x00\x01\xc1 \x00\x00\x00\x00\x00\x18?\xe0\x00\x00\x00\x00\x00\x18?\xe0\x00\x00\x01\x0cD\x00\x00\x13\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd3\x00\x00\x00D\x00\x00\x00\x00<#\xd7\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00L\x00\x00\x00\x01\x00\x00\tf\x00\x00\x01M\x00\x00\x05\xa0\x00\x00\x00\x00\x00\x00\x12\x84\x00\x04\xde\x9a\x00\x00\x1e\x00\x00\x00\x00<\x00\x00\x00\x1e\x00\x002\xa2\x00\x00h\xea\x00\x00\x07\xd6\x00\x00\x00(\x00\x00\x00\x00\x00\x02Nx\x00\x00\x04\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x94\xa0\x00\x00\x00\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd0\x00\x00\x00D\x00\x00\x00\tritubuntu\x00\x00\x00\x1fB+\x1f\xd5)N\x8b\x88\xce\xe8\x0eMV[\xa0\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x152.6.32-28-generic-pae\x00\x00\x00"""

data = None

def test_test():
    eq_("test", "test", "Checking sflow unittest")
    
def test_start_udp_server():
    port = 6343
    sock = start_udp_server(port)
    sock_obj, sockaddr = inet.create_external_address(port, socket.SOCK_DGRAM, use_gevent=True)
    assert_is(type(sock_obj), type(sock), "test UDP server")
    
def test__get_sid():
    ip = "127.0.0.1"
    config = {"col_type": "sflow"}
    expected = '%s|%s' % (config['col_type'], ip)
    result = _get_sid(ip, config)
    eq_(result, expected, "test sid")

def test__is_valid_ipv4_invalid():
    address =  "192"      #"\xc0\xa8\x02\x16"
    eq_(_is_valid_ipv4(address), False)

def test__is_valid_ipv4_valid():
    address = "127.0.0.1"
    eq_(_is_valid_ipv4(address), True)

def test__is_valid_ipv6_invalid():
    address =  "192.127.4.5"
    eq_(_is_valid_ipv6(address), False)

def test__is_valid_ipv6_valid():
    address = "::1"
    eq_(_is_valid_ipv6(address), True)
    
def test__is_valid_num_invalid():
    num = "a"
    eq_(_is_valid_num(num), False)
    
def test__is_valid_num_valid():
    num = 2
    eq_(_is_valid_num(num), True)
    
def test__fill_msg_types():
    d = dict(
        number=9841045959,
        string="test_msg_fill",
        ipv4='192.168.2.222',
        ipv6='::1',
        _p__raw_msg_b='AAAABQAAAAHAqAIo',
        next_num=347,
        misc="LI510"
    )
    result = _fill_msg_types(d)
    expected = dict(
        string='test_msg_fill',
        misc='LI510',
        number=9841045959,
        _p__raw_msg_b='AAAABQAAAAHAqAIo',
        ipv4='192.168.2.222',
        ipv6='::1',
        next_num=347,
        _type_ip='ipv4 ipv6',
        _type_num='number next_num',
        _type_str='ipv4 string ipv6 misc',
        )
    eq_(result, expected)
    
def test_peek_data32():
    global data
    result = peek_data32(sample_data)
    expected = 5
    eq_(result,expected)
    eq_(data,sflow_collector.data)
    
def test_get_data32():
    global data
    result = get_data32(sample_data)
    expected = 5
    eq_(result,expected)
    data = sample_data[4:]
    eq_(data,sflow_collector.data)
    
def test_peek_data128():
    global data
    result = peek_data128(data)
    expected = 12
    eq_(result,expected)
    eq_(data,sflow_collector.data)

def test_get_data128():
    global data
    result = get_data128(data)
    expected = 12
    eq_(result,expected)
    data = data[16:]
    eq_(data,sflow_collector.data)
    
def test_get_data64():
    global data
    result = get_data64(data)
    expected = 240000
    eq_(result, expected)
    data = data[8:]
    eq_(data, sflow_collector.data)

def test_get_data32_addr():
    global data
    result = get_data32_addr(data)
    expected = '0.0.0.2'        #   ipv4 address format
    eq_(result, expected)
    data = data[4:]
    eq_(data, sflow_collector.data)
    
def test_get_data128_addr():
    global data
    result = get_data128_addr(data)
    expected = "::18c:0:c:200:1:0:6"
    eq_(result, expected)
    data = data[16:]
    eq_(data, sflow_collector.data)

def test_skip_bytes():
    global data
    result = skip_bytes(data, 8)
    data = data[8:]
    expected = data
    eq_(data, sflow_collector.data)
    
def test_parse_sample():
    global data
    result = parse_sample(data)
    expected = None
    eq_(result, expected)
    data = data[20:]
    eq_(len(data), len(sflow_collector.data))
    eq_(data, sflow_collector.data)

def test_parse_flow_sample_expanded_true():
    global data
    expanded = True
    result = parse_flow_sample(sample_data, expanded)
    expected = None
    eq_(result, expected)
    
def test_parse_flow_record_header():
    global data
    expanded = True
    result = parse_flow_record_header(data)
    expected = None
    eq_(result, expected)
    
def test_parse_counter_sample_expanded_true():
    assert True

def test_parse_counter_record_header():
    global data
    expanded = True
    result = parse_counter_record_header(data)
    expected = None
    eq_(result, expected)
    
def test_parse_counters_generic():
    assert True
    
def test_parse_counters_ethernet():
    global data
    expanded = True
    result = parse_counters_ethernet(data)
    expected = None
    eq_(result, expected)

def test_main():
    
    expected = {'sample_output_if_format': 1L, 'sample_sampling_rate': 1153957888L,
                'counter_ethernet_dot3_stats_SQETestErrors': 2004L, 'counter_ethernet_dot3_stats_InternalMacTransmitErrors': 0L,
                'counter_ethernet_dot3_stats_DeferredTransmissions': 72L, 'sample_sample_pool': 2005L,
                'sample_sequence_number': 2L, 'sample_source_id_index': 134227772L,
                'counter_ethernet_dot3_stats_FrameTooLongs': 0L, 'counter_ethernet_dot3_stats_FCSErrors': 0L,
                'sample_input_if_value': 3709258752L, 'counter_ethernet_dot3_stats_LateCollisions': 0L,
                'counter_ethernet_dot3_stats_CarrierSenseErrors': 695468032L, 'counter_ethernet_dot3_stats_InternalMacReceiveErrors': 0L,
                'sample_drops': 52L, 'sample_source_id_type': 1L,
                'counter_ethernet_dot3_stats_ExcessiveCollisions': 771215360L, 'sample_type': 'FLOW_SAMPLE',
                'counter_ethernet_dot3_stats_SymbolErrors': 0L, 'sample_output_if_value': 2407653376L,
                'counter_ethernet_dot3_stats_SingleCollisionFrames': 15437824L,
                'counter_ethernet_dot3_stats_MultipleCollisionFrames': 5084L, 'sample_input_if_format': 1L,
                'counter_ethernet_dot3_stats_AlignmentErrors': 2214L}

    eq_(EVENT, expected)
    eq_(EACH_EVENT, {})
  
    