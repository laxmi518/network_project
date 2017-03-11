#!/usr/bin/env python

"""
Sflow Collecter.
It handles each of the sflow data, parses and unpack to retrieve the useful information
and sends them to the upper storage layer.
"""
import sys
import time
from gevent import socket
import struct
import binascii

from pylib.wiring import gevent_zmq as zmq
from libcol import config_reader
from pylib import conf, logger, wiring, msgfilling, inet


log = logger.getLogger(__name__)

data = None         #

SIZE_OF_HEADER = 24   # Sflow v5 header size
SIZE_OF_RECORD = 48   # Sflow v5 record size

RAW_HEADER_SIZE  = 128

# The header protocol describes the format of the sampled header 
SFLHeader_protocol = {
    1 : 'SFLHEADER_ETHERNET_ISO8023',
    2 : 'SFLHEADER_ISO88024_TOKENBUS',
    3 : 'SFLHEADER_ISO88025_TOKENRING',
    4 : 'SFLHEADER_FDDI',
    5 : 'SFLHEADER_FRAME_RELAY',
    6 : 'SFLHEADER_X25',
    7 : 'SFLHEADER_PPP',
    8 : 'SFLHEADER_SMDS',
    9 : 'SFLHEADER_AAL5',
    10 : 'SFLHEADER_AAL5_IP', #/* e.g. Cisco AAL5 mux */
    11 : 'SFLHEADER_IPv4',
    12 : 'SFLHEADER_IPv6',
    13 : 'SFLHEADER_MPLS'
}

Generic_ifDirection = {
    0: 'Unknown',
    1: 'Full-Duplex',
    2: 'Half-Duplex',
    3: 'In',
    4: 'Out'
}

Versions = dict(VERSION2 = 2, VERSION4 = 4, VERSION5 = 5)
Address_type = dict(IPV4 = 1, IPV6 = 2)
Sample_tag = dict(
    SFLFLOW_SAMPLE = 1,              # enterprise = 0 : format = 1 
    SFLCOUNTERS_SAMPLE = 2,          # enterprise = 0 : format = 2 
    SFLFLOW_SAMPLE_EXPANDED = 3,     # enterprise = 0 : format = 3 
    SFLCOUNTERS_SAMPLE_EXPANDED = 4  # enterprise = 0 : format = 4 
)

SFLFlow_type_tag = dict(
    #/* enterprise = 0, format = ... */
    SFLFLOW_HEADER    = 1,      #/* Packet headers are sampled */
    SFLFLOW_ETHERNET  = 2,      #/* MAC layer information */
    SFLFLOW_IPV4      = 3,      #/* IP version 4 data */
    SFLFLOW_IPV6      = 4,      #/* IP version 6 data */
    SFLFLOW_EX_SWITCH    = 1001,      #/* Extended switch information */
    SFLFLOW_EX_ROUTER    = 1002,      #/* Extended router information */
    SFLFLOW_EX_GATEWAY   = 1003,      #/* Extended gateway router information */
    SFLFLOW_EX_USER      = 1004,      #/* Extended TACAS/RADIUS user information */
    SFLFLOW_EX_URL       = 1005,      #/* Extended URL information */
    SFLFLOW_EX_MPLS      = 1006,      #/* Extended MPLS information */
    SFLFLOW_EX_NAT       = 1007,      #/* Extended NAT information */
    SFLFLOW_EX_MPLS_TUNNEL  = 1008,   #/* additional MPLS information */
    SFLFLOW_EX_MPLS_VC      = 1009,
    SFLFLOW_EX_MPLS_FTN     = 1010,
    SFLFLOW_EX_MPLS_LDP_FEC = 1011,
    SFLFLOW_EX_VLAN_TUNNEL  = 1012,   #/* VLAN stack */
    #/* enterprise = 4300 (inmon)...*/
    SFLFLOW_EX_PROCESS   = (4300 << 12) + 3 #/* =17612803 Extended Process information */
)

#/* Counters data */
SFLCounters_type_tag = dict(
    #/* enterprise = 0, format = ... */
    SFLCOUNTERS_GENERIC      = 1,
    SFLCOUNTERS_ETHERNET     = 2,
    SFLCOUNTERS_TOKENRING    = 3,
    SFLCOUNTERS_VG           = 4,
    SFLCOUNTERS_VLAN         = 5,
    SFLCOUNTERS_PROCESSOR    = 1001
)

STOP = 0
VERSION = 0
sflowdata = None


def _parse_args():
    options, config = conf.parse_config()
    return config


def _get_sid(ip, config):
    sid = '%s|%s' % (config['col_type'], ip)
    return sid


def _handle_data(event, sid, sflow_out, device_name, col_type, ip, collected_at):
    sflow_out.start_benchmarker_processing()

    global LAST_COL_TS
    global LOG_COUNTER

    col_ts = int(time.time())
    if col_ts > LAST_COL_TS:
        LAST_COL_TS = col_ts
        LOG_COUNTER = 0

    mid_prefix = '%s|%s|%s|' % (collected_at, sid, col_ts)
    LOG_COUNTER += 1
    event['mid'] = mid_prefix + "%d" % LOG_COUNTER
    event['device_name'] = device_name
    event['col_type'] = col_type
    event['msg'] = ''
    event['device_ip'] = ip
    event['collected_at'] = collected_at
    event["_to_preserve"] = dict(_p__raw_msg_b = event["_p__raw_msg_b"])
    del event['_p__raw_msg_b']
    
    #msgfilling.add_types(event, '_type_str', '_p__raw_msg_b')
    msgfilling.add_types(event, '_type_str', 'msg col_type device_name collected_at')
    msgfilling.add_types(event, '_type_num', 'version')
    msgfilling.add_types(event, '_type_ip', 'device_ip')
    sflow_out.send_with_mid(event)


def start_udp_server(port):
    log.info("sflow Collector; listening udp server at port: %s", port)
    try:
        sock, sockaddr = inet.create_external_address(port, socket.SOCK_DGRAM, use_gevent=True)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Asking for 8MB for receive buffer.
        if not sys.platform == 'darwin':
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608) 
        sock.bind(sockaddr)
        return sock
    except Exception,e:
        log.error('Error while binding udp connection to address: %s\n%s', port, repr(e))
        raise


def _is_valid_ipv4(address):
    log.debug("checking ipv4 address: %s", address)
    address = str(address)
    try:
        addr = socket.inet_aton(address)
    except socket.error:
        return False
    return address.count('.') == 3
    return True

def _is_valid_ipv6(address):
    log.debug("checking ipv6 address: %s", address)
    address = str(address)
    try:
        addr = socket.inet_pton(socket.AF_INET6, address)
    except socket.error: # not a valid address
        return False
    return True

def _is_valid_num(s):
    try:
        float(s) # for int, long and float
    except ValueError:
        try:
            complex(s) # for complex
        except ValueError:
            return False
    return True

def _fill_msg_types(d):
    event = {}
    for (k, v) in d.iteritems():
        log.debug("%s : %s ", k , v)
        if v and k is not "_p__raw_msg_b":
            if _is_valid_ipv4(v) or _is_valid_ipv6(v):
                msgfilling.add_types(event, '_type_ip', k)
                msgfilling.add_types(event, '_type_str', k)
            elif _is_valid_num(v):
                msgfilling.add_types(event, '_type_num', k)
            else:    
                msgfilling.add_types(event, '_type_str', k )    
        event[k] = v
    log.debug("event: %s", event)
    return event
 
   
"""
peek_data32() and 128() just read the data and do not move the pointer
get_data32() and 128() read the data and also move the pointer
skip_bytes() just moves the pointer to given length
"""
def peek_data32(raw_data):
    return socket.ntohl(struct.unpack('I',raw_data[0:4])[0])
    
def get_data32(raw_data):
    global data
    data = raw_data[4:]
    return socket.ntohl(struct.unpack('I',raw_data[0:4])[0])

def get_data32_addr(raw_data):
    global data
    data = raw_data[4:]
    #return socket.ntohl(struct.unpack('!L',raw_data[0:4])[0])
    return socket.inet_ntoa(raw_data[0:4])  #struct.pack('!L',raw_data[0:4]))  

def get_data64(raw_data):
    global data
    data = raw_data[8:]
    return socket.ntohl(struct.unpack('L',raw_data[0:8])[0])
    
def peek_data128(raw_data):
    return socket.ntohl(struct.unpack('I',raw_data[12:16])[0])

def get_data128(raw_data):
    global data
    data = raw_data
    skip_bytes(data, 16)
    return socket.ntohl(struct.unpack('I',raw_data[12:16])[0])

def get_data128_addr(raw_data):
    global data
    data = raw_data
    skip_bytes(data, 16)
    #return socket.ntohl(struct.unpack('!L',raw_data[12:16])[0])
    return socket.inet_ntop(socket.AF_INET6, raw_data[0:16])

def skip_bytes(raw_data, byte_len):
    global data
    data = raw_data[byte_len:]

    
def parse_sample(raw_data):
    global data
    data = raw_data
    sample_tag = get_data32(data)
    sample_length = get_data32(data)
    sample_data = data
    if sample_tag == Sample_tag['SFLFLOW_SAMPLE']:  # or sample_tag == Sample_tag['SFLFLOW_SAMPLE_EXPANDED']:
        parse_flow_sample(data, False)
    elif sample_tag == Sample_tag['SFLCOUNTERS_SAMPLE']: # or sample_tag==Sample_tag['SFLCOUNTERS_SAMPLE_EXPANDED']:
        parse_counter_sample(data, False)
    elif sample_tag == Sample_tag['SFLFLOW_SAMPLE_EXPANDED']:
        parse_flow_sample(data, True)   #True = expanded
    elif sample_tag == Sample_tag['SFLCOUNTERS_SAMPLE_EXPANDED']:
        parse_counter_sample(data, True)    #True = expanded
    else:
        # We dont know what it is, skip ahead to the next sample
        skip_bytes(data, sample_length)

#flow samples     
def parse_flow_sample(raw_data, expanded):
    global data
    log.info("Unpacking flow sample...")

    s_sequence_number 	= get_data32(data)
    
    if expanded:
        s_ds_class = get_data32(data)
        s_ds_index = get_data32(data)
    else: 
        tmp = data
        s_ds_class = ord(tmp[0])
        s_ds_index = get_data32(data) & 0x00ffffff

    s_sampling_rate = get_data32(data)
    s_sample_pool = get_data32(data)
    s_drops = get_data32(data)
    
    if expanded:
        s_inputFormat = get_data32(data)
        s_input	= get_data32(data)
        s_outputFormat = get_data32(data)
        s_output = get_data32(data)
    else:
        tmp = get_data32(data)
        s_inputFormat = tmp >> 30
        s_input	= tmp & 0x3fffffff
        tmp = get_data32(data)
        s_outputFormat = tmp >> 30
        s_output = tmp & 0x3fffffff

    s_num_elements		= get_data32(data);

    sample_dict = dict(
        sample_type = 'FLOW_SAMPLE',
        sample_sequence_number	= s_sequence_number,
        sample_source_id_type 	= s_ds_class,
        sample_source_id_index 	= s_ds_index,
        sample_sampling_rate 	= s_sampling_rate,
        sample_sample_pool		= s_sample_pool,
        sample_drops			= s_drops,
        sample_input_if_format	= s_inputFormat,
        sample_input_if_value	= s_input,
        sample_output_if_format	= s_outputFormat,
        sample_output_if_value	= s_output
    )
    EVENT.update(sample_dict)
    parse_flow_record_header(data)
    log.debug( "end of parse sample flow + extended.")

def parse_flow_record_header(raw_data):
    global data
    hdr_tag = get_data32(data)
    hdr_length = get_data32(data)

    if hdr_tag == SFLFlow_type_tag['SFLFLOW_HEADER']:
        try:
            parse_sampled_header(data)
        except:
            skip_bytes(data, hdr_length);
    else:
        # Skip ahead since we cant parse this record
        skip_bytes(data, hdr_length);

def parse_sampled_header(raw_data):

    hdr_header_protocol = get_data32(data)
    hdr_frame_length = get_data32(data)
    hdr_stripped = get_data32(data)
    hdr_header_length = get_data32(data)
    
    sample_raw_dict = dict(
        raw_header_protocol 	= SFLHeader_protocol[hdr_header_protocol],
        raw_header_frame_length = hdr_frame_length,
        raw_header_stripped 	= hdr_stripped,
        raw_header_length 		= hdr_header_length
    )
    EVENT.update(sample_raw_dict)
    # Allocate dynamic space for the raw header on the heap using the raw_header
    # pointer in the sample structure and copy the raw header
    
    #RAW_HEADER_SIZE ##yesko baarema thaha chaina aile
    
    # update the data pointer, we need to do this manually
    skip_bytes(data, hdr_header_length); 

#counter samples
def parse_counter_sample(raw_data, expanded):
    global data
    log.info("Unpacking counter sample...")
    
    s_sequence_number = get_data32(data);

    if expanded:
            s_ds_class = get_data32(data);
            s_ds_index = get_data32(data);
    else:
            tmp = get_data32(data);
            s_ds_class = tmp >> 24;
            s_ds_index = tmp & 0x00ffffff;
            
    s_num_elements = get_data32(data);
    
    sample_dict = dict(
        sample_type = 'COUNTER_SAMPLE',
        sample_sequence_number = s_sequence_number,
        sample_source_id_type  = s_ds_class,
        sample_source_id_index = s_ds_index
    )
    EVENT.update(sample_dict)

    for i in range(s_num_elements):
        parse_counter_record_header(data);
            
def parse_counter_record_header(raw_data):
    global data
    data = raw_data
    hdr_tag 	= get_data32(data);
    hdr_length 	= get_data32(data);
    
    log.debug("header tag: %s", hdr_tag)
    log.debug("header length: %s", hdr_length)
    
    if hdr_tag == SFLCounters_type_tag['SFLCOUNTERS_GENERIC']:
        try:
            parse_counters_generic(data)
        except:
            skip_bytes(data, hdr_length)
    elif hdr_tag == SFLCounters_type_tag['SFLCOUNTERS_ETHERNET']:
        try:
            parse_counters_ethernet(data)
        except:
            skip_bytes(data, hdr_length)
    else:
        # We dont know about this record type yet 
        skip_bytes(data, hdr_length)

def parse_counters_generic(raw_data):
    global data
    counter_generic_dict = dict(
        counter_generic_if_index 			 = get_data32(data),
        counter_generic_if_type 			 = get_data32(data),
        counter_generic_if_speed 			 = get_data64(data),
        counter_generic_if_direction 		 = Generic_ifDirection[get_data32(data)],
        counter_generic_if_if_status 		 = get_data32(data),
        counter_generic_if_in_octets 		 = get_data64(data),
        counter_generic_if_in_ucast_pkts 	 = get_data32(data),
        counter_generic_if_in_mcast_pkts 	 = get_data32(data),
        counter_generic_if_in_bcast_pkts 	 = get_data32(data),
        counter_generic_if_in_discards 		 = get_data32(data),
        counter_generic_if_in_errors 		 = get_data32(data),
        counter_generic_if_in_unknown_proto  = get_data32(data),
        counter_generic_if_out_octets 		 = get_data64(data),
        counter_generic_if_out_ucast_pkts 	 = get_data32(data),
        counter_generic_if_out_mcast_pkts 	 = get_data32(data),
        counter_generic_if_out_bcast_pkts 	 = get_data32(data),
        counter_generic_if_out_discards 	 = get_data32(data),
        counter_generic_if_out_errors 		 = get_data32(data),
        counter_generic_if_promisc 			 = get_data32(data)
    )
    EVENT.update(counter_generic_dict)

def parse_counters_ethernet(raw_data):
    global data
    counter_ethernet_dict = dict(
        counter_ethernet_dot3_stats_AlignmentErrors 			= get_data32(data),
        counter_ethernet_dot3_stats_FCSErrors 					= get_data32(data),
        counter_ethernet_dot3_stats_SingleCollisionFrames 		= get_data32(data),
        counter_ethernet_dot3_stats_MultipleCollisionFrames 	= get_data32(data),
        counter_ethernet_dot3_stats_SQETestErrors 				= get_data32(data),
        counter_ethernet_dot3_stats_DeferredTransmissions 		= get_data32(data),
        counter_ethernet_dot3_stats_LateCollisions 				= get_data32(data),
        counter_ethernet_dot3_stats_ExcessiveCollisions 		= get_data32(data),
        counter_ethernet_dot3_stats_InternalMacTransmitErrors 	= get_data32(data),
        counter_ethernet_dot3_stats_CarrierSenseErrors 			= get_data32(data),
        counter_ethernet_dot3_stats_FrameTooLongs 				= get_data32(data),
        counter_ethernet_dot3_stats_InternalMacReceiveErrors 	= get_data32(data),
        counter_ethernet_dot3_stats_SymbolErrors 				= get_data32(data)
    )
    EVENT.update(counter_ethernet_dict)

               
# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0
EVENT = {}  #dict of event 
EACH_EVENT = {} #dict of each samples as global

def main():
    #print "This is my sflow_collector 1 ."
    log.debug("Started.")    
    config = _parse_args()
    log_level = config['core']['log_level']
    port = config['port']   
    log.debug("This is log level set to %s.", log_level)
    col_type = config['col_type']
    log.debug("Col_type : %s", col_type)
    
    zmq_context = zmq.Context()
    sflow_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)  
    sock = start_udp_server(port)

    while True:
        global data
        data, addr = sock.recvfrom(9216)
        log.info("data: %s, addr: %s", data, addr)
        if not data:
            log.debug("no data")
            continue
        
        ip = inet.get_ip(addr)
        config_ip = config_reader.get_config_ip(ip, config)
        if not config_ip:
            continue
        
        try:
            _p__raw_msg_b = data
            # Datagram
            version = get_data32(data)
            address_type = get_data32(data)
            if address_type == Address_type['IPV4']:
                log.debug("IPV4 agent found.")
                address_type = 'IP_V4'
                ip_address = get_data32_addr(data)
            elif address_type == Address_type['IPV6']:
                address_type = 'IP_V6'
                ip_address = get_data128_addr(data)
            else:
                address_type = None
            
            sub_agent_id = get_data32(data)
            datagram_sequence_number = get_data32(data)
            switch_uptime = get_data32(data)   #in ms
            samples_count = get_data32(data)
            
            datagram_dict = dict(
                _p__raw_msg_b = binascii.b2a_base64(str(_p__raw_msg_b)),
                version = version,
                address_type = address_type,
                ip_address = ip_address,
                sub_agent_id = sub_agent_id,
                datagram_sequence_number = datagram_sequence_number,
                switch_uptime = switch_uptime,
                samples_count = samples_count
                )
            EVENT.clear()
            EACH_EVENT.clear()
            EVENT.update(datagram_dict)
            EACH_EVENT.update(datagram_dict)
            
            log.info("Version: %s", version)        
            
            # samples
            if version == Versions['VERSION5'] or address_type is not None:
                log.info("Version %s unpacking...", version)
                try:
                    for i in range(samples_count):
                        log.debug("datagram samples : %s", i)
                        try:
                            parse_sample(data)      #Parse the obtained datagram
                        except Exception, e:
                            log.error("Unable to parse the data: %s", repr(e))
                        complete_event_dict = _fill_msg_types(EVENT)
        
                        sid = _get_sid(config_ip, config)
                        device_name = config['client_map'][config_ip]["device_name"]
                        collected_at = config["loginspect_name"]
                        _handle_data(complete_event_dict, sid, sflow_out, device_name, col_type, ip, collected_at)
                        EVENT.clear()
                        EVENT.update(EACH_EVENT)
                except Exception, e:
                    log.error("Error in constructing sflow message, Necessary field not supplied in Sflow")
                    log.error(repr(e))
            else:
                #we donot accept this agent
                log.error("Datagram from Unknown agent: %s. Or incorrect version type.", address_type)                
        except Exception, e:
            log.error("Incorrect Sflow data format, %s", repr(e))
            
    #main_end

if __name__ == '__main__':
    main()

