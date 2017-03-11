#!/usr/bin/env python

"""
Sflow Collecter.
It handles each of the sflow data, parses and unpack to retrieve the useful information
and sends them to the upper storage layer.
"""

from libcol.interface.collector import CollectorInterface
from libcol.interface.field_type import *


import sys
import time
from gevent import socket
import struct
import binascii

import logging as log
import traceback


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


class SflowCollector(CollectorInterface):
    
    def __init__(self, name):
        super(SflowCollector, self).__init__(name)
        
        self.data = None
        self.EVENT = {}  #dict of event 
        self.EACH_EVENT = {} #dict of each samples as global
        
    
    def handle_data(self, parsed_data, config):
        """
        Handle UDP data
        """
        parsed_data["msg"] = ""
        parsed_data['_to_preserve'] = dict(_p__raw_msg_b=parsed_data["_p__raw_msg_b"])
        del parsed_data['_p__raw_msg_b']
        self.add_event(parsed_data, config)

    
    def handle_udp_data(self, data, **config):
        sample_data = """\x00\x00\x00\x05\x00\x00\x00\x01\xc0\xa8\x02(\x00\x01\x86\xa0\x00\x00\x00\x0c\x00\x03\xa9\x80\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x01\x8c\x00\x00\x00\x0c\x02\x00\x00\x01\x00\x00\x00\x06\x00\x00\x07\xd1\x00\x00\x00$\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x01\x08\x00\'<D\xc8\x00\x00\x00\x00\x07\xd5\x00\x00\x004\x00\x00\x00\x01\xdd\x16\xcc\x00\x00\x00\x00\x01\x8f\x81\xe0\x00\x00\x00\x06f\x00\x00"\xc8\x00\x00\x00\x00\n\x89\x84\x00\x00\x104\xb0\x00\x00\x08\xa6\x00\x00\x00\x00\x00\xeb\x90\x00\x00\x00\x13\xdc\x00\x00\x07\xd4\x00\x00\x00H\x00\x00\x00\x00-\xf7\xd0\x00\x00\x00\x00\x00)t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe`\x00\x00\x00\x00\x00\x01\xc1 \x00\x00\x00\x00\x00\x18?\xe0\x00\x00\x00\x00\x00\x18?\xe0\x00\x00\x01\x0cD\x00\x00\x13\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd3\x00\x00\x00D\x00\x00\x00\x00<#\xd7\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00L\x00\x00\x00\x01\x00\x00\tf\x00\x00\x01M\x00\x00\x05\xa0\x00\x00\x00\x00\x00\x00\x12\x84\x00\x04\xde\x9a\x00\x00\x1e\x00\x00\x00\x00<\x00\x00\x00\x1e\x00\x002\xa2\x00\x00h\xea\x00\x00\x07\xd6\x00\x00\x00(\x00\x00\x00\x00\x00\x02Nx\x00\x00\x04\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x94\xa0\x00\x00\x00\x8c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\xd0\x00\x00\x00D\x00\x00\x00\tritubuntu\x00\x00\x00\x1fB+\x1f\xd5)N\x8b\x88\xce\xe8\x0eMV[\xa0\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x152.6.32-28-generic-pae\x00\x00\x00"""
        data = sample_data
        self.data = data
        try:
            _p__raw_msg_b = self.data
            # Datagram
            version = self.get_data32()
            address_type = self.get_data32()
            if address_type == Address_type['IPV4']:
                log.debug("IPV4 agent found.")
                address_type = 'IP_V4'
                ip_address = self.get_data32_addr()
            elif address_type == Address_type['IPV6']:
                address_type = 'IP_V6'
                ip_address = self.get_data128_addr()
            else:
                address_type = None
                ip_address = None
            
            sub_agent_id = self.get_data32()
            datagram_sequence_number = self.get_data32()
            switch_uptime = self.get_data32()   #in ms
            samples_count = self.get_data32()
            
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
            self.EVENT.clear()
            self.EACH_EVENT.clear()
            self.EVENT.update(datagram_dict)
            self.EACH_EVENT.update(datagram_dict)
            
            log.info("Version: %s", version)        
            
            # samples
            if version == Versions['VERSION5'] or address_type is not None:
                log.info("Version %s unpacking...", version)
                try:
                    for i in xrange(samples_count):
                        #log.debug("datagram samples : %s", i)
                        try:
                            self.parse_sample()      #Parse the obtained datagram
                        except Exception, e:
                            log.error("Unable to parse the data: %s", repr(e))
                        complete_event_dict = self._fill_msg_types(self.EVENT)
        
                        self.handle_data(complete_event_dict, config)
                        self.EVENT.clear()
                        self.EVENT.update(self.EACH_EVENT)
                except Exception, e:
                    log.error("Error in constructing sflow message, Necessary field not supplied in Sflow")
                    log.error(repr(e))
                    #log.warn(traceback.print_exc())
            else:
                #we donot accept this agent
                log.error("Datagram from Unknown agent: %s. Or incorrect version type.", address_type)                
                #log.warn(traceback.print_exc())
        except Exception, e:
            log.error("Incorrect Sflow data format, %s", repr(e))
            #log.warn(traceback.print_exc())
            

    def _is_valid_ipv4(self, address):
        #log.debug("checking ipv4 address: %s", address)
        address = str(address)
        try:
            addr = socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
        return True

    
    def _is_valid_ipv6(self, address):
        #log.debug("checking ipv6 address: %s", address)
        address = str(address)
        try:
            addr = socket.inet_pton(socket.AF_INET6, address)
        except socket.error: # not a valid address
            return False
        return True

    
    def _is_valid_num(self, s):
        try:
            float(s) # for int, long and float
        except ValueError:
            try:
                complex(s) # for complex
            except ValueError:
                return False
        return True

    
    def _fill_msg_types(self, ev):
        event = {"_normalized_fields": {}}
        for (k, v) in ev.iteritems():
            #log.debug("%s : %s ", k , v)
            if v and k is not "_p__raw_msg_b":
                if self._is_valid_ipv4(v) or self._is_valid_ipv6(v):
                    self.prepare_msgfilling(event, TYPE_IP, k)
                    self.prepare_msgfilling(event, TYPE_STR, k)
                elif self._is_valid_num(v):
                    self.prepare_msgfilling(event, TYPE_STR, k)
                else:    
                    self.prepare_msgfilling(event, TYPE_STR, k )

            if k is "_p__raw_msg_b":
                event[k] = v
            else:
                event["_normalized_fields"][k] = v
        log.debug("event: %s", event)
        return event
     
       
    """
    peek_data32() and 128() just read the data and do not move the pointer
    get_data32() and 128() read the data and also move the pointer
    skip_bytes() just moves the pointer to given length
    """
    
    def peek_data32(self):
        return socket.ntohl(struct.unpack('I',self.data[0:4])[0])
    
        
    def get_data32(self):
        raw_data = self.data
        self.data = raw_data[4:]
        return socket.ntohl(struct.unpack('I',raw_data[0:4])[0])
    
    
    def get_data32_addr(self):
        raw_data = self.data
        self.data = raw_data[4:]
        return socket.inet_ntoa(raw_data[0:4])  #struct.pack('!L',raw_data[0:4]))  
    
    
    def get_data64(self):
        raw_data = self.data
        self.data = raw_data[8:]
        return socket.ntohl(struct.unpack('L',raw_data[0:8])[0])
    
        
    def peek_data128(self):
        return socket.ntohl(struct.unpack('I',self.data[12:16])[0])
    
    
    def get_data128(self):
        raw_data = self.data
        self.skip_bytes(16)
        return socket.ntohl(struct.unpack('I',raw_data[12:16])[0])
    
    
    def get_data128_addr(self):
        raw_data = self.data
        self.skip_bytes(16)
        #return socket.ntohl(struct.unpack('!L',raw_data[12:16])[0])
        return socket.inet_ntop(socket.AF_INET6, raw_data[0:16])
    
    
    def skip_bytes(self, byte_len):
        raw_data = self.data
        self.data = raw_data[byte_len:]
    
        
    def parse_sample(self):
        raw_data = self.data
        sample_tag = self.get_data32()
        sample_length = self.get_data32()
        sample_data = self.data
        if sample_tag == Sample_tag['SFLFLOW_SAMPLE']:  # or sample_tag == Sample_tag['SFLFLOW_SAMPLE_EXPANDED']:
            self.parse_flow_sample(False)
        elif sample_tag == Sample_tag['SFLCOUNTERS_SAMPLE']: # or sample_tag==Sample_tag['SFLCOUNTERS_SAMPLE_EXPANDED']:
            self.parse_counter_sample(False)
        elif sample_tag == Sample_tag['SFLFLOW_SAMPLE_EXPANDED']:
            self.parse_flow_sample(True)   #True = expanded
        elif sample_tag == Sample_tag['SFLCOUNTERS_SAMPLE_EXPANDED']:
            self.parse_counter_sample(True)    #True = expanded
        else:
            # We dont know what it is, skip ahead to the next sample
            self.skip_bytes(sample_length)
    
    
    #flow samples     
    def parse_flow_sample(self, expanded):
        raw_data = self.data
        log.info("Unpacking flow sample...")
    
        s_sequence_number 	= self.get_data32()
        
        if expanded:
            s_ds_class = self.get_data32()
            s_ds_index = self.get_data32()
        else: 
            tmp = self.data
            s_ds_class = ord(tmp[0])
            s_ds_index = self.get_data32() & 0x00ffffff
    
        s_sampling_rate = self.get_data32()
        s_sample_pool = self.get_data32()
        s_drops = self.get_data32()
        
        if expanded:
            s_inputFormat = self.get_data32()
            s_input	= self.get_data32()
            s_outputFormat = self.get_data32()
            s_output = self.get_data32()
        else:
            tmp = self.get_data32()
            s_inputFormat = tmp >> 30
            s_input	= tmp & 0x3fffffff
            tmp = self.get_data32()
            s_outputFormat = tmp >> 30
            s_output = tmp & 0x3fffffff
    
        s_num_elements		= self.get_data32()
    
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
        self.EVENT.update(sample_dict)
        self.parse_flow_record_header()
        log.debug( "end of parse sample flow + extended.")
    
    
    def parse_flow_record_header(self):
        raw_data = self.data
        hdr_tag = self.get_data32()
        hdr_length = self.get_data32()
    
        if hdr_tag == SFLFlow_type_tag['SFLFLOW_HEADER']:
            try:
                self.parse_sampled_header()
            except:
                self.skip_bytes(hdr_length);
        else:
            # Skip ahead since we cant parse this record
            self.skip_bytes(hdr_length);
    
    
    def parse_sampled_header(self):
    
        hdr_header_protocol = self.get_data32()
        hdr_frame_length = self.get_data32()
        hdr_stripped = self.get_data32()
        hdr_header_length = self.get_data32()
        
        sample_raw_dict = dict(
            raw_header_protocol 	= SFLHeader_protocol[hdr_header_protocol],
            raw_header_frame_length = hdr_frame_length,
            raw_header_stripped 	= hdr_stripped,
            raw_header_length 		= hdr_header_length
        )
        self.EVENT.update(sample_raw_dict)
        # Allocate dynamic space for the raw header on the heap using the raw_header
        # pointer in the sample structure and copy the raw header
        
        #RAW_HEADER_SIZE ##yesko baarema thaha chaina aile
        
        # update the data pointer, we need to do this manually
        self.skip_bytes(hdr_header_length); 
    
    
    #counter samples
    def parse_counter_sample(self, expanded):
        raw_data = self.data
        log.info("Unpacking counter sample...")
        
        s_sequence_number = self.get_data32()
    
        if expanded:
                s_ds_class = self.get_data32()
                s_ds_index = self.get_data32()
        else:
                tmp = self.get_data32()
                s_ds_class = tmp >> 24
                s_ds_index = tmp & 0x00ffffff
                
        s_num_elements = self.get_data32()
        
        sample_dict = dict(
            sample_type = 'COUNTER_SAMPLE',
            sample_sequence_number = s_sequence_number,
            sample_source_id_type  = s_ds_class,
            sample_source_id_index = s_ds_index
        )
        self.EVENT.update(sample_dict)
    
        for i in range(s_num_elements):
            self.parse_counter_record_header();
    
                
    def parse_counter_record_header(self):
        raw_data = self.data
        hdr_tag 	= self.get_data32();
        hdr_length 	= self.get_data32();
        
        #log.debug("header tag: %s", hdr_tag)
        #log.debug("header length: %s", hdr_length)
        
        if hdr_tag == SFLCounters_type_tag['SFLCOUNTERS_GENERIC']:
            try:
                self.parse_counters_generic()
            except:
                self.skip_bytes(hdr_length)
        elif hdr_tag == SFLCounters_type_tag['SFLCOUNTERS_ETHERNET']:
            try:
                self.parse_counters_ethernet()
            except:
                self.skip_bytes(hdr_length)
        else:
            # We dont know about this record type yet 
            self.skip_bytes(hdr_length)
    
    
    def parse_counters_generic(self):
        raw_data = self.data
        counter_generic_dict = dict(
            counter_generic_if_index 			 = self.get_data32(),
            counter_generic_if_type 			 = self.get_data32(),
            counter_generic_if_speed 			 = self.get_data64(),
            counter_generic_if_direction 		 = Generic_ifDirection[self.get_data32()],
            counter_generic_if_if_status 		 = self.get_data32(),
            counter_generic_if_in_octets 		 = self.get_data64(),
            counter_generic_if_in_ucast_pkts 	 = self.get_data32(),
            counter_generic_if_in_mcast_pkts 	 = self.get_data32(),
            counter_generic_if_in_bcast_pkts 	 = self.get_data32(),
            counter_generic_if_in_discards 		 = self.get_data32(),
            counter_generic_if_in_errors 		 = self.get_data32(),
            counter_generic_if_in_unknown_proto  = self.get_data32(),
            counter_generic_if_out_octets 		 = self.get_data64(),
            counter_generic_if_out_ucast_pkts 	 = self.get_data32(),
            counter_generic_if_out_mcast_pkts 	 = self.get_data32(),
            counter_generic_if_out_bcast_pkts 	 = self.get_data32(),
            counter_generic_if_out_discards 	 = self.get_data32(),
            counter_generic_if_out_errors 		 = self.get_data32(),
            counter_generic_if_promisc 			 = self.get_data32()
        )
        self.EVENT.update(counter_generic_dict)
    
    
    def parse_counters_ethernet(self):
        raw_data = self.data
        counter_ethernet_dict = dict(
            counter_ethernet_dot3_stats_AlignmentErrors 			= self.get_data32(),
            counter_ethernet_dot3_stats_FCSErrors 					= self.get_data32(),
            counter_ethernet_dot3_stats_SingleCollisionFrames 		= self.get_data32(),
            counter_ethernet_dot3_stats_MultipleCollisionFrames 	= self.get_data32(),
            counter_ethernet_dot3_stats_SQETestErrors 				= self.get_data32(),
            counter_ethernet_dot3_stats_DeferredTransmissions 		= self.get_data32(),
            counter_ethernet_dot3_stats_LateCollisions 				= self.get_data32(),
            counter_ethernet_dot3_stats_ExcessiveCollisions 		= self.get_data32(),
            counter_ethernet_dot3_stats_InternalMacTransmitErrors 	= self.get_data32(),
            counter_ethernet_dot3_stats_CarrierSenseErrors 			= self.get_data32(),
            counter_ethernet_dot3_stats_FrameTooLongs 				= self.get_data32(),
            counter_ethernet_dot3_stats_InternalMacReceiveErrors 	= self.get_data32(),
            counter_ethernet_dot3_stats_SymbolErrors 				= self.get_data32()
        )
        self.EVENT.update(counter_ethernet_dict)



if __name__ == '__main__':
    sflow_col = SflowCollector("sflow")
    sflow_col.turn_udp_server_on()
    sflow_col.start()


