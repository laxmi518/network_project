"""
Netflow complatible with pypy
"""

import sys
import logging as log
import time
import socket
import struct
import binascii

from dpkt import netflow

import conf
import inet

from libcol import config_reader
from pylib import msgfilling

from proto import *
from netflow_field_type import *


sample_v5 = '\x00\x05\x00\x01\x01\xbd$\x1dP\xab-=\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\n\x00\x00\x02\n\x00\x00\x03\x00\x00\x00\x00\x00\x03\x00\x05\x00\x00\x00\x01\x00\x00\x00@\x01\xbc9\xbd\x01\xbd$\x1d\x10\x92\x00P\x00\x00\x11\x01\x00\x02\x00\x03 \x1f\x00\x00'

def _parse_args():
    options, config = conf.parse_config()
    return config


def _get_sid(ip, config):
    sid = '%s|%s' % (config['col_type'], ip)
    return sid


def _handle_data(event, sid, netflow_out, device_name, col_type, ip, collected_at):
    #netflow_out.start_benchmarker_processing()

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
    event['_to_preserve'] = dict(_p__raw_msg_b=event["_p__raw_msg_b"])
    del event['_p__raw_msg_b']
    
    msgfilling.add_types(event, '_type_str', 'msg col_type device_name collected_at')
    msgfilling.add_types(event, '_type_ip', 'device_ip')
    #msgfilling.add_types(event, '_type_str', '_raw_msg_b')
   # netflow_out.send_with_mid(event)
    #log.debug(event)


def start_udp_server(port):
    log.info("Netflow Collector; listening udp server at port %s", port)
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


def get_netflow_packet_version(version_header):
    return ord(version_header[1])


def parse_record(record):
    global PROTO_DIC
    d = {}
    d['interface_index'] = int(record.input_iface)
    d['source_address'] = socket.inet_ntoa(struct.pack('!L',record.src_addr))               #record[0:4]
    d['destination_address'] = socket.inet_ntoa(struct.pack('!L',record.dst_addr))        #record[4:8]
    d['packet_count'] = int(record.pkts_sent)                                           #record[16:20]
    d['bytes_count'] = int(record.bytes_sent)                                       #record[20:24])[0])
    d['start_uptime_ms'] = int(record.start_time)                                     #record[24:28])[0])
    d['end_uptime_ms'] = int(record.end_time)                                        #record[28:32])[0])
    d['source_port'] = int(record.src_port)                                       #record[32:34])[0])
    d['destination_port'] = int(record.dst_port)                                       #record[34:36])[0])
    protocol = int(record.ip_proto)                                    #record[38])
    d['types_of_service'] = int(record.tos)
    d['protocol_name'] = PROTO_DIC[protocol]
    
    msgfilling.add_types(d, '_type_str', "protocol_name source_address destination_address")
    msgfilling.add_types(d, '_type_ip', "source_address destination_address")
    msgfilling.add_types(d, '_type_num', "interface_index start_uptime_ms end_uptime_ms source_port destination_port packet_count bytes_count types_of_service")
    
    #log.debug("this is parsed result %s", d)
    return d


# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0


def main():
    config = _parse_args()
    #print config
    
    port = config['port']   
    expire_time = config['expire_time']
    col_type = config['col_type']
    collected_at = config["loginspect_name"]
    
    sock = start_udp_server(port)
    
    netflow1 = netflow.Netflow1()
    netflow5 = netflow.Netflow5()
    netflow6 = netflow.Netflow6()
    netflow7 = netflow.Netflow7()
            
    netflow_out = None
    COUNT = 0
    total_time = 0.0
    
    while True:
        data, addr = sock.recvfrom(9216)
        
        if not data:
            continue
        old_time = time.time()
        #log.debug('udp collector; from ip=%s, got msg=%s;', addr, data)
        #data = sample_v5
        
        ip = inet.get_ip(addr)
        config_ip = config_reader.get_config_ip(ip, config)
        if not config_ip:
            continue
        
        sid = _get_sid(config_ip, config)
        device_name = config['client_map'][config_ip]["device_name"]
        
        try:
            version = get_netflow_packet_version(data[0:2])
            count = socket.ntohs(struct.unpack('H',data[2:4])[0])
            current_unix_sec = socket.ntohl(struct.unpack('I',data[8:12])[0])
            
            global VERSION
            global netflowdata
            
            if ((version == 1) or (version == 5) or (version == 6) or (version == 7)):
                
                if version == 1:
                    log.info("version 1 unpacking...")
                    VERSION = 1
                    netflow1.unpack(data)
                    netflowdata = netflow1.data
                elif version == 5:
                    log.info("version 5 unpacking...")
                    VERSION = 5
                    netflow5.unpack(data)
                    netflowdata = netflow5.data
                elif version == 6:
                    log.info("version 6 unpacking...")
                    VERSION = 6
                    netflow6.unpack(data)
                    netflowdata = netflow6.data
                elif version == 7:
                    log.info("version 7 unpacking...")
                    VERSION = 7
                    netflow7.unpack(data)
                    netflowdata = netflow7.data
                    
                if not netflowdata:
                    continue
                
                for netflow_record in netflowdata:
                    try:                   
                        try:
                            parsed_msg_dict = parse_record(netflow_record)
                        except Exception, e:
                            log.error("Could not parse the given record. %s", repr(e))
                        parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(netflow_record))
                        parsed_msg_dict['version'] = VERSION
                        parsed_msg_dict['current_unix_sec'] = current_unix_sec
                        msgfilling.add_types(parsed_msg_dict, '_type_num', 'version current_unix_sec')
                        
                        _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)
                    except Exception,e:
                        log.error("Error in constructing message, Necessary field not supplied in Netflow")
                        log.error(repr(e))
                    
                COUNT += 1
                total_time += (time.time() - old_time)
                print COUNT, total_time
                if COUNT % 1000 == 0:
                    print "COUNT:", COUNT,  "SPEED", COUNT/total_time, "TOTAL_TIME", total_time
                    
                        
            else:
                log.error("Not the correct version type.")
        except Exception, e:
            log.error("Incorrect Netflow data format, %s", repr(e))
            #log.warn(traceback.print_exc())
    #main_end




if __name__ == '__main__':
    main()
