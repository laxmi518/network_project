#!/usr/bin/env python

"""
Netflow Collecter.
It handles each of the netflow data, parses and unpack to retrieve the useful information
and sends them to the upper storage layer.
"""
import sys
import time
import datetime
import struct
#from gevent_zeromq import zmq
from pylib.wiring import gevent_zmq as zmq
import binascii

from gevent import socket
from dpkt import netflow
from libcol import config_reader
from pylib import conf, logger, wiring, msgfilling, inet
#import traceback

from proto import *

from field_type import *

log = logger.getLogger(__name__)

SIZE_OF_HEADER = 24   # Netflow v5 header size
SIZE_OF_RECORD = 48   # Netflow v5 record size
ONEDAY_SECOND = 86400 # 60 second * 60 minute * 24 hours
TIMELINE_PERIOD = 300 # 60 second * 5 minute

SIZE_OF_HEADER_9 = 20 # Netflow v9 header size
SIZE_OF_HEADER_IPFIX = 16 # Netflow IPFIX header size

FLOWSET_ID_V9_DATA_TEMPLATE = 0
FLOWSET_ID_V9_OPTIONS_TEMPLATE = 1
FLOWSET_ID_V10_DATA_TEMPLATE = 2
FLOWSET_ID_V10_OPTIONS_TEMPLATE = 3
FLOWSET_ID_RESERVED_MIN = 4
FLOWSET_ID_RESERVED_MAX = 255
FLOWSET_ID_DATA_MIN = 256
FLOWSET_ID_DATA_MAX = 65535

STOP = 0
VERSION = 0
netflowdata = None
config_ip = None

_filter_ipv4 = [8, 12, 15, 47, 130, 225, 226, 40001, 40002, 24632, 24633]
_filter_ipv6 = [27, 28, 62, 63, 131, 281, 282, 40057, 40058]

DEVICES = {}
TEMPLATE_CACHE = {}
DATA_CACHE = {}

IPFIX_DEVICES = {}
IPFIX_TEMPLATE_CACHE = {}
IPFIX_DATA_CACHE = {}

IPFIX_OPTION_TEMPLATE = {}
IPFIX_RECORD_LEN = {}       #{device_ip:{template_id: len}  //For ipfix
V9_RECORD_LEN = {}          #{device_ip:{template_id: len}  //For v9

def _parse_args():
    options, config = conf.parse_config()
    return config

def _get_sid(ip, config):
    sid = '%s|%s' % (config['col_type'], ip)
    return sid

def _handle_data(event, sid, netflow_out, device_name, col_type, ip, collected_at):
    netflow_out.start_benchmarker_processing()

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
    netflow_out.send_with_mid(event)

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

def get_template_field_value(template_template_list):
    '''
    template_dict = list of (key,val)  ==>    {template_id:[(field_type, length)]}
    '''
    template_dict = {}
    for template in template_template_list:
        temp_id = template[0]
        field_cnt = template[1]

        field_list = [] #dict of feild_types:length
        i = 0
        for field in xrange(field_cnt):
            field_type_temp = socket.ntohs(struct.unpack('H', template[2][4+i:6+i])[0])
            field_length_temp = socket.ntohs(struct.unpack('H', template[2][6+i:8+i])[0])
            field_list.append((field_type_temp, field_length_temp))
            i = i+4
        template_dict[temp_id] = field_list
    return template_dict


def get_data_length_data(data_header_list):
    data_dict = {}
    for each_data in data_header_list:
        key, length, data = each_data
        if key in data_dict:
            data_dict[key].append((length, data))
        else:
            val = []
            val.append((length, data))
            data_dict[key] = val
    return data_dict


def get_flow_count(version, device_ip, temp_id, each_data):
    length, data = each_data
    count = 1
    if version == 10:
        if device_ip in IPFIX_RECORD_LEN and temp_id in IPFIX_RECORD_LEN[device_ip]:
            count = int((length - 4)/ IPFIX_RECORD_LEN[device_ip][temp_id]) or 1
            #log.debug("total lengths key:%s length:%s:  count:%s--------", temp_id, length, count)
    elif version == 9:
        if device_ip in V9_RECORD_LEN and temp_id in V9_RECORD_LEN[device_ip]:
            count = int((length - 4)/ V9_RECORD_LEN[device_ip][temp_id]) or 1
            #log.debug("total lengths key:%s length:%s:  count:%s--------", temp_id, length, count)
    return count


def get_finalized_data_length_data(version, device_ip, temp_id, data_header_list):
    data_list = []
    for each_data in data_header_list:
        flow_count = 1
        flow_count = get_flow_count(version, device_ip, temp_id, each_data)

        length, data = each_data
        if flow_count == 1:
            #log.debug("Single flow set is obtained.")
            data_list.append((length, data))
        else:
            #log.debug("Number of flows here is --------- :%s ", flow_count)
            each_len = 0
            if version == 10:
                each_len = IPFIX_RECORD_LEN[device_ip][temp_id]
            elif version == 9:
                each_len = V9_RECORD_LEN[device_ip][temp_id]
            start, end = 0, each_len
            for cnt in xrange(flow_count):
                data_list.append((each_len, data[start:end]))
                start += each_len
                end += each_len
    return data_list


def update_record_len(version, device_ip, template_and_template):
    for temp_id, field_list in template_and_template.iteritems():
        total_len = 0
        for field, length in field_list:
            total_len += length

        if version == 9:
            if device_ip in V9_RECORD_LEN:
                V9_RECORD_LEN[device_ip].update({temp_id: total_len})
            else:
                V9_RECORD_LEN.update({device_ip: {temp_id: total_len}})
        elif version == 10:
            if device_ip in IPFIX_RECORD_LEN:
                IPFIX_RECORD_LEN[device_ip].update({temp_id: total_len})
            else:
                IPFIX_RECORD_LEN.update({device_ip: {temp_id: total_len}})

def update_template_cache(version, device_ip, template_template_list):
    TEMPLATE = TEMPLATE_CACHE
    if version == 10:
        TEMPLATE = IPFIX_TEMPLATE_CACHE
    template_and_template = get_template_field_value(template_template_list)
    #if version == 10:
    update_record_len(version, device_ip, template_and_template)     #for updating IPFIX_RECORD_LEN and v9_RECORD_LEN

    if device_ip in TEMPLATE:
        TEMPLATE[device_ip].update(template_and_template)
    else:
        TEMPLATE[device_ip] = template_and_template
    #log.debug("TEMPLATE : %s", TEMPLATE_CACHE)

def update_data_cache(version, device_ip, data_header_list):
    DATA = DATA_CACHE
    if version == 10:
        DATA = IPFIX_DATA_CACHE

    #data_and_data = get_data_length_data(version, device_ip, data_header_list)
    data_and_data = get_data_length_data(data_header_list)

    if device_ip in DATA:
        for key, val in data_and_data.iteritems():
            data_id = DATA[device_ip].get(key)
            if data_id:
                DATA[device_ip][key].extend(val)
            else:
                DATA[device_ip].update({key: val})
    else:
        DATA[device_ip] = data_and_data
    #log.debug("DATA : %s", DATA_CACHE)

def refresh_template_data_cache(version, device_ip):
    TEMPLATE = TEMPLATE_CACHE
    DATA = DATA_CACHE
    DEVICE = DEVICES
    if version == 10:
        TEMPLATE = IPFIX_TEMPLATE_CACHE
        DATA = IPFIX_DATA_CACHE
        DEVICE = IPFIX_DEVICES

    TEMPLATE[device_ip] = {}
    unparsed_data_info = DATA.pop(device_ip, None)
    DEVICE[device_ip] = int(time.time())
    return unparsed_data_info

def _handle_unparsed_raw_data(unparsed_data_info, sid, netflow_out, device_name, col_type, ip, collected_at):
    for template_id, data_list in unparsed_data_info.iteritems():
        unparsed_msg = {}
        unparsed_msg["template_id"] =  template_id
        unparsed_msg["msg_status"] = "unparsed"
        unparsed_msg["version"] = 9
        msgfilling.add_types(unparsed_msg, '_type_num', 'template_id version')
        msgfilling.add_types(unparsed_msg, '_type_str', 'msg_status')
        for length, datum in data_list:
            unparsed_msg["_p__raw_msg_b"] = binascii.b2a_base64(str(datum))
            _handle_data(unparsed_msg, sid, netflow_out, device_name, col_type, ip, collected_at)

def parse_template_data(version, ip):
    TEMPLATE = TEMPLATE_CACHE
    DATA = DATA_CACHE
    if version == 10:
        TEMPLATE = IPFIX_TEMPLATE_CACHE
        DATA = IPFIX_DATA_CACHE

    template_info = TEMPLATE.get(ip)
    data_info = DATA.get(ip)
    #log.debug("temlate : %s and data: %s", template_info, data_info)
    if not template_info:
        log.info("No any template flowset found till date.")
    elif not data_info:
        log.info("No any data flowset found till date.")
    else:
        data_dict = []
        final_data_info = dict(data_info)


        for template_id, temp_fields in template_info.iteritems():
            field_cnt = len(temp_fields)

            data_record_list = final_data_info.get(template_id)
            if not data_record_list:
                log.info("Corresponding data for template_id:%s  not found.", template_id)
                continue

            #if version == 10:
            #update data_record_list for that template_id for multiple flow in a single flowset of data
            data_record_list = get_finalized_data_length_data(version, ip, template_id, data_record_list)

            for record in data_record_list:
                record_len, single_data = record
                field_dict = {} #dict of field values
                i = 0
                for field in xrange(field_cnt):
                    field_type_temp, temp_len = temp_fields[field]
                    start = i
                    end = start + temp_len
                    i = i + temp_len
                    #log.debug("field_type: %s **********len is : %s", field_type_temp ,  temp_len)
                    if temp_len == 1:
                        val = ord(single_data[start])
                    elif temp_len == 2:
                        val = socket.ntohs(struct.unpack('H', single_data[start:end])[0])
                    elif temp_len == 4:
                        val = socket.ntohl(struct.unpack('I', single_data[start:end])[0])
                    elif temp_len == 8:
                        val = (struct.unpack('>Q', single_data[start:end])[0])
                    elif temp_len == 16:
                        val = socket.inet_ntop(socket.AF_INET6, single_data[start:end])
                    #log.debug(val)
                    field_dict[field_type_temp] = val

                _raw_data = single_data
                data_dict.append(({template_id : field_dict}, _raw_data))

            #log.debug("netflow_v9; data dict: %s", data_dict)
            #log.debug("netflow_v9; length data dict: %s", len(data_dict))
            if template_id in data_info:
                del DATA[ip][template_id]
            #log.debug("second : %s", DATA)
        return data_dict

def netflow_parser(version, data, count, expire_time, sid, netflow_out, device_name, col_type, device_ip, collected_at, msg_dict):
    #log.debug("device_ip : %s", device_ip)
    #log.debug("version: %s", version)

    unparsed_data_info = None
    DEVICE = DEVICES
    if version == 10:
        DEVICE = IPFIX_DEVICES
    if device_ip not in DEVICE:
        now = int(time.time())
        DEVICE[device_ip] = now
    else:
        '''check the expire time of templates'''
        template_start_time = DEVICE[device_ip]
        if int(time.time()) > (template_start_time + expire_time):
            log.info("Templates are expired; reinitializing templates")
            unparsed_data_info = refresh_template_data_cache(version, device_ip)

    if unparsed_data_info:
        log.info("Handling unparsed data")
        _handle_unparsed_raw_data(unparsed_data_info, sid, netflow_out, device_name, col_type, device_ip, collected_at)

    current_netflow = NewNetflow(version, data, count)
    # print_debug_logs(current_netflow)

    current_netflow.get_flowset_id_length_data(data, count)
    # print_debug_logs(current_netflow)

    current_netflow.template_data_analyzer(sid, netflow_out, device_name, col_type, device_ip, collected_at, msg_dict)
    # print_debug_logs(current_netflow)

    template_template_list = current_netflow.template_template_list
    data_header_list = current_netflow.data_header_list

    if len(template_template_list) > 0:
        update_template_cache(version, device_ip, template_template_list)

    if len(data_header_list) > 0:
        update_data_cache(version, device_ip, data_header_list)

    netflow_data = parse_template_data(version, device_ip)
    #log.debug("Current netflow data: %s", netflow_data)
    return netflow_data

def print_debug_logs(cls):
    log.debug("inside cls.length: %s", cls.length)
    log.debug("inside cls.data: %s", cls.data)
    log.debug("inside cls.count: %s", cls.count)
    log.debug("inside _raw_data: %s", cls._raw_data)
    log.debug("inside template_header_list: %s", cls.template_header_list)
    log.debug("inside data_header_list: %s", cls.data_header_list)
    log.debug("inside template_template_list: %s", cls.template_template_list)
    log.debug("inside template_data_dict: %s", cls.template_data_dict)
    log.debug("inside data_data_dict: %s", cls.data_data_dict)
    log.debug("just checking template flag: %s", cls.template_flag)

    my_netflow_data = [({300: {1: 64, 7: 4242}}, '\n\x00\x00\x02\n\x00')]
    return my_netflow_data

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

def msgfill_parsed_record(dd):
    #log.info("parsing  v9 records")
    global FIELDS
    global PROTO_DIC
    d = {}
    e = {}
    for (k, v) in dd.iteritems():
        #log.debug("********** %s ******* %s", k, v)
        if k in _filter_ipv4:
            #log.debug("#pack the ipv4")
            msgfilling.add_types(e, '_type_ip', FIELDS[k])
            msgfilling.add_types(e, '_type_str', FIELDS[k])
            d[k] = socket.inet_ntoa(struct.pack('!I',dd[k]))
        elif k in _filter_ipv6:
            #log.debug("#pace the ipv6")
            msgfilling.add_types(e, '_type_ip', FIELDS[k])
            msgfilling.add_types(e, '_type_str', FIELDS[k])
            d[k] = dd[k]
        else:
            #log.debug("leave as it is")
            d[k] = dd[k]
            if (k == 4):
                e['protocol_name'] = PROTO_DIC.get(d[k], "Unknown")
                msgfilling.add_types(e, '_type_str', "protocol_name")
            try:
                msgfilling.add_types(e, '_type_num', FIELDS[k])
            except:
                log.info("Fields not found in netflow_v9 field_type; Not filling msg_type")
                #msgfilling.add_types(e, '_type_num', "Unknown_field_"+str(k))
        try:
            e[FIELDS[k]] = d[k]
        except:
            log.info("Fields not found in netflow_v9 field_type; Not assigining values.")
            #e["Unknown_field_"+str(k)] = d[k]
    #log.debug("this is v9 parsed result %s", e)
    return e

class NewNetflow:
    def __init__(self, version, data, count):
        self.version = version
        self.data = data
        self.count = count

        self._raw_data = ''    #sting of the raw data from the dataflow set
        self.length = []         #length of each flow set

        self.flowset_id = []     #lsit of flowset id
        self.template_header_list = []   #contains flowset_id and length

        self.template_template_list = [] #contains template_id and field count
        self.data_header_list = []       #contains template_id and length of the data
        self.previous_data_header_list = []

        self.template_data_dict = {} #contains templateflow data as template_id:data
        self.data_data_dict = []     #contains dataflow data as template_id:data

        self.now = int(time.time())
        self.template_flag = False
        self.option_template_flag = False

    def get_flowset_id_length_data(self, data, count):
        total_len = len(data)
        skip_byte = SIZE_OF_HEADER_9
        if self.version == 10:
            skip_byte =  SIZE_OF_HEADER_IPFIX

        flow_data = data[skip_byte:]
        length = [0]
        offset = 0
        for flowset_num in xrange(count):
            flowset_id_temp = socket.ntohs(struct.unpack('H', flow_data[offset:offset+2])[0])
            self.flowset_id.append(flowset_id_temp)

            length_temp = socket.ntohs(struct.unpack('H', flow_data[offset+2:offset+4])[0])
            length.append(length_temp)

            # log.debug("flowset_id_temp: %s", flowset_id_temp)
            # log.debug("flowset_length: %s", length_temp)

            if length_temp != 0:
                flow_data_list_temp = flow_data[offset+0:offset+length_temp]
                self.template_header_list.append((flowset_id_temp, length_temp, flow_data_list_temp))
            
            offset += length_temp
            if (offset + skip_byte) > total_len:
                print "here :", offset + skip_byte
                del length[-1]
                del self.flowset_id[-1]
                del self.template_header_list[-1]
                break
            elif (offset + skip_byte) == total_len:
                break
            else:
                continue
        del length[0]
        self.length.append(length)
        # log.debug("Checking this : %s", self.template_header_list)


    def template_data_analyzer(self, sid, netflow_out, device_name, col_type, device_ip, collected_at, msg_dict):
        '''
        template_template_list = (300, 18, 'XXX')
        template_data_dict = {300: 'XXXX'}
        '''

        #log.debug("Analyzing whether it is template or not and setting flag")
        set_id = FLOWSET_ID_V9_DATA_TEMPLATE
        if self.version == 10:
            set_id = FLOWSET_ID_V10_DATA_TEMPLATE

        for header in self.template_header_list:
            each_data = header[2]

            if header[0] == FLOWSET_ID_V9_OPTIONS_TEMPLATE or header[0] == FLOWSET_ID_V10_OPTIONS_TEMPLATE:
                #log.debug("Inside ; this is v10 option template set")
                self.option_template_flag = True
                if header[1] > 6:
                    do = True
                    next_count = 0
                    while do:
                        this_flowset_length = socket.ntohs(struct.unpack('H', each_data[2+next_count:4+next_count])[0])
                        template_id = socket.ntohs(struct.unpack('H', each_data[4+next_count:6+next_count])[0])

                        if header[0] == FLOWSET_ID_V9_OPTIONS_TEMPLATE:
                            option_scope_length = socket.ntohs(struct.unpack('H', each_data[6+next_count:8+next_count])[0])
                            option_field_length = socket.ntohs(struct.unpack('H', each_data[8+next_count:10+next_count])[0])
                            total_field_count = int((option_scope_length + option_field_length) / 4)

                        elif header[0] == FLOWSET_ID_V10_OPTIONS_TEMPLATE:
                            total_field_count = socket.ntohs(struct.unpack('H', each_data[6+next_count:8+next_count])[0])
                            scope_field_count = socket.ntohs(struct.unpack('H', each_data[8+next_count:10+next_count])[0])

                        present_flag = False
                        for i in xrange(len(self.template_template_list)):
                            if template_id == self.template_template_list[i][0]:            #replace the template if template_id is repeated
                                present_flag = True
                                self.template_template_list[i] = (template_id, total_field_count, each_data[6:])
                                break
                        if not present_flag:
                            self.template_template_list.append((template_id, total_field_count, each_data[6:]))
                        self.template_data_dict[template_id] = each_data[6:] #removing flowset_id and length bytes

                        #log.debug("template_id: %s and total_field_count: %s", template_id, total_field_count)
                        skip_next_count = False
                        new_next_count = 0
                        if (self.template_template_list[-1][1] * 4 + 6 + 4) > (header[1]):
                            log.info("Invalid field count vs template data length; header_1: %s: temp_lsit:%s", header[1], self.template_template_list[-1])
                            del self.template_template_list[-1]
                            break
                        elif (self.template_template_list[-1][1] * 4 + 6 + 4) < (header[1]):
                            skip_next_count = True
                            skip_count = header[1] - 6
                        if skip_next_count:
                            next_count += skip_count
                        else:
                            next_count += (total_field_count * 2 * 2) + 6
                        if (next_count + 6) >= header[1]:
                            do = False

            elif header[0] == set_id:
                '''
                do the task of templates here
                '''
                #log.debug("Inside ; this is template set")
                self.template_flag = True
                if header[1] > 4:
                    do = True
                    next_count = 0
                    while do:

                        template_id = socket.ntohs(struct.unpack('H', each_data[4+next_count:6+next_count])[0])
                        field_count = socket.ntohs(struct.unpack('H', each_data[6+next_count:8+next_count])[0])
                        present_flag = False
                        for i in xrange(len(self.template_template_list)):
                            if template_id == self.template_template_list[i][0]:            #replace the template if template_id is repeated
                                present_flag = True
                                self.template_template_list[i] = (template_id, field_count, each_data[4:])
                                break
                        if not present_flag:
                            self.template_template_list.append((template_id, field_count, each_data[4:]))
                        self.template_data_dict[template_id] = each_data[4:] #removing flowset_id and length bytes

                        #self.template_template_list.append((2344, 4567, "\x00\x12\00"))

                        #log.debug("template_id: %s and field_count: %s", template_id, field_count)
                        skip_next_count = False
                        new_next_count = 0
                        if (self.template_template_list[-1][1] * 4 + 4 + 4) > (header[1]):
                            log.info("Invalid field count vs template data length; header_1: %s: temp_lsit:%s", header[1], self.template_template_list[-1])
                            del self.template_template_list[-1]
                            break
                        elif (self.template_template_list[-1][1] * 4 + 4 + 4) < (header[1]):
                            skip_next_count = True
                            skip_count = header[1] - 4
                        if skip_next_count:
                            next_count += skip_count
                        else:
                            next_count += (field_count * 2 * 2) + 4
                        if (next_count + 4) >= header[1]:
                            do = False

            else:
                '''
                do the task of data here
                '''
                template_id = header[0]
                data_length = socket.ntohs(struct.unpack('H', each_data[2:4])[0])
                self.data_header_list.append((template_id, data_length, each_data[4:]))
                #log.debug("Data header list is : %s", self.data_header_list)

        if self.template_flag:
            self._handle_template(sid, netflow_out, device_name, col_type, device_ip, collected_at, msg_dict, option_template=False)
        if self.option_template_flag:
            self._handle_template(sid, netflow_out, device_name, col_type, device_ip, collected_at, msg_dict, option_template=True)

    def _handle_template(self, sid, netflow_out, device_name, col_type, device_ip, collected_at, msg_dict, option_template):
        for (k, v) in self.template_data_dict.iteritems():
            _raw_msg_b = binascii.b2a_base64(self.template_data_dict[k])
            if option_template:
                packet_t = "option_template"
            else:
                packet_t = "template"
            event = dict(
                _p__raw_msg_b= _raw_msg_b,
                packet_type= packet_t,
                version= self.version,
                template_id= k,
                )
            event.update(msg_dict)
            msgfilling.add_types(event, '_type_str', 'packet_type')
            if self.version == 9:
                msgfilling.add_types(event, '_type_num', 'template_id version sys_uptime_ms package_sequence source_id unix_secs flowset_count' )
            elif self.version == 10:
                msgfilling.add_types(event, '_type_num', 'template_id version sys_uptime_ms package_sequence source_id flowset_length')
            _handle_data(event, sid, netflow_out, device_name, col_type, device_ip, collected_at)

# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0

def main():
    config = _parse_args()
    port = config['port']
    expire_time = config['expire_time']
    col_type = config['col_type']
    

    zmq_context = zmq.Context()

    netflow_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)

    sock = start_udp_server(port)

    netflow1 = netflow.Netflow1()
    netflow5 = netflow.Netflow5()
    netflow6 = netflow.Netflow6()
    netflow7 = netflow.Netflow7()

    while True:
        collected_at = config["loginspect_name"]
        
        data, addr = sock.recvfrom(9216)

        if not data:
            continue

        #log.debug('udp collector; from ip=%s, got msg=%s;', addr, data)

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

            elif (version == 9):
                log.info("version 9 unpacking...")
                VERSION = 9

                try:
                    '''
                    get the v9 data in dict
                    '''
                    #str_data = str(data)
                    #log.debug("v9 str data: %s", str(str_data))
                    # log.debug("v9 str data len: %s", len(str(data)))

                    #Other information in packet header
                    sys_uptime_ms = socket.ntohl(struct.unpack('I',data[4:8])[0])
                    unix_secs = socket.ntohl(struct.unpack('I',data[8:12])[0])
                    package_sequence = socket.ntohl(struct.unpack('I',data[12:16])[0])
                    source_id = socket.ntohl(struct.unpack('I',data[16:20])[0])

                    msg_dict = {}
                    msg_dict['version'] = VERSION
                    msg_dict['sys_uptime_ms'] = sys_uptime_ms
                    msg_dict['unix_secs'] = unix_secs
                    msg_dict['package_sequence'] = package_sequence
                    msg_dict['source_id'] = source_id
                    msg_dict['flowset_count'] = count

                    netflow_data_list_tuple = netflow_parser(version, data, count, expire_time, sid, netflow_out, device_name, col_type, ip, collected_at, msg_dict)

                    #log.debug("this is the returned aaaaaaa netflow_tuple: %s", netflow_data_list_tuple)

                    if netflow_data_list_tuple is not None and len(netflow_data_list_tuple) != 0:
                        for data_dict, _p__raw_msg_b in netflow_data_list_tuple:
                            #log.debug("Testing data dict: %s", data_dict)
                            ###parse record
                            for (k, v) in data_dict.iteritems():
                                try:
                                    parsed_msg_dict = msgfill_parsed_record(v)
                                except Exception, e:
                                    log.error("Could not msgfill the parsed v9 record; %s", repr(e))
                                parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(_p__raw_msg_b))
                                parsed_msg_dict['template_id'] = k

                                parsed_msg_dict.update(msg_dict)

                                msgfilling.add_types(parsed_msg_dict, '_type_num', 'template_id version sys_uptime_ms package_sequence source_id unix_secs flowset_count' )

                                _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)

                except Exception, e:
                    parsed_msg_dict = {}
                    parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(data))
                    parsed_msg_dict['version'] = VERSION
                    msgfilling.add_types(parsed_msg_dict, '_type_num', 'version')

                    _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)

                    log.warn("Error in constructing v9 message, Necessary field not supplied in Netflow; %s", repr(e))
                    log.warn(traceback.print_exc())

            elif (version == 10):
                log.info("version 10 unpacking...")
                VERSION = 10
                try:
                    '''
                    get the ipfix data in dict
                    '''

                    #Other information in packet header
                    sys_uptime_ms = socket.ntohl(struct.unpack('I',data[4:8])[0])
                    package_sequence = socket.ntohl(struct.unpack('I',data[8:12])[0])
                    source_id = socket.ntohl(struct.unpack('I',data[12:16])[0])

                    msg_dict = {}
                    msg_dict['version'] = VERSION
                    msg_dict['sys_uptime_ms'] = sys_uptime_ms
                    msg_dict['package_sequence'] = package_sequence
                    msg_dict['source_id'] = source_id
                    msg_dict['flowset_length'] = count
                    
                    netflow_data_list_tuple = netflow_parser(version, data, count, expire_time, sid, netflow_out, device_name, col_type, ip, collected_at, msg_dict)

                    if netflow_data_list_tuple is not None and len(netflow_data_list_tuple) != 0:
                        for data_dict, _p__raw_msg_b in netflow_data_list_tuple:
                            #log.debug("Testing data dict: %s", data_dict)
                            ###parse record
                            for (k, v) in data_dict.iteritems():
                                try:
                                    parsed_msg_dict = msgfill_parsed_record(v)
                                except Exception, e:
                                    log.error("Could not msgfill the parsed ipfix record; %s", repr(e))
                                parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(_p__raw_msg_b))
                                parsed_msg_dict['template_id'] = k

                                parsed_msg_dict.update(msg_dict)

                                msgfilling.add_types(parsed_msg_dict, '_type_num', 'template_id version flowset_length sys_uptime_ms package_sequence source_id')

                                _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)

                except Exception, e:
                    parsed_msg_dict = {}
                    parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(data))
                    parsed_msg_dict['version'] = VERSION
                    msgfilling.add_types(parsed_msg_dict, '_type_num', 'version')

                    _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)

                    log.warn("Error in constructing IPFIX message, Necessary field not supplied; %s", repr(e))
                    #log.warn(traceback.print_exc())
            else:
                log.error("Not the correct version type.")
        except Exception, e:
            log.error("Incorrect Netflow data format, %s", repr(e))
            #log.warn(traceback.print_exc())
    #main_end

if __name__ == '__main__':
    main()
