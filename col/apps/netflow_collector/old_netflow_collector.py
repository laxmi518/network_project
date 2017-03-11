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

STOP = 0
VERSION = 0
netflowdata = None
config_ip = None
_filter_ipv4 = [8, 12, 15, 47, 225, 226, 40001, 40002]
_filter_ipv6 = [27, 28, 62, 63, 281, 282, 40057, 40058]

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


def _netflow9(data, count, expire_time, sid, netflow_out, device_name, col_type, device_ip, collected_at):
    global device_ip_list
    global new_netflow_v9
    netflow_data_raw = []
    
    log.debug("device ip :%s", device_ip)
    total_len = len(data)
    log.debug("full length :%s", total_len)
    if device_ip not in device_ip_list:
        device_ip_list.append(device_ip)
        new_netflow_v9[device_ip] = _New_Netflow_v9(data, count)
        log.info("Object creation for v9 under certain ip:  %s", new_netflow_v9[device_ip])
        
    #log.debug("Object of total netflows:  %s", new_netflow_v9)
    
    '''check the expire time of templates'''
    template_start_time = new_netflow_v9[device_ip].now
    if int(time.time()) > (template_start_time + expire_time):
        log.info("Templates are expired; reinitializing templates")
        new_netflow_v9[device_ip] = _New_Netflow_v9(data, count)
    
    previous_data_header_list = new_netflow_v9[device_ip].previous_data_header_list
    log.info("Getting flowset headers")
    new_netflow_v9[device_ip].get_flowset_id_length_data(data, count)
    
    try:
        log.info("Getting templates' and data's headers and raw data.")
        new_netflow_v9[device_ip].get_raw_template_dict_raw_data_dict(sid, netflow_out, device_name, col_type, device_ip, collected_at)
                
        unparsed_raw_data = new_netflow_v9[device_ip].unparsed_raw_data
        #log.debug("Object of total unparsed_raw_data: %s", unparsed_raw_data)
        if len(unparsed_raw_data) != 0:
            netflow_data_raw.extend(unparsed_raw_data)
            log.debug("Cleaning unparsed raw data.")
            new_netflow_v9[device_ip].clean_unparsed_raw_data()
    except Exception, err:
        new_netflow_v9[device_ip] = _New_Netflow_v9(data, count)
        log.warn("Cannot create the template and data lists and dict : %s", repr(err))
        #traceback.print_exc()
        return "Warning"
    
    log.debug("***************After after updating lists********************")
    new_netflow_v9[device_ip].update_template_data_list_dict()
    #log.debug("Final template_template_list:  %s", new_netflow_v9[device_ip].template_template_list)
    #log.debug("Final total data_header_list:  %s", new_netflow_v9[device_ip].data_header_list)
    
    flow_data = data[SIZE_OF_HEADER_9:]
    
    #flowset header
    flowset_id = socket.ntohs(struct.unpack('H', flow_data[0:2])[0])
    length1 = socket.ntohs(struct.unpack('H', flow_data[2:4])[0]) 
            
    '''
    template_dict = list of (key,val)  ==>    {template_id:[(field_type, length)]}
    '''
    
    template_template_list = new_netflow_v9[device_ip].template_template_list
    template_data_dict = new_netflow_v9[device_ip].template_data_dict
    data_header_list = new_netflow_v9[device_ip].data_header_list
    data_data_dict = new_netflow_v9[device_ip].data_data_dict
    
    temp_data_header_list = data_header_list
    
    #log.debug("previous_data :%s :%s\n ", (data_header_list), (previous_data_header_list))
    for item in previous_data_header_list:
        if item in data_header_list:
            data_header_list.remove(item)
    
    all_data_dict = []
    temp_data_dict = {}
    isParsed = False
    template_data_dict_encoded = {}
    if len(template_template_list) == 0:
        log.info("No any templetes flowset found till date. ")
    else:
        template_dict = {}
        for record in range(len(template_template_list)):
            if template_template_list[record][0] in [id[0] for id in data_header_list]:
                temp_id = template_template_list[record][0]
                field_cnt = template_template_list[record][1]
                #log.debug("Template Flowset; Matched data and template id: %s", temp_id)
             
                field_list = [] #dict of feild_types:length
                i = 0
                for field in range(0,field_cnt):            
                    field_type_temp = socket.ntohs(struct.unpack('H', template_data_dict[temp_id][4+i:6+i])[0])
                    field_length_temp = socket.ntohs(struct.unpack('H', template_data_dict[temp_id][6+i:8+i])[0])
                    
                    field_list.append((field_type_temp, field_length_temp))
                    i = i+4
                template_dict[temp_id] = field_list
                #log.debug("This is template dict: %s", template_dict)
        '''
        data_dict = dict of (key,val)  ==>    {template_id:{field_type: field_val}}  
        '''
        if len(data_header_list) == 0:
            log.info("No any data flowset found till date.") 
        else:
            for temp_data in template_data_dict:
                template_data_dict_encoded[temp_data] = binascii.b2a_base64(template_data_dict[temp_data])
            data_dict = []
            for template_num in xrange(len(template_dict)):
                for record in range(len(data_header_list)):
                    temp_id = data_header_list[record][0]
                    if template_dict.keys()[template_num] == temp_id:
                        try:
                            field_cnt = len(template_dict[temp_id]) #her is some error
                            #log.debug("Data Flowset; matched data and template id: %s", temp_id)
                        except Exception,err:
                            log.info("Corresponding data for template_id  not found.")
                            continue
                        single_data = data_header_list[record][2]
                        field_list = [] #list of feild_values
                        field_dict = {} #dict of field values
                        i = 0
                        for field in range(0,field_cnt):
                            temp_len = template_dict[temp_id][field][1]
                            field_type_temp = template_dict[temp_id][field][0]
                            start = i
                            end = start + temp_len
                            i = i + temp_len
                            
                            if temp_len == 1:
                                val = ord(data_header_list[record][2][start])
                            elif temp_len == 2:
                                val = socket.ntohs(struct.unpack('H', data_header_list[record][2][start:end])[0])
                            elif temp_len == 4:
                                #val = socket.ntohl(struct.unpack('!L', data_data_dict[temp_id][start:end])[0])
                                val = (struct.unpack('!L', data_header_list[record][2][start:end])[0])
                            elif temp_len == 16:
                                val = socket.inet_ntop(socket.AF_INET6, data_header_list[record][2][start:end])
                            
                            field_list.append(val)
                            field_dict[field_type_temp] = val
                        
                        _raw_data = data_header_list[record][2]
                        #_packet_type = template_data_dict_encoded[temp_id]
                        data_dict.append(({temp_id : field_dict}, _raw_data))   
                        temp_data_dict[temp_id] = field_list
                        
                        #log.debug("temp data_dict : %s", temp_data_dict)
                        #
                        #log.debug("netflow_v9; flowset_id: %s", flowset_id)
                        #log.debug("netflow_v9; template template : %s", template_template_list)
                        #log.debug("netflow_v9; data header lsit: %s", data_header_list)
                        #log.debug("netflow_v9; template data dict : %s", template_data_dict)
                        #log.debug("netflow_v9; data data dict: %s", data_data_dict)
                        #log.debug("netflow_v9; template dict : %s", template_dict)
                        #log.debug("netflow_v9; data dict: %s", data_dict)
                        #log.debug("netflow_v9; length data dict: %s", len(data_dict))
                        
            netflow_data_raw.extend(data_dict)
            isParsed = True
    if isParsed and netflow_data_raw is not None:
        log.info("Creating initial object Returned: %s", netflow_data_raw)
        previous_data_header_list = data_header_list
        new_netflow_v9[device_ip].set_previous_data_header_list(previous_data_header_list)
        #new_netflow_v9[device_ip] = _New_Netflow_v9(data, count)
        return netflow_data_raw
    elif len(netflow_data_raw) != 0 and netflow_data_raw is not None:
        log.debug("Returning unparsed raw data %s", netflow_data_raw)
        return netflow_data_raw
    ##templates and data flow sets end
    
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
    
    
    ts = int(time.time())
    timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    #d['timestamp'] = timestamp
    
    
    # format: timestamp (interface_index) srcIP(srcPort)-(PROTO)->dstIP(dstPort) from start_uptime to end_uptime (tos) nPacket nBytes
    
    result = "%s (%d) %s(%d) -(%s)-> %s(%d) from %s to %s, (%s) pcount:%s, bcount:%s" % (
        timestamp, d['interface_index'], d['source_address'], d['source_port'], PROTO_DIC[protocol], \
        d['destination_address'], d['destination_port'], \
            d['start_uptime_ms'], d['end_uptime_ms'], d['types_of_service'], d['packet_count'], d['bytes_count'])
    
    log.debug("Record %s", result)
    
    log.debug("this is parsed result %s", d)
    return d


def msgfill_parsed_record_v9(dd):
    log.info("parsing  v9 records")
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
                try:
                    e['protocol_name'] = PROTO_DIC[d[k]]
                except:
                    log.info("Protocol Name not found in PROTO_DIC")
                    e['protocol_name'] = "Unknown"
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
    log.debug("this is v9 parsed result %s", e)
    return e


class _New_Netflow_v9:
    def __init__(self, data, count):
        self.data = data
        self.count = count
        
        self._raw_data = ''    #sting of the raw data from the dataflow set
        self.length = []         #length of each flow set
        
        self.flowset_id = []     #lsit of flowset id
        self.template_header_list = []   #contains flowset_id and length
        self.flow_data_list = []         #contains raw data
        
        self.template_template_list = [] #contains template_id and field count
        self.data_header_list = []       #contains template_id and length of the data
        self.previous_data_header_list = []
        
        self.template_data_dict = {} #contains templateflow data as template_id:data 
        self.data_data_dict = []     #contains dataflow data as template_id:data
        
        self.unparsed_raw_data = []
        self.now = int(time.time())
        
    def get_flowset_id_length_data(self, data, count):
        total_len = len(data)
        flow_data = data[SIZE_OF_HEADER_9:]
        length = [0]
        do = False
        for flowset_num in range(0,count):
            #log.debug("Flowset_num : %s", flowset_num)
            
            start = length[flowset_num]+0
            end = length[flowset_num]+2
            
            flowset_id_temp = socket.ntohs(struct.unpack('H', flow_data[start:end])[0])
            self.flowset_id.append(flowset_id_temp)
            
            
            length_temp = socket.ntohs(struct.unpack('H', flow_data[length[flowset_num]+2:length[flowset_num]+4])[0])
            length.append(length_temp)
            #log.debug("length :%s", length)
            if length_temp != 0:
                #log.debug("Not appending the 0 length flowset")
                self.template_header_list.append((flowset_id_temp, length_temp))
                flow_data_list_temp = flow_data[length[flowset_num]+0:length[flowset_num]+length_temp]
                self.flow_data_list.append(flow_data_list_temp)
            checked_data_length = 0
            for i in length:
                checked_data_length += i
            #log.debug("checked len :%s", checked_data_length + 20)
            if (checked_data_length + 20) > total_len:
                #log.debug("checked len is greater :%s", checked_data_length)
                do = True
                #log.debug("doing break no 1")
                del length[-1]
                del self.flowset_id[-1]
                del self.template_header_list[-1]
                del self.flow_data_list[-1]
                break
            elif (checked_data_length + 20) == total_len:
                break
            else:
                continue
            #log.debug("doing break no 2")
            break
        del length[0]
        self.length.append(length)
        
    def get_raw_template_dict_raw_data_dict(self, sid, netflow_out, device_name, col_type, device_ip, collected_at):
        log.debug(".. inside separate the data and template flowsets and store with template_id in the ;;tempalate_data_dict ---> raw template flowset ;;data_data_dict --------> raw data flowset ...")
        for header_num in range(0,len(self.template_header_list)):
            if self.template_header_list[header_num][0] == 0:
                
                '''
                do the task of templates here            
                '''
                #log.debug("Inside ; this is template set")
                if self.template_header_list[header_num][1] > 4:
                    #log.debug("Template Diagnonsis; template length: %s", self.template_header_list[header_num][1])
                    do = True
                    next_count = 0
                    while do:
                        template_id = socket.ntohs(struct.unpack('H', self.flow_data_list[header_num][4+next_count:6+next_count])[0])
                        field_count = socket.ntohs(struct.unpack('H', self.flow_data_list[header_num][6+next_count:8+next_count])[0])
                        for i in range(len(self.template_template_list)):
                            if template_id == self.template_template_list[i][0]:            #replace the template if template_id is repeated
                                self.template_template_list[i] = (template_id,field_count)    
                        self.template_template_list.append((template_id,field_count))
                        self.template_data_dict[template_id] = self.flow_data_list[header_num][4:] #removing flowset_id and length
                        
                        #self.template_template_list.append((2344, 4567))
                        #self.template_data_dict[2344] = "\x00\x12\00"
                        
                        if (self.template_template_list[-1][1] * 4 + 4 + 4) != (self.template_header_list[header_num][1]):
                            log.debug("Here is true error; Invalid field count vs template data length")
                            del self.template_template_list[-1]
                            #del self.template_data_dict[2344]
                            break
                        '''
                        log.debug("inside template_id: %s", template_id)
                        log.debug("inside field_count: %s", field_count)
                        log.debug("inside template_template_list: %s", self.template_template_list)
                        log.debug("inside template_data_dict: %s", self.template_data_dict)
                        '''
                        next_count += (field_count * 2 * 2) + 4
                        if (next_count + 4) >= self.template_header_list[header_num][1]:
                            do = False
                    
                else:
                    log.info("Length Problem;;;Deleteing template header with incorrect lengths: %s", self.template_header_list[header_num])
                    #del self.template_header_list[header_num]
            else:
                '''
                do the task of data here
                '''
                #log.debug("Inside;; this is data set")
                template_id = self.template_header_list[header_num][0]
                data_length = socket.ntohs(struct.unpack('H', self.flow_data_list[header_num][2:4])[0])
                replaced = False
                
                self.data_header_list.append((template_id, data_length, self.flow_data_list[header_num][4:]))
                '''
                log.debug("inside data template_id: %s", template_id)
                log.debug("inside data dataflow length: %s", data_length)
                log.debug("inside self.data_header_list: %s", self.data_header_list)
                log.debug("inside self.data_data_dict: %s", self.data_data_dict)
                '''
        #handle template data
        self.update_template_data_list_dict()
        for (k, v) in self.template_data_dict.iteritems():
            _raw_msg_b = binascii.b2a_base64(self.template_data_dict[k])
            event = dict(
                _p___raw_msg_b= _raw_msg_b,
                packet_type= "template",
                template_id= k,
                )
            msgfilling.add_types(event, '_type_str', 'packet_type')
            msgfilling.add_types(event, '_type_num', 'template_id')
            _handle_data(event, sid, netflow_out, device_name, col_type, device_ip, collected_at)
                        
    def update_template_data_list_dict(self):
        self.template_template_list = list(set(self.template_template_list))
        #self.data_header_list = list(set(self.data_header_list))
        
    def clean_unparsed_raw_data(self):
        self.unparsed_raw_data = []

    def set_previous_data_header_list(self, header_list):
        self.previous_data_header_list.extend(header_list)
        
# globals used across the green threads
LAST_COL_TS = 0
LOG_COUNTER = 0

new_netflow_v9 = {}
device_ip_list = []

def main(): 
    config = _parse_args()
    log_level = config['core']['log_level']
    port = config['port']   
    expire_time = config['expire_time']
    col_type = config['col_type']
    collected_at = config["loginspect_name"]

    zmq_context = zmq.Context()

    netflow_out = wiring.Wire('collector_out', zmq_context=zmq_context,
                                    conf_path=config.get('wiring_conf_path') or None)
    
    sock = start_udp_server(port)
    while True:
        data, addr = sock.recvfrom(9216)
        
        if not data:
            continue
        log.debug('udp collector; from ip=%s, got msg=%s;', addr, data)
        
        ip = inet.get_ip(addr)
        config_ip = config_reader.get_config_ip(ip, config)
        if not config_ip:
            continue
        try:
            version = get_netflow_packet_version(data[0:2])
            count = socket.ntohs(struct.unpack('H',data[2:4])[0])
            current_unix_sec = (struct.unpack('I',data[8:12])[0])
            
            log.debug("Version: %s", version)
            log.debug("Count of no. of records: %s", count)
            log.debug("Count of no. of seconds since 0000 UTC 1970: %s", current_unix_sec)
            
            netflow1 = netflow.Netflow1()
            netflow5 = netflow.Netflow5()
            netflow6 = netflow.Netflow6()
            netflow7 = netflow.Netflow7()
            
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
                    
                i = 1
                if not netflowdata:
                    continue
                
                for netflow_record in netflowdata:
                    try:
                        i = i + 1                   
                        try:
                            parsed_msg_dict = parse_record(netflow_record)
                        except Exception, e:
                            log.error("Could not parse the given record. %s", repr(e))
                        parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(netflow_record))
                        parsed_msg_dict['version'] = VERSION
                        parsed_msg_dict['current_unix_sec'] = current_unix_sec
                        msgfilling.add_types(parsed_msg_dict, '_type_num', 'version current_unix_sec')
                        
                        sid = _get_sid(config_ip, config)
                        device_name = config['client_map'][config_ip]["device_name"]
                        log.debug("device: %s", device_name)
                        log.debug("descrete ip: %s", ip)
                        try:
                            _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)
                        except Exception, e:
                            log.error("Device name not found. %s", repr(e))
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
                    str_data = str(data)
                    log.debug("v9 str data: %s", str(str_data))
                    
                    
                    #Other information in packet header
                    sys_uptime_ms = (struct.unpack('!L',data[4:8])[0])
                    unix_secs = (struct.unpack('!L',data[8:12])[0])
                    package_sequence = (struct.unpack('!L',data[12:16])[0])
                    source_id = (struct.unpack('!L',data[16:20])[0])
                    
                    sid = _get_sid(config_ip, config)
                    device_name = config['client_map'][config_ip]["device_name"]
                    netflow_data_list_tuple = _netflow9(data, count, expire_time, sid, netflow_out, device_name, col_type, ip, collected_at)
                        
                    if netflow_data_list_tuple is not None and len(netflow_data_list_tuple) != 0:
                        for data_dict_tuple in netflow_data_list_tuple:
                            #log.debug("Testing data dict tuple: %s", data_dict_tuple)
                            if data_dict_tuple[0] and data_dict_tuple is not None:
                                data_dict = data_dict_tuple[0]
                                _p__raw_msg_b = data_dict_tuple[1]
                                if not data_dict:
                                    parsed_msg_dict = {}
                                    parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(_p__raw_msg_b))
                                    parsed_msg_dict['version'] = VERSION
                                    parsed_msg_dict['sys_uptime_ms'] = sys_uptime_ms
                                    parsed_msg_dict['unix_secs'] = unix_secs
                                    parsed_msg_dict['package_sequence'] = package_sequence
                                    parsed_msg_dict['source_id'] = source_id
                                    msgfilling.add_types(parsed_msg_dict, '_type_num', 'version sys_uptime_ms unix_secs package_sequence source_id')
                                    
                                    #sid = _get_sid(config_ip, config)
                                    #device_name = config['client_map'][config_ip]["device_name"]
                                    try:  
                                        _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)
                                    except Exception, e:
                                        log.error("Device name not found; %s", repr(e))
                                else:        ###parse record
                                    for (k, v) in data_dict.iteritems():          
                                        try:
                                            parsed_msg_dict = msgfill_parsed_record_v9(v)
                                        except Exception, e:
                                            log.error("Could not msgfill the parsed v9 record; %s", repr(e))
                                        parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(_p__raw_msg_b))
                                        parsed_msg_dict['version'] = VERSION
                                        parsed_msg_dict['sys_uptime_ms'] = sys_uptime_ms
                                        parsed_msg_dict['unix_secs'] = unix_secs
                                        parsed_msg_dict['package_sequence'] = package_sequence
                                        parsed_msg_dict['source_id'] = source_id
                                        parsed_msg_dict['template_id'] = k
                                        msgfilling.add_types(parsed_msg_dict, '_type_num', 'version sys_uptime_ms unix_secs package_sequence source_id template_id')
                                        
                                        #sid = _get_sid(config_ip, config)
                                        #device_name = config['client_map'][config_ip]["device_name"]
                                        try:
                                            _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)
                                        except Exception, e:
                                            log.error("Device name not found; %s", repr(e))
                except Exception, e:
                    parsed_msg_dict = {}
                    parsed_msg_dict['_p__raw_msg_b'] = binascii.b2a_base64(str(str_data))
                    parsed_msg_dict['version'] = VERSION
                    msgfilling.add_types(parsed_msg_dict, '_type_num', 'version')
                    
                    sid = _get_sid(config_ip, config)
                    device_name = config['client_map'][config_ip]["device_name"]
                    _handle_data(parsed_msg_dict, sid, netflow_out, device_name, col_type, ip, collected_at)
                    if ip in device_ip_list:
                        device_ip_list.remove(ip)
                    
                    log.warn("Error in constructing v9 message, Necessary field not supplied in Netflow")
                    log.warn(repr(e))
                    #log.warn(traceback.print_exc())
                
            else:
                log.error("Not the correct version type.")
        except Exception, e:
            log.error("Incorrect Netflow data format, %s", repr(e))
            #log.warn(traceback.print_exc())
    #main_end

if __name__ == '__main__':
    main()

