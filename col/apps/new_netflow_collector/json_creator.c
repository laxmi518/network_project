
/**
*   @file json_creator.c
*   @author ritesh, hari
*   @date 8/22/2013
    
    Creates the json object with given key value pairs
*/
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <jansson.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "netflow_v5_v7.h"
#include "netflow_v9_v10.h"
#include "netflow_common.h"
#include "json_creator.h"

#include "../../lib/clib/config_reader.h"

/**
*   @brief  Creating the json object using device ip device configuration, message id etc and return the created event.
*   @param[in]  single_flow struct containg v5 data (single_flowset_v5_t * type)
*   @param[in]  lp_name Logpoint name
*   @param[in]  dev_ip device ip
*   @param[in]  mid message id
*   @param[in]  dev_config device configuration
*   @param[in]  col_ts time stamp of syslog message(in sec)
*   @param[in]  log_counter  Number of syslog message per second
*   @param[in]  col_type collection type(netflowc)
*   @param[in]  device_name Name of the corresponding device
*   @return  json_t *
*/    
json_t *create_json_object_from_single_struct_v5(single_flowset_v5_t *single_flow, const char *lp_name, \
                                              char *dev_ip, char *mid, json_t *dev_config, long col_ts, \
                                              long log_counter, const char *col_type, const char *device_name) {
	/* create an event to send to upper layer*/
	char *_type_ip, *_type_str, *_type_num;

    json_t *event;
    event = json_object();
    
    /* normal fields from config_file */
    json_object_set_new(event, "msg",  json_string(""));
    json_object_set_new(event, "device_name", json_string(device_name));
    json_object_set_new(event, "device_ip", json_string(dev_ip));
    json_object_set_new(event, "mid", json_string(mid));
    json_object_set_new(event, "collected_at", json_string(lp_name));
    json_object_set_new(event, "col_ts", json_integer(col_ts));
    json_object_set_new(event, "_counter", json_integer(log_counter));
    json_object_set_new(event, "col_type", json_string(col_type));
    
    /* raw msg */
    json_t *raw_msg_event;
    raw_msg_event = json_object();
    json_object_set_new(raw_msg_event, "_p__raw_msg_b", json_string(single_flow->_p__raw_msg_b)); 
    json_object_set_new(event, "_to_preserve", raw_msg_event);
    
    
    /* from packet headers */
    json_t *normalized_fields = json_object();
    json_object_set_new(normalized_fields, "version", json_integer(5));
    json_object_set_new(normalized_fields, "flowcount", json_integer(single_flow->hdr_v5->flowcount));
    //    json_object_set_new(normalized_fields, "uptime", json_interger(single_flow->hdr_v5->uptime));
    json_object_set_new(normalized_fields, "current_unix_sec", json_integer(single_flow->hdr_v5->unix_ts));
    json_object_set_new(normalized_fields, "unix_ns", json_integer(single_flow->hdr_v5->unix_tns));
    json_object_set_new(normalized_fields, "packet_sequence", json_integer(single_flow->hdr_v5->sequence));
    json_object_set_new(normalized_fields, "engine_type", json_integer(single_flow->hdr_v5->engine_type));
    json_object_set_new(normalized_fields, "engine_id", json_integer(single_flow->hdr_v5->engine_id));
    json_object_set_new(normalized_fields, "sample_interval", json_integer(single_flow->hdr_v5->samp_interval));
    //
    /* from packets records */
    char srcbuf[INET6_ADDRSTRLEN];
    char dstbuf[INET6_ADDRSTRLEN];
    //    static char nextbuf[INET6_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &single_flow->rec_v5->src, srcbuf, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &single_flow->rec_v5->dst, dstbuf, INET6_ADDRSTRLEN);
    //    inet_ntop(AF_INET, &single_flow->rec_v5->nexthop, dstbuf, INET6_ADDRSTRLEN);
    
    json_object_set_new(normalized_fields, "source_address", json_string(srcbuf));
    json_object_set_new(normalized_fields, "destination_address", json_string(dstbuf));
    //    json_object_set_new(normalized_fields, "next_hop", json_string(nextbuf));
    json_object_set_new(normalized_fields, "snmp_in", json_integer(single_flow->rec_v5->snmp_in));
    json_object_set_new(normalized_fields, "snmp_out", json_integer(single_flow->rec_v5->snmp_out));
    json_object_set_new(normalized_fields, "packets", json_integer(single_flow->rec_v5->packets));
    json_object_set_new(normalized_fields, "bytes", json_integer(single_flow->rec_v5->bytes));
    json_object_set_new(normalized_fields, "start_uptime_ms", json_integer(single_flow->rec_v5->first_ts));
    json_object_set_new(normalized_fields, "end_uptime_ms", json_integer(single_flow->rec_v5->last_ts));
    json_object_set_new(normalized_fields, "source_port", json_integer(single_flow->rec_v5->src_port));
    json_object_set_new(normalized_fields, "destination_port", json_integer(single_flow->rec_v5->dst_port));
    json_object_set_new(normalized_fields, "tcp_flags", json_integer(single_flow->rec_v5->tcp_flags));
    json_object_set_new(normalized_fields, "protocol", json_integer(single_flow->rec_v5->proto));
    json_object_set_new(normalized_fields, "source_as", json_integer(single_flow->rec_v5->src_asn));
    json_object_set_new(normalized_fields, "destination_as", json_integer(single_flow->rec_v5->dst_asn));
    json_object_set_new(normalized_fields, "type_of_service", json_integer(single_flow->rec_v5->tos));
    json_object_set_new(normalized_fields, "source_mask", json_integer(single_flow->rec_v5->src_mask));
    json_object_set_new(normalized_fields, "destination_mask", json_integer(single_flow->rec_v5->dst_mask));
    
    
    /* Msgfilling the types */
	_type_ip = "device_ip source_address destination_address";
	_type_str = "msg device_ip device_name collected_at source_address destination_address col_type";
    _type_num = "col_ts version flowcount current_unix_sec unix_ns packet_sequence engine_type engine_id sample_interval snmp_in snmp_out packets bytes start_uptime_ms source_port destination_port tcp_flags protocol source_as destination_as type_of_service source_mask destination_mask";
    
    json_object_set_new(event, "_type_str", json_string(_type_str));
    json_object_set_new(event, "_type_ip", json_string(_type_ip));
	json_object_set_new(event, "_type_num", json_string(_type_num));
    json_object_set_new(event, "_normalized_fields", normalized_fields);

#ifdef DEBUG
    char *json_st;
    json_st = json_dumps(event, JSON_INDENT(4));
    printf("Event is: %s\n", json_st);
    free(json_st);
#endif
    
    return event;
}



/**
*   @brief Creating the json object using device ip device configuration, message id etc and return the created event.
*   @param[in]  v9_v10_header v9/v10 header information
*   @param[in]  info Packet information (packet_info_t * type)
*   @return  json_t *
*/
json_t *create_json_object_packet(void *v9_v10_header, packet_info_t *info) {
    
    /* create an event to send to upper layer*/
    const char *device_name;
    device_name = get_string_value_from_json(info->dev_config, "device_name");
    
    json_t *event;
    event = json_object();
    json_t *normalized_fields = json_object();
    /* normal fields from config_file */
    json_object_set_new(event, "msg",  json_string(""));
    json_object_set_new(event, "device_name", json_string(device_name));
    json_object_set_new(event, "device_ip", json_string(info->device_ip));
    json_object_set_new(event, "collected_at", json_string(info->lp_name));

    if (info->version == 9) {   
        netflow_v9_header_t *v9_header = (netflow_v9_header_t *)v9_v10_header;
        json_object_set_new(normalized_fields, "version", json_integer(v9_header->version));
        json_object_set_new(normalized_fields, "count", json_integer(v9_header->count));
        json_object_set_new(normalized_fields, "sys_uptime", json_integer(v9_header->sys_uptime));
        json_object_set_new(normalized_fields, "unix_secs", json_integer(v9_header->unix_secs));
        json_object_set_new(normalized_fields, "sequence", json_integer(v9_header->sequence));
        json_object_set_new(normalized_fields, "source_id", json_integer(v9_header->source_id));
    } else if (info->version == 10) {
        netflow_v10_header_t *v10_header = (netflow_v10_header_t *)v9_v10_header;
        json_object_set_new(normalized_fields, "version", json_integer(v10_header->version));
        json_object_set_new(normalized_fields, "ipfix_length", json_integer(v10_header->ipfix_length));
        json_object_set_new(normalized_fields, "unix_secs", json_integer(v10_header->unix_secs));
        json_object_set_new(normalized_fields, "sequence", json_integer(v10_header->sequence));
        json_object_set_new(normalized_fields, "source_id", json_integer(v10_header->source_id));

    }
    json_object_set_new(event, "_normalized_fields", normalized_fields);    
    /* raw msg */
   // json_object_set_new(event, "_p__raw_msg_b", json_string(_raw_msg_b));
    
    return event;
}

