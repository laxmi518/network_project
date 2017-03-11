#ifndef JSON_CREATOR_H
#define JSON_CRETOR_H

/**
*   @file json_creator.h
*   @author ritesh, hari
*   @date 8/22/2013
    
    Creates the json object with given key value pairs
*/

json_t *create_json_object_from_single_struct_v5(single_flowset_v5_t *single_flow,  const char *lp_name, char *dev_ip, char *mid \
	, json_t *dev_config, long col_ts, long log_counter, const char *col_type, const char *device_name);

char *get_message_id(const char *col_type, const char *lp_name, char *dev_ip,
						long col_ts, long counter);

json_t *create_json_object_packet(void *v9_header, packet_info_t *info);

#endif