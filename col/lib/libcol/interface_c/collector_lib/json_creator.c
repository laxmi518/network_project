
/*! \file json_creator.c
* @author ritesh, hari
* @date 8/22/2013
    
    Creates the json object with given key value pairs
*/
#define _GNU_SOURCE
#define __USE_XOPEN 
#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <string.h>
#include <time.h>
#include <oniguruma.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <glib.h>

#include "json_creator.h"

/**
* 	@brief	Creating the json object using device ip device configuration, message id etc and return the created event.
*	@param[in]  _re regex object
*	@param[in]  _region Onigregion
*	@param[in]  lp_name log point name
*	@param[in]  message Message received
*	@param[in]  dev_ip device ip
*	@param[in]  dev_config device configuration
*	@param[in]  mid message id
*	@param[in]  col_ts time stamp of syslog message(in sec)
*	@param[in]  _log_counter  Number of syslog message per secone
*	@param[in]  col_type collection type(syslog collector)
*	@return  json_t *
*/ 
json_t *create_json_object(const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
						char *mid, long col_ts, const char *col_type) {
	/* create an event to send to upper layer*/

	char *_type_ip = "device_ip";
	char *_type_str = "msg device_name collected_at device_ip col_type";
	char *_type_num = "col_ts";

    const char *device_name = get_string_value_from_json(dev_config, "device_name");

    json_t *event = json_object();

    json_object_set_new(event, "msg", json_string(message));
    json_object_set_new(event, "device_name", json_string(device_name));
    json_object_set_new(event, "device_ip", json_string(dev_ip));
    json_object_set_new(event, "mid", json_string(mid));
    json_object_set_new(event, "collected_at", json_string(lp_name));
	json_object_set_new(event, "col_ts", json_integer(col_ts));
	g_mutex_lock(&_mutex_log_counter);
	json_object_set_new(event, "_counter", json_integer(_log_counter));
	g_mutex_unlock(&_mutex_log_counter);
	json_object_set_new(event, "col_type", json_string(col_type));
	json_object_set_new(event, "_type_num", json_string(_type_num));
	json_object_set_new(event, "_type_str", json_string(_type_str));
    json_object_set_new(event, "_type_ip", json_string(_type_ip));

    return event;
}