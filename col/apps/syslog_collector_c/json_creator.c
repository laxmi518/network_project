
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
    
#include "../../lib/clib/config_reader.h"

extern GMutex mutex_log_counter; 	/**< Extern: Mutex for log_counter */
extern GMutex mutex_regex;			/**< Extern: Mutex for regex */
extern long log_counter;			/**< Extern: log_counter */

/**
* 	@brief	Callback function for onigumara regex matching
*	@param[in]  name group name
*	@param[in]  end terminate address of group name
*	@param[in]  ngroups number of groups
*	@param[in]  group_list group number's list
*	@param[in]  re regex object
*	@param[in]  arg// Remaining
*	@return int
*/ 
int name_callback(const OnigUChar *name, const OnigUChar *end, int ngroups, int *group_list,
					OnigRegex re_arg, void *arg) {
	struct syslog_data *d = (struct syslog_data *)arg;

	OnigRegion *region_local = d->region;
	char *str = d->str;

	int num = onig_name_to_backref_number(re_arg, name, end, region_local);

	//char *value = (char *)calloc(25, sizeof(char));
	//sprintf(value, "%.*s", region->end[num] - region->beg[num], (str + region->beg[num]));

	char *value = (char *) malloc(25);
	memset(value, 0, 25);
	sprintf(value, "%.*s", region_local->end[num] - region_local->beg[num], (str + region_local->beg[num]));

	if(strcmp(value, "") != 0){
		if(strcmp((char *)name, "pri") == 0)
		{
			d->pri = atoi(value);
			free(value);
		}
		else if(strcmp((char *)name, "year") == 0)
			d->year = value;
		else if(strcmp((char *)name, "log_time") == 0)
			d->date_time = value;
		else
			free(value);
	}
	else
	{
		free(value);
	}
	return 0;
}

/** 
*	@brief	Check regex  syslog  message return NULL if not match
*	@param[in]  message Incoming message
*	@param[in]  re regex object
*	@param[in]  region Onigregion
*	@return struct syslog_data *
*	@warning use the get_syslog_data_from_message_r for thread safety
*/ 
struct syslog_data * get_syslog_data_from_message(OnigRegex re_arg,OnigRegion *region_arg, char *message) {
	int r = onig_search(re_arg, (UChar *)message, (UChar *)(message + strlen(message)), (UChar *)message,
						(UChar *)(message + strlen(message)), region_arg, ONIG_OPTION_NONE);

	struct syslog_data *d = (struct syslog_data *)malloc(sizeof(struct syslog_data));
	d->region = region_arg;
	d->str = message;
	d->pri = 0;
	d->year = NULL;
	d->date_time = NULL;

	/* match found */
	if (r >= 0) {
		onig_foreach_name(re_arg, name_callback, (void *)(d));
	}
	else
	{
		free(d);
		return NULL;
	}
	return d;
}

/** 
*	@brief	Parses the syslog  message and return syslog_data type
*	@param[in]  message Incoming message
*	@param[in]  re regex object
*	@param[in]  region Onigregion
*	@return struct syslog_data *
*/ 
struct syslog_data * get_syslog_data_from_message_r(OnigRegex re_arg,OnigRegion *region_arg, char *message) {
	g_mutex_lock(&mutex_regex);
	int r = onig_search(re_arg, (UChar *)message, (UChar *)(message + strlen(message)), (UChar *)message,
						(UChar *)(message + strlen(message)), region_arg, ONIG_OPTION_NONE);

	struct syslog_data *d = (struct syslog_data *)malloc(sizeof(struct syslog_data));
	d->region = region_arg;
	d->str = message;
	d->pri = 0;
	d->year = NULL;
	d->date_time = NULL;

	/* match found */
	if (r >= 0) {
		onig_foreach_name(re_arg, name_callback, (void *)(d));
	}
	g_mutex_unlock(&mutex_regex);

	return d;
}

/**
* 	@brief	Creating the json object using device ip device configuration, message id etc and return the created event.
*	@param[in]  re regex object
*	@param[in]  region Onigregion
*	@param[in]  lp_name log point name
*	@param[in]  message Message received
*	@param[in]  dev_ip device ip
*	@param[in]  dev_config device configuration
*	@param[in]  mid message id
*	@param[in]  col_ts time stamp of syslog message(in sec)
*	@param[in]  log_counter  Number of syslog message per secone
*	@param[in]  col_type collection type(syslog collector)
*	@return  json_t *
*/ 
json_t *create_json_object(const char *lp_name, char *message, char *dev_ip, json_t *dev_config,
						char *mid, long col_ts, const char *col_type, struct syslog_data *d) {
	/* create an event to send to upper layer*/
	char *_type_ip, *_type_str, *_type_num;
    const char *device_name;

	_type_ip = "device_ip";
	_type_str = "msg device_name collected_at device_ip col_type";

	_type_num = malloc(sizeof(char)* 100);
	strcpy(_type_num, "col_ts");

    device_name = get_string_value_from_json(dev_config, "device_name");

    json_t *event;

    event = json_object();


    json_object_set_new(event, "msg", json_string(message));
    json_object_set_new(event, "device_name", json_string(device_name));
    json_object_set_new(event, "device_ip", json_string(dev_ip));
    json_object_set_new(event, "mid", json_string(mid));
    json_object_set_new(event, "collected_at", json_string(lp_name));
	json_object_set_new(event, "col_ts", json_integer(col_ts));
	g_mutex_lock(&mutex_log_counter);
	json_object_set_new(event, "_counter", json_integer(log_counter));
	g_mutex_unlock(&mutex_log_counter);
	json_object_set_new(event, "col_type", json_string(col_type));
	
	json_t *normalized_fields= json_object();
    
	const char *parser = get_string_value_from_json(dev_config, "parser");
	/* use regex only if parser is SyslogParser or NewSyslogParser*/
	if( (strcmp(parser,"SyslogParser")==0) || (strcmp(parser,"NewSyslogParser")==0) ) 
	{
	    // struct syslog_data *d;
	    // d = parse_syslog_message(message);

		if(d->pri != 0)
		{
			int sev, fac;
			sev = d->pri / 10;
			fac = d->pri % 10;

			json_object_set_new(normalized_fields, "severity", json_integer(sev));
			json_object_set_new(normalized_fields, "facility", json_integer(fac));

			strcat(_type_num, " severity facility");

		}

		if(d->date_time)
		{
			if(d->year)
			{
				struct tm tm = {0};
				time_t epoch = 0;
				if (strptime(d->date_time, "%b %d %Y %H:%M:%S", &tm) != NULL)
				{
					epoch = mktime(&tm);
					json_object_set_new(normalized_fields, "log_ts", json_integer((int)epoch));
					strcat(_type_num, " log_ts ");
				}
		    }
			else
			{
				time_t curr_time;
				time(&curr_time);
				struct tm *ltm= localtime(&curr_time);

				char *dt_with_year = (char *) malloc(50);
				memset(dt_with_year, 0, 50);
				sprintf(dt_with_year, "%d %s", 1900+ltm->tm_year, d->date_time);

				struct tm tm;
				time_t epoch = 0;
				if (strptime(dt_with_year, "%Y %b %d %H:%M:%S", &tm) != 0){
					epoch = mktime(&tm);
					json_object_set_new(normalized_fields, "log_ts", json_integer((int)epoch));
					strcat(_type_num, " log_ts");
				}
				free(dt_with_year);
		    }
		}
		//cleanup
		// if(d)
		// {
		// 	if(d->str)
		// 		free(d->str);
		// 	if(d->year)
		// 		free(d->year);
		// 	if(d->date_time)
		// 		free(d->date_time);
		// 	free(d);
		// }
	}
	json_object_set_new(event, "_normalized_fields",normalized_fields);
	json_object_set_new(event, "_type_num", json_string(_type_num));
	json_object_set_new(event, "_type_str", json_string(_type_str));
    json_object_set_new(event, "_type_ip", json_string(_type_ip));
   	free(_type_num);

#ifdef DEBUG
    char *json_st;
    json_st = json_dumps(event, JSON_INDENT(4));
    printf("Event is: %s\n", json_st);
    free(json_st);
#endif

    return event;
}

