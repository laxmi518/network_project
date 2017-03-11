#ifndef JSON_CREATOR_H
#define JSON_CREATOR_H
#include <zlog.h>
#include <jansson.h>
#include "common.h"

extern zlog_category_t *_c; 		/**< Extern: for using zlog */
extern pthread_mutex_t _mutex_log_counter; 	/**< Extern: Mutex for _log_counter */
extern long _log_counter;			/**< Extern: _log_counter */
json_t *create_json_object(const char *lp_name, char *msg,char *mid, long col_ts, 
	const char *col_type, config_data_t *config_data);
#endif